package core

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// SessionType distinguishes Bearer from Cookie authentication.
type SessionType int

const (
	// SessionBearer uses Authorization: Bearer <token> headers.
	SessionBearer SessionType = iota
	// SessionCookie uses HTTP cookies set by the server.
	SessionCookie
)

// SessionData contains the authentication state for a single session.
type SessionData struct {
	Type         SessionType
	UID          string
	AccessToken  string
	RefreshToken string
}

// SessionTree represents the full session hierarchy for persistence across
// process restarts. It includes the top-level session and all forked
// per-service sessions.
type SessionTree struct {
	Primary  SessionData
	Services map[string]SessionData
}

// ErrAlreadyConverted is returned when ConvertToCookie is called on a session
// that has already been converted from Bearer to Cookie.
var ErrAlreadyConverted = errors.New("core: session already converted to cookie")

// Session is the top-level authenticated connection to the Proton API. It
// holds the primary credentials (Bearer or Cookie) and manages forked
// per-service sessions that share the underlying TCP/TLS connection pool.
//
// Session is safe for concurrent use from multiple goroutines.
type Session struct {
	host        string
	transport   *Transport
	authHandler AuthHandler // optional; nil means no notifications
	maxRetries  int
	baseBackoff time.Duration

	mu        sync.RWMutex
	primary   SessionData
	converted bool // true after ConvertToCookie; one-way flag
	services  map[string]*ServiceSession
}

// SessionOption configures a Session at construction time.
type SessionOption func(*sessionConfig)

type sessionConfig struct {
	maxRetries  int
	baseBackoff time.Duration
	authHandler AuthHandler
}

// WithMaxRetries sets the maximum number of retry attempts for transient
// failures (429, 5xx, network errors). Zero disables retries. Default: 3.
func WithMaxRetries(n int) SessionOption {
	return func(c *sessionConfig) {
		c.maxRetries = n
	}
}

// WithRetryBackoff sets the base duration for exponential backoff between
// retries. The actual wait is base * 2^attempt with ±25% jitter. Default: 1s.
func WithRetryBackoff(d time.Duration) SessionOption {
	return func(c *sessionConfig) {
		c.baseBackoff = d
	}
}

// WithAuthHandler registers an [AuthHandler] to receive authentication
// lifecycle events (token refresh, session conversion, deauth). If not set,
// no notifications are sent and tokens live in memory only.
func WithAuthHandler(handler AuthHandler) SessionOption {
	return func(c *sessionConfig) {
		c.authHandler = handler
	}
}

// Login constructs a new Session from pre-obtained authentication tokens. The
// returned Session uses Bearer authentication. The actual SRP login handshake
// is not implemented — this constructor accepts tokens obtained through an
// external authentication flow.
//
// The host parameter is the Proton API base URL (e.g.,
// "https://mail.proton.me/api"). The transport is the shared connection pool
// created via [NewTransport]. Service clients fork from this session to obtain
// their own token pair.
func Login(_ context.Context, host string, data SessionData, transport *Transport, opts ...SessionOption) (*Session, error) {
	if host == "" {
		return nil, fmt.Errorf("core: host must not be empty")
	}
	if data.UID == "" {
		return nil, fmt.Errorf("core: session data UID must not be empty")
	}
	if data.AccessToken == "" {
		return nil, fmt.Errorf("core: session data access token must not be empty")
	}
	if transport == nil {
		return nil, fmt.Errorf("core: transport must not be nil")
	}

	cfg := sessionConfig{
		maxRetries:  defaultMaxRetries,
		baseBackoff: defaultBaseBackoff,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Session{
		host:        host,
		transport:   transport,
		authHandler: cfg.authHandler,
		maxRetries:  cfg.maxRetries,
		baseBackoff: cfg.baseBackoff,
		primary:     data,
		services:    make(map[string]*ServiceSession),
	}, nil
}

// Resume restores a Session from a previously stored SessionTree. All service
// sessions in the tree are re-created as forked sessions sharing the provided
// transport. The primary session's type (Bearer or Cookie) is preserved from
// the stored data.
//
// This is the entry point for process restart — the consumer loads the stored
// tree from keyring/file and calls Resume to re-establish all sessions without
// a full re-login.
func Resume(_ context.Context, host string, tree SessionTree, transport *Transport, opts ...SessionOption) (*Session, error) {
	if host == "" {
		return nil, fmt.Errorf("core: host must not be empty")
	}
	if tree.Primary.UID == "" {
		return nil, fmt.Errorf("core: session tree primary UID must not be empty")
	}
	if tree.Primary.AccessToken == "" {
		return nil, fmt.Errorf("core: session tree primary access token must not be empty")
	}
	if transport == nil {
		return nil, fmt.Errorf("core: transport must not be nil")
	}

	cfg := sessionConfig{
		maxRetries:  defaultMaxRetries,
		baseBackoff: defaultBaseBackoff,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	s := &Session{
		host:        host,
		transport:   transport,
		authHandler: cfg.authHandler,
		maxRetries:  cfg.maxRetries,
		baseBackoff: cfg.baseBackoff,
		primary:     tree.Primary,
		converted:   tree.Primary.Type == SessionCookie,
		services:    make(map[string]*ServiceSession, len(tree.Services)),
	}

	for name, data := range tree.Services {
		s.services[name] = &ServiceSession{
			service: name,
			parent:  s,
			data:    data,
		}
	}

	return s, nil
}

// Fork creates a per-service session that shares the underlying transport but
// maintains its own token pair and User-Agent header. Each forked session
// refreshes independently of the primary session and other forks.
//
// The service name is used as the key for later retrieval via [Session.Service]
// and is included in the User-Agent header for the forked session's requests.
//
// Fork panics if the service name is empty.
func (s *Session) Fork(service string, data SessionData) *ServiceSession {
	if service == "" {
		panic("core: service name must not be empty")
	}

	ss := &ServiceSession{
		service: service,
		parent:  s,
		data:    data,
	}

	s.mu.Lock()
	s.services[service] = ss
	s.mu.Unlock()

	return ss
}

// ConvertToCookie converts the session from Bearer to Cookie authentication.
// This is a one-way operation: the original Bearer tokens and all existing
// Bearer forks become invalid. After conversion, new forks use Cookie auth.
//
// Lumo/AI endpoints require Cookie authentication — Bearer is rejected.
//
// ConvertToCookie returns [ErrAlreadyConverted] if the session has already
// been converted.
func (s *Session) ConvertToCookie(ctx context.Context, newData SessionData) error {
	s.mu.Lock()
	if s.converted {
		s.mu.Unlock()
		return ErrAlreadyConverted
	}

	s.converted = true
	newData.Type = SessionCookie
	s.primary = newData
	s.services = make(map[string]*ServiceSession)

	handler := s.authHandler
	primary := s.primary
	s.mu.Unlock()

	if handler != nil {
		tree := SessionTree{
			Primary:  primary,
			Services: make(map[string]SessionData),
		}
		// Ignore error — session conversion succeeded regardless of
		// whether the consumer can persist the new state.
		_ = handler.OnSessionConverted(ctx, tree)
	}

	return nil
}

// Service returns the forked ServiceSession for the given service name, or
// nil if no session has been forked for that service.
func (s *Session) Service(name string) *ServiceSession {
	s.mu.RLock()
	ss := s.services[name]
	s.mu.RUnlock()
	return ss
}

// Services returns a snapshot of all active service session names and their
// sessions. The returned map is a copy — modifications do not affect the
// Session.
func (s *Session) Services() map[string]*ServiceSession {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := make(map[string]*ServiceSession, len(s.services))
	for k, v := range s.services {
		cp[k] = v
	}
	return cp
}

// Primary returns a snapshot of the session's primary authentication data.
func (s *Session) Primary() SessionData {
	s.mu.RLock()
	d := s.primary
	s.mu.RUnlock()
	return d
}

// Host returns the Proton API host URL for this session.
func (s *Session) Host() string {
	return s.host
}

// ErrServiceNotFound is returned when UpdateTokens is called with a service
// name that has no forked session.
var ErrServiceNotFound = errors.New("core: service session not found")

// UpdateTokens pushes new tokens for a specific service session. This is the
// consumer's entry point for proactive token refresh — the consumer drives
// the refresh schedule, Core accepts whatever tokens it's given.
//
// Thread-safe: in-flight requests on the old token complete normally; new
// requests use the updated token immediately.
//
// Returns [ErrServiceNotFound] if no session has been forked for the given
// service name.
func (s *Session) UpdateTokens(ctx context.Context, service string, data SessionData) error {
	s.mu.RLock()
	ss := s.services[service]
	s.mu.RUnlock()

	if ss == nil {
		return ErrServiceNotFound
	}

	ss.UpdateData(data)

	if s.authHandler != nil {
		// Persistence failure is non-fatal — tokens are valid in memory.
		_ = s.authHandler.OnTokenRefresh(ctx, service, data)
	}

	return nil
}

// UpdatePrimaryTokens pushes new tokens for the top-level session. The
// session's Type and UID are preserved — only AccessToken and RefreshToken
// are replaced.
//
// Thread-safe: concurrent readers see a consistent snapshot (old or new).
func (s *Session) UpdatePrimaryTokens(ctx context.Context, data SessionData) {
	s.mu.Lock()
	s.primary.AccessToken = data.AccessToken
	s.primary.RefreshToken = data.RefreshToken
	handler := s.authHandler
	updated := s.primary
	s.mu.Unlock()

	if handler != nil {
		_ = handler.OnTokenRefresh(ctx, "", updated)
	}
}

// ServiceSession is a per-service authenticated session that shares the
// underlying TCP/TLS connection pool with the parent [Session] but maintains
// its own token pair, User-Agent, and refresh lifecycle.
//
// ServiceSession is safe for concurrent use from multiple goroutines.
type ServiceSession struct {
	service string
	parent  *Session

	mu   sync.RWMutex
	data SessionData
}

// Data returns a snapshot of the service session's current authentication
// data.
func (ss *ServiceSession) Data() SessionData {
	ss.mu.RLock()
	d := ss.data
	ss.mu.RUnlock()
	return d
}

// UpdateData replaces the service session's tokens. This is the internal
// entry point used by the retry transport after a successful reactive refresh.
// The consumer-facing equivalent is [Session.UpdateTokens].
//
// Thread-safe: acquires a write lock, so in-flight requests reading the old
// token via [serviceRoundTripper] are not disrupted (they already captured
// the token under a read lock).
func (ss *ServiceSession) UpdateData(data SessionData) {
	ss.mu.Lock()
	ss.data = data
	ss.mu.Unlock()
}

// RefreshToken implements [TokenRefresher] for the reactive refresh path.
// When the retry transport encounters a 401, it calls this method to attempt
// a token refresh. The actual /auth/refresh API call is not yet implemented —
// this stub returns an error indicating refresh is not available via Core.
//
// Consumers should drive token refresh proactively via
// [Session.UpdateTokens]; Core only provides this reactive fallback.
func (ss *ServiceSession) RefreshToken(_ context.Context) error {
	// TODO: Implement actual /auth/refresh API call when the endpoint is wired.
	return errors.New("core: reactive token refresh not yet implemented")
}

// Name returns the service name for this session (e.g., "drive", "mail").
func (ss *ServiceSession) Name() string {
	return ss.service
}

// HTTPClient returns an [*http.Client] configured with the service session's
// authentication headers and User-Agent. The client shares the parent
// session's TCP/TLS connection pool.
//
// The returned client is safe for concurrent use. Token values are read under
// a read lock at request time, so token updates are reflected in subsequent
// requests without creating a new client.
func (ss *ServiceSession) HTTPClient() *http.Client {
	base := newRetryTransport(
		ss.parent.transport.RoundTripper(),
		withTokenRefresher(ss),
		withMaxRetries(ss.parent.maxRetries),
		withBaseBackoff(ss.parent.baseBackoff),
	)
	srt := &serviceRoundTripper{
		session: ss,
		base:    base,
	}
	return &http.Client{Transport: srt}
}

// serviceRoundTripper injects per-service auth headers and User-Agent into
// each request before delegating to the shared transport with retry logic.
type serviceRoundTripper struct {
	session *ServiceSession
	base    http.RoundTripper
}

// RoundTrip implements [http.RoundTripper]. It clones the request, injects
// authentication and User-Agent headers under a read lock, then delegates to
// the base transport.
func (srt *serviceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())

	srt.session.mu.RLock()
	data := srt.session.data
	srt.session.mu.RUnlock()

	clone.Header.Set("X-Pm-Uid", data.UID)
	clone.Header.Set("User-Agent", "ProtonService/"+srt.session.service)

	switch data.Type {
	case SessionBearer:
		clone.Header.Set("Authorization", "Bearer "+data.AccessToken)
	case SessionCookie:
		clone.AddCookie(&http.Cookie{Name: "AUTH-" + data.UID, Value: data.AccessToken})
	}

	return srt.base.RoundTrip(clone)
}
