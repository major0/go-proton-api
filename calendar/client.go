package calendar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	calendarapi "github.com/ProtonMail/go-proton-api/calendar/internal/generated"
)

// ErrNotFound is returned when a requested calendar or event does not exist.
var ErrNotFound = errors.New("calendar: not found")

// HTTPDoer performs HTTP requests. The standard *http.Client satisfies this
// interface. Calendar defines its own copy so the module does not depend on
// core or any sibling service module for HTTP transport.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// APIError represents a non-2xx response from the Proton Calendar API. Proton
// returns JSON error bodies with a numeric Code and a human-readable Error.
type APIError struct {
	StatusCode int    // HTTP status code
	Code       int    // Proton error code from response body
	Message    string // error message from response body
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("calendar: %d %s (code %d)", e.StatusCode, e.Message, e.Code)
	}
	return fmt.Sprintf("calendar: HTTP %d (code %d)", e.StatusCode, e.Code)
}

// protonError is the JSON error body returned by the Proton API on non-2xx
// responses.
type protonError struct {
	Code  int    `json:"Code"`
	Error string `json:"Error"`
}

// Client is the public, plaintext-facing Proton Calendar client. It wraps the
// generated transport client and handles encryption transparently.
type Client struct {
	gen *calendarapi.Client
}

// ClientOption configures a Client during construction.
type ClientOption func(*clientConfig)

type clientConfig struct {
	userAgent string
}

// WithUserAgent sets a custom User-Agent header on every request.
func WithUserAgent(ua string) ClientOption {
	return func(c *clientConfig) {
		c.userAgent = ua
	}
}

// NewClient creates a Calendar client that issues requests via doer against
// the given host (e.g. "https://mail.proton.me"). The doer is typically a
// forked service session from core, but any HTTPDoer works.
func NewClient(doer HTTPDoer, host string, opts ...ClientOption) (*Client, error) {
	cfg := clientConfig{}
	for _, o := range opts {
		o(&cfg)
	}

	genOpts := []calendarapi.ClientOption{
		calendarapi.WithHTTPClient(doer),
	}
	if cfg.userAgent != "" {
		ua := cfg.userAgent
		genOpts = append(genOpts, calendarapi.WithRequestEditorFn(
			func(_ context.Context, req *http.Request) error {
				req.Header.Set("User-Agent", ua)
				return nil
			},
		))
	}

	gen, err := calendarapi.NewClient(host, genOpts...)
	if err != nil {
		return nil, fmt.Errorf("calendar: new client: %w", err)
	}

	return &Client{gen: gen}, nil
}

// ListCalendars returns the user's calendars.
//
// Not yet wired: the calendar listing endpoint is served by the core account
// API rather than the calendar transport client. This returns decrypted
// domain types once the endpoint is available.
func (c *Client) ListCalendars(_ context.Context) ([]Calendar, error) {
	return nil, fmt.Errorf("calendar: ListCalendars: not yet wired")
}

// GetCalendar returns a single calendar by ID.
//
// Not yet wired: see [Client.ListCalendars].
func (c *Client) GetCalendar(_ context.Context, calendarID string) (*Calendar, error) {
	return nil, fmt.Errorf("calendar: GetCalendar(%q): not yet wired", calendarID)
}

// ListEvents returns the events for a calendar.
//
// The request is dispatched to the calendar transport client. Decryption of
// event fields (title, description, location, attendees) under the calendar
// keyring is not yet wired, so the returned events carry only server-provided
// identifiers.
func (c *Client) ListEvents(ctx context.Context, calendarID string) ([]Event, error) {
	resp, err := c.gen.CalendarListV1Events(ctx, calendarID)
	if err != nil {
		return nil, fmt.Errorf("calendar: ListEvents: %w", err)
	}

	// TODO: decrypt event fields under the calendar keyring. The wire payload
	// is retained here only long enough to surface transport/API errors.
	if _, err := decodeResponse[json.RawMessage](resp); err != nil {
		return nil, fmt.Errorf("calendar: ListEvents: %w", err)
	}

	return []Event{}, nil
}

// CreateEvent creates a calendar event.
//
// Not yet wired: event field encryption under the calendar keyring is pending.
func (c *Client) CreateEvent(_ context.Context, _ Event) (*Event, error) {
	return nil, fmt.Errorf("calendar: CreateEvent: not yet wired")
}

// decodeResponse decodes a 2xx JSON body into T, or returns an [*APIError] for
// non-2xx responses. The response body is always closed.
func decodeResponse[T any](resp *http.Response) (T, error) {
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	var zero T

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, parseAPIError(resp)
	}

	if resp.StatusCode == http.StatusNoContent {
		return zero, nil
	}

	if resp.Body == nil {
		return zero, nil
	}

	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		if errors.Is(err, io.EOF) {
			return zero, nil
		}
		return zero, fmt.Errorf("decoding response body: %w", err)
	}
	return result, nil
}

// parseAPIError reads the response body and constructs an [*APIError]. A 404
// maps additionally through [ErrNotFound] for callers matching on it.
func parseAPIError(resp *http.Response) error {
	apiErr := &APIError{StatusCode: resp.StatusCode}

	if resp.Body != nil {
		if body, err := io.ReadAll(resp.Body); err == nil && len(body) > 0 {
			var pe protonError
			if json.Unmarshal(body, &pe) == nil {
				apiErr.Code = pe.Code
				apiErr.Message = pe.Error
			}
		}
	}

	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, apiErr.Error())
	}

	return apiErr
}
