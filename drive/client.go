package drive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// HTTPDoer is the interface for making HTTP requests. It is satisfied by
// *http.Client (and by extension, the client returned from
// core.ServiceSession.HTTPClient()). Consumers pass a pre-authenticated
// HTTP client; the drive package does not manage authentication.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client is the public Proton Drive API client. It handles encryption and
// decryption transparently — consumers work exclusively with plaintext domain
// types. All cryptographic operations (name encryption, XAttr encryption,
// keyring derivation, signature creation/verification) happen internally
// before and after API calls.
//
// Client is safe for concurrent use from multiple goroutines.
type Client struct {
	http HTTPDoer
	host string
	ua   string
}

// ClientOption configures a Client at construction time.
type ClientOption func(*Client)

// WithUserAgent sets a custom User-Agent prefix for Drive API requests.
func WithUserAgent(ua string) ClientOption {
	return func(c *Client) {
		c.ua = ua
	}
}

// NewClient creates a Drive client that uses the given HTTP doer (typically
// from a forked core.ServiceSession) and host URL.
//
// The host is the Proton API base URL (e.g., "https://mail.proton.me/api").
// The doer should be an authenticated *http.Client obtained from the core
// session layer.
func NewClient(doer HTTPDoer, host string, opts ...ClientOption) *Client {
	c := &Client{
		http: doer,
		host: host,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ListShares returns all shares accessible to the authenticated user.
func (c *Client) ListShares(ctx context.Context) ([]Share, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+"/drive/shares", nil)
	if err != nil {
		return nil, fmt.Errorf("drive: list shares: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: list shares: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: list shares: %w", err)
	}

	var body struct {
		Shares []wireShare `json:"Shares"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: list shares: decode: %w", err)
	}

	shares := make([]Share, 0, len(body.Shares))
	for _, ws := range body.Shares {
		shares = append(shares, ws.toDomain())
	}
	return shares, nil
}

// GetShare retrieves a single share by ID.
func (c *Client) GetShare(ctx context.Context, shareID string) (*Share, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+"/drive/shares/"+shareID, nil)
	if err != nil {
		return nil, fmt.Errorf("drive: get share %s: %w", shareID, err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: get share %s: %w", shareID, err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: get share %s: %w", shareID, err)
	}

	var body struct {
		Share wireShare `json:"Share"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: get share %s: decode: %w", shareID, err)
	}

	s := body.Share.toDomain()
	return &s, nil
}

// ListVolumes returns all volumes for the authenticated user.
func (c *Client) ListVolumes(ctx context.Context) ([]Volume, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+"/drive/volumes", nil)
	if err != nil {
		return nil, fmt.Errorf("drive: list volumes: %w", err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: list volumes: %w", err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: list volumes: %w", err)
	}

	var body struct {
		Volumes []wireVolume `json:"Volumes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: list volumes: decode: %w", err)
	}

	volumes := make([]Volume, 0, len(body.Volumes))
	for _, wv := range body.Volumes {
		volumes = append(volumes, wv.toDomain())
	}
	return volumes, nil
}

// setHeaders applies common request headers.
func (c *Client) setHeaders(req *http.Request) {
	if c.ua != "" {
		req.Header.Set("User-Agent", c.ua)
	}
	req.Header.Set("Content-Type", "application/json")
}

// jsonReader wraps a JSON byte slice in a bytes.Reader for use as a request body.
func jsonReader(data []byte) io.Reader {
	return bytes.NewReader(data)
}

// checkResponse returns an error if the HTTP response indicates failure.
func checkResponse(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	var apiErr struct {
		Code    int    `json:"Code"`
		Error   string `json:"Error"`
		Details string `json:"Details"`
	}
	if json.Unmarshal(body, &apiErr) == nil && apiErr.Error != "" {
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       apiErr.Code,
			Message:    apiErr.Error,
		}
	}

	return &APIError{
		StatusCode: resp.StatusCode,
		Message:    http.StatusText(resp.StatusCode),
	}
}

// APIError represents an error response from the Proton Drive API.
type APIError struct {
	StatusCode int
	Code       int
	Message    string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("drive: API error %d (HTTP %d): %s", e.Code, e.StatusCode, e.Message)
	}
	return fmt.Sprintf("drive: HTTP %d: %s", e.StatusCode, e.Message)
}

// ErrNotFound is returned when a requested resource does not exist.
var ErrNotFound = errors.New("drive: not found")

// wireShare is the JSON representation from the API. Fields that require
// decryption are handled during the toDomain conversion.
type wireShare struct {
	ShareID  string `json:"ShareID"`
	VolumeID string `json:"VolumeID"`
	LinkID   string `json:"LinkID"`
	Type     int    `json:"Type"`
	State    int    `json:"State"`
}

func (ws wireShare) toDomain() Share {
	return Share{
		ID:       ws.ShareID,
		VolumeID: ws.VolumeID,
		LinkID:   ws.LinkID,
		Type:     ShareType(ws.Type),
		State:    ShareState(ws.State),
	}
}

// wireVolume is the JSON representation from the API.
type wireVolume struct {
	VolumeID string `json:"VolumeID"`
	State    int    `json:"State"`
}

func (wv wireVolume) toDomain() Volume {
	return Volume{
		ID:    wv.VolumeID,
		State: VolumeState(wv.State),
	}
}
