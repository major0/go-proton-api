// Package contacts provides a public client for the Proton Contacts API.
//
// Contacts are stored as encrypted and/or signed vCards. Each contact carries
// one or more "cards" at distinct protection levels (cleartext, signed,
// encrypted and signed). This package exposes plaintext-facing domain types
// ([Contact], [Card]) and handles the PGP crypto internally.
//
// The client depends only on a local [HTTPDoer] and does not import the core
// module or any sibling service module. Consumers supply an authenticated HTTP
// client (for example a forked session's *http.Client) that satisfies HTTPDoer.
package contacts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPDoer performs HTTP requests. The standard *http.Client satisfies this
// interface. Consumers typically pass an authenticated client so that requests
// carry the required auth and User-Agent headers.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ErrNotFound is returned when a requested contact does not exist.
var ErrNotFound = errors.New("contacts: not found")

// APIError represents a non-2xx response from the Contacts API.
type APIError struct {
	// StatusCode is the HTTP status code of the failed response.
	StatusCode int
	// Message is the server-provided error message, if any.
	Message string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("contacts: api error: status %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("contacts: api error: status %d", e.StatusCode)
}

// Client is the public Contacts API client. It handles request construction,
// response parsing, and card crypto, exposing plaintext domain types.
//
// Client is safe for concurrent use as long as the underlying HTTPDoer is.
type Client struct {
	doer      HTTPDoer
	host      string
	userAgent string
}

// ClientOption configures a [Client] at construction time.
type ClientOption func(*Client)

// WithUserAgent sets the User-Agent header sent with each request. If the
// provided HTTPDoer already injects a User-Agent, this value takes precedence.
func WithUserAgent(ua string) ClientOption {
	return func(c *Client) {
		c.userAgent = ua
	}
}

// NewClient constructs a Contacts client. The doer performs HTTP requests
// (typically an authenticated *http.Client), and host is the Proton API base
// URL (for example "https://mail.proton.me/api").
//
// NewClient returns an error if doer is nil or host is empty.
func NewClient(doer HTTPDoer, host string, opts ...ClientOption) (*Client, error) {
	if doer == nil {
		return nil, fmt.Errorf("contacts: new client: doer must not be nil")
	}
	if host == "" {
		return nil, fmt.Errorf("contacts: new client: host must not be empty")
	}

	c := &Client{
		doer: doer,
		host: strings.TrimSuffix(host, "/"),
	}
	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// contactEmail is the wire shape of an email entry in a contact listing.
type contactEmail struct {
	Email string `json:"Email"`
}

// wireContact is the wire shape of a contact in a listing response. Only the
// fields the public layer needs are modeled; the full card payloads are
// fetched via GetContact.
type wireContact struct {
	ID            string         `json:"ID"`
	Name          string         `json:"Name"`
	ContactEmails []contactEmail `json:"ContactEmails"`
}

// listContactsResponse is the wire shape of the contacts list endpoint.
type listContactsResponse struct {
	Contacts []wireContact `json:"Contacts"`
}

// ListContacts returns all contacts for the authenticated user. Card payloads
// are not decrypted here; use [Client.GetContact] to fetch and decrypt a
// contact's cards.
func (c *Client) ListContacts(ctx context.Context) ([]Contact, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+"/contacts/v4/contacts", nil)
	if err != nil {
		return nil, fmt.Errorf("contacts: list contacts: %w", err)
	}

	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("contacts: list contacts: %w", err)
	}

	var resp listContactsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("contacts: list contacts: decode: %w", err)
	}

	contacts := make([]Contact, 0, len(resp.Contacts))
	for _, wc := range resp.Contacts {
		emails := make([]string, 0, len(wc.ContactEmails))
		for _, e := range wc.ContactEmails {
			emails = append(emails, e.Email)
		}
		contacts = append(contacts, Contact{
			ID:     wc.ID,
			Name:   wc.Name,
			Emails: emails,
		})
	}

	return contacts, nil
}

// GetContact fetches a single contact by ID.
//
// Card decryption is not yet wired: the returned contact carries card payloads
// as delivered by the API. Decrypting them requires the caller's key ring,
// which will be threaded through in a later iteration.
func (c *Client) GetContact(ctx context.Context, contactID string) (*Contact, error) {
	if contactID == "" {
		return nil, fmt.Errorf("contacts: get contact: contact ID must not be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+"/contacts/v4/contacts/"+contactID, nil)
	if err != nil {
		return nil, fmt.Errorf("contacts: get contact: %w", err)
	}

	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("contacts: get contact: %w", err)
	}

	var resp struct {
		Contact wireContact `json:"Contact"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("contacts: get contact: decode: %w", err)
	}

	emails := make([]string, 0, len(resp.Contact.ContactEmails))
	for _, e := range resp.Contact.ContactEmails {
		emails = append(emails, e.Email)
	}

	// TODO: fetch card payloads and decrypt them via internal/crypto once the
	// caller's key ring is threaded through the public API.
	return &Contact{
		ID:     resp.Contact.ID,
		Name:   resp.Contact.Name,
		Emails: emails,
	}, nil
}

// CreateContact creates a new contact.
//
// This method is not yet wired: encrypting and signing the request's cards and
// mapping the created resource back to a domain [Contact] depends on the
// caller's key ring, which will be threaded through in a later iteration.
func (c *Client) CreateContact(_ context.Context, _ CreateContactReq) (*Contact, error) {
	return nil, fmt.Errorf("contacts: create contact: not yet wired")
}

// do executes the request, maps non-2xx responses to errors, and returns the
// response body for successful requests.
func (c *Client) do(req *http.Request) ([]byte, error) {
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.doer.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    apiErrorMessage(body),
		}
	}

	return body, nil
}

// apiErrorMessage extracts the Proton "Error" field from an error response
// body, returning an empty string if the body is not the expected shape.
func apiErrorMessage(body []byte) string {
	var e struct {
		Error string `json:"Error"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return ""
	}
	return e.Error
}
