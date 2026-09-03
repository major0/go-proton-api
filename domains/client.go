// Package domains provides a public client for the Proton Domains API.
//
// Domains are custom email/organization domains managed by an organization
// (domain names, DNS records, verification state, catch-all settings). This is
// administrative, server-side organizational metadata — it is NOT end-to-end
// encrypted. Consequently this package performs no PGP crypto: the public
// layer maps wire types to plaintext domain types directly.
//
// The client depends only on a local [HTTPDoer] and does not import the core
// module or any sibling service module. Consumers supply an authenticated HTTP
// client (for example a forked session's *http.Client) that satisfies HTTPDoer.
package domains

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// domainsBasePath is the API path prefix for all domain endpoints.
const domainsBasePath = "/core/v4/domains"

// HTTPDoer performs HTTP requests. The standard *http.Client satisfies this
// interface. Consumers typically pass an authenticated client so that requests
// carry the required auth and User-Agent headers.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ErrNotFound is returned when a requested domain does not exist.
var ErrNotFound = errors.New("domains: not found")

// APIError represents a non-2xx response from the Domains API.
type APIError struct {
	// StatusCode is the HTTP status code of the failed response.
	StatusCode int
	// Message is the server-provided error message, if any.
	Message string
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("domains: api error: status %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("domains: api error: status %d", e.StatusCode)
}

// Client is the public Domains API client. It handles request construction and
// response parsing, exposing plaintext domain types.
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

// NewClient constructs a Domains client. The doer performs HTTP requests
// (typically an authenticated *http.Client), and host is the Proton API base
// URL (for example "https://mail.proton.me/api").
//
// NewClient returns an error if doer is nil or host is empty.
func NewClient(doer HTTPDoer, host string, opts ...ClientOption) (*Client, error) {
	if doer == nil {
		return nil, fmt.Errorf("domains: new client: doer must not be nil")
	}
	if host == "" {
		return nil, fmt.Errorf("domains: new client: host must not be empty")
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

// wireDNSRecord is the wire shape of a DNS record entry on a domain.
type wireDNSRecord struct {
	Type     string `json:"Type"`
	Hostname string `json:"Hostname"`
	Value    string `json:"Value"`
	Status   int    `json:"Status"`
}

// wireDomain is the wire shape of a domain object in list and detail responses.
type wireDomain struct {
	ID          string          `json:"ID"`
	DomainName  string          `json:"DomainName"`
	State       int             `json:"State"`
	VerifyState int             `json:"VerifyState"`
	MxState     int             `json:"MxState"`
	SpfState    int             `json:"SpfState"`
	DKIMState   int             `json:"DKIMState"`
	DmarcState  int             `json:"DmarcState"`
	CatchAll    string          `json:"CatchAll"`
	DNS         []wireDNSRecord `json:"DNS"`
}

// toDomain converts a wire domain into a plaintext domain type.
func (w wireDomain) toDomain() Domain {
	records := make([]DNSRecord, 0, len(w.DNS))
	for _, r := range w.DNS {
		records = append(records, DNSRecord{
			Type:     r.Type,
			Hostname: r.Hostname,
			Value:    r.Value,
			Status:   DNSRecordStatus(r.Status),
		})
	}
	return Domain{
		ID:          w.ID,
		Name:        w.DomainName,
		State:       DomainState(w.State),
		VerifyState: VerifyState(w.VerifyState),
		MXState:     DNSRecordStatus(w.MxState),
		SPFState:    DNSRecordStatus(w.SpfState),
		DKIMState:   DNSRecordStatus(w.DKIMState),
		DMARCState:  DNSRecordStatus(w.DmarcState),
		CatchAll:    w.CatchAll,
		DNSRecords:  records,
	}
}

// listDomainsResponse is the wire shape of the list-domains endpoint.
type listDomainsResponse struct {
	Domains []wireDomain `json:"Domains"`
}

// domainResponse is the wire shape of a single-domain response envelope.
type domainResponse struct {
	Domain wireDomain `json:"Domain"`
}

// ListDomains returns all custom domains for the authenticated organization.
func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+domainsBasePath, nil)
	if err != nil {
		return nil, fmt.Errorf("domains: list domains: %w", err)
	}
	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("domains: list domains: %w", err)
	}
	var resp listDomainsResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("domains: list domains: decode: %w", err)
	}
	domains := make([]Domain, 0, len(resp.Domains))
	for _, wd := range resp.Domains {
		domains = append(domains, wd.toDomain())
	}
	return domains, nil
}

// GetDomain fetches a single custom domain by ID.
func (c *Client) GetDomain(ctx context.Context, domainID string) (*Domain, error) {
	if domainID == "" {
		return nil, fmt.Errorf("domains: get domain: domain ID must not be empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+domainsBasePath+"/"+domainID, nil)
	if err != nil {
		return nil, fmt.Errorf("domains: get domain: %w", err)
	}
	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("domains: get domain: %w", err)
	}
	var resp domainResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("domains: get domain: decode: %w", err)
	}
	domain := resp.Domain.toDomain()
	return &domain, nil
}

// AddDomain registers a new custom domain by name and returns the created
// domain, including the DNS records the organization must configure.
func (c *Client) AddDomain(ctx context.Context, name string) (*Domain, error) {
	if name == "" {
		return nil, fmt.Errorf("domains: add domain: name must not be empty")
	}
	reqBody, err := json.Marshal(struct {
		Name string `json:"Name"`
	}{Name: name})
	if err != nil {
		return nil, fmt.Errorf("domains: add domain: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+domainsBasePath, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("domains: add domain: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("domains: add domain: %w", err)
	}
	var resp domainResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("domains: add domain: decode: %w", err)
	}
	domain := resp.Domain.toDomain()
	return &domain, nil
}

// DeleteDomain removes a custom domain by ID.
func (c *Client) DeleteDomain(ctx context.Context, domainID string) error {
	if domainID == "" {
		return fmt.Errorf("domains: delete domain: domain ID must not be empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.host+domainsBasePath+"/"+domainID, nil)
	if err != nil {
		return fmt.Errorf("domains: delete domain: %w", err)
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("domains: delete domain: %w", err)
	}
	return nil
}

// ListDNSRecords returns the DNS records the organization must configure for
// the given custom domain. The records are carried on the domain detail
// response; this method fetches that domain and returns its records.
func (c *Client) ListDNSRecords(ctx context.Context, domainID string) ([]DNSRecord, error) {
	if domainID == "" {
		return nil, fmt.Errorf("domains: list dns records: domain ID must not be empty")
	}
	domain, err := c.GetDomain(ctx, domainID)
	if err != nil {
		return nil, fmt.Errorf("domains: list dns records: %w", err)
	}
	return domain.DNSRecords, nil
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
