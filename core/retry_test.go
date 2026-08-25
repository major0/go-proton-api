package core

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// fakeTransport records calls and returns pre-configured responses.
type fakeTransport struct {
	responses []*http.Response
	errors    []error
	calls     int
}

func (f *fakeTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	i := f.calls
	f.calls++
	if i < len(f.errors) && f.errors[i] != nil {
		return nil, f.errors[i]
	}
	if i < len(f.responses) {
		return f.responses[i], nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// fakeRefresher records whether refresh was called and can be configured to fail.
type fakeRefresher struct {
	called    bool
	shouldErr bool
}

func (f *fakeRefresher) RefreshToken(_ context.Context) error {
	f.called = true
	if f.shouldErr {
		return errors.New("refresh failed")
	}
	return nil
}

func newRequest(t *testing.T) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.proton.me/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func bodyResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestRetryTransport_Success(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
	}
	rt := newRetryTransport(ft)

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ft.calls != 1 {
		t.Fatalf("expected 1 call, got %d", ft.calls)
	}
}

func TestRetryTransport_NetworkError_RetriesThenSucceeds(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			nil,
			nil,
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
		errors: []error{
			errors.New("connection reset"),
			errors.New("timeout"),
			nil,
		},
	}
	rt := newRetryTransport(ft, withBaseBackoff(1*time.Millisecond))

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ft.calls != 3 {
		t.Fatalf("expected 3 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_NetworkError_ExhaustsRetries(t *testing.T) {
	netErr := errors.New("connection refused")
	ft := &fakeTransport{
		errors: []error{netErr, netErr, netErr, netErr},
	}
	rt := newRetryTransport(ft, withMaxRetries(3), withBaseBackoff(1*time.Millisecond))

	_, err := rt.RoundTrip(newRequest(t))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if ft.calls != 4 { // initial + 3 retries
		t.Fatalf("expected 4 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_5xx_RetriesThenSucceeds(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusInternalServerError, "err"),
			bodyResponse(http.StatusBadGateway, "err"),
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
	}
	rt := newRetryTransport(ft, withBaseBackoff(1*time.Millisecond))

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ft.calls != 3 {
		t.Fatalf("expected 3 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_5xx_ExhaustsRetries(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusInternalServerError, "a"),
			bodyResponse(http.StatusInternalServerError, "b"),
			bodyResponse(http.StatusInternalServerError, "c"),
			bodyResponse(http.StatusInternalServerError, "d"),
		},
	}
	rt := newRetryTransport(ft, withMaxRetries(3), withBaseBackoff(1*time.Millisecond))

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}
	if ft.calls != 4 { // initial + 3 retries
		t.Fatalf("expected 4 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_429_RespectsRetryAfterSeconds(t *testing.T) {
	resp429 := bodyResponse(http.StatusTooManyRequests, "")
	resp429.Header.Set("Retry-After", "1")

	ft := &fakeTransport{
		responses: []*http.Response{
			resp429,
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
	}
	rt := newRetryTransport(ft, withBaseBackoff(1*time.Millisecond))

	// Use a short-lived context to avoid waiting the full second.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.proton.me/test", nil)

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ft.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_429_MissingRetryAfter(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusTooManyRequests, ""),
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
	}
	rt := newRetryTransport(ft, withBaseBackoff(1*time.Millisecond))

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ft.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_401_RefreshesAndRetries(t *testing.T) {
	refresher := &fakeRefresher{}
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusUnauthorized, ""),
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
	}
	rt := newRetryTransport(ft, withTokenRefresher(refresher))

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !refresher.called {
		t.Fatal("expected refresher to be called")
	}
	if ft.calls != 2 {
		t.Fatalf("expected 2 calls, got %d", ft.calls)
	}
}

func TestRetryTransport_401_NoRefresher(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusUnauthorized, "no auth"),
		},
	}
	rt := newRetryTransport(ft)

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if ft.calls != 1 {
		t.Fatalf("expected 1 call, got %d", ft.calls)
	}
}

func TestRetryTransport_401_RefreshFails(t *testing.T) {
	refresher := &fakeRefresher{shouldErr: true}
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusUnauthorized, "first"),
			bodyResponse(http.StatusUnauthorized, "second"),
		},
	}
	rt := newRetryTransport(ft, withTokenRefresher(refresher))

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	// Should re-issue request and return fresh 401.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if !refresher.called {
		t.Fatal("expected refresher to be called")
	}
	if ft.calls != 2 {
		t.Fatalf("expected 2 calls (original + re-issue), got %d", ft.calls)
	}
}

func TestRetryTransport_4xx_NoRetry(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusBadRequest, "bad"),
		},
	}
	rt := newRetryTransport(ft)

	resp, err := rt.RoundTrip(newRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if ft.calls != 1 {
		t.Fatalf("expected 1 call (no retry for 4xx), got %d", ft.calls)
	}
}

func TestRetryTransport_ContextCancelled(t *testing.T) {
	ft := &fakeTransport{
		responses: []*http.Response{
			bodyResponse(http.StatusInternalServerError, ""),
			{StatusCode: http.StatusOK, Body: http.NoBody},
		},
	}
	rt := newRetryTransport(ft, withBaseBackoff(5*time.Second))

	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.proton.me/test", nil)

	// Cancel immediately so backoff aborts.
	cancel()

	_, err := rt.RoundTrip(req)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}
