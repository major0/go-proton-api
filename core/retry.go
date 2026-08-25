package core

import (
	"context"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Default retry configuration values.
const (
	defaultMaxRetries  = 3
	defaultBaseBackoff = 1 * time.Second
)

// TokenRefresher performs a token refresh when a 401 response is encountered.
// Implementations must be safe for concurrent use.
type TokenRefresher interface {
	// RefreshToken attempts to refresh the session token. It returns an error
	// if the refresh fails (expired refresh token, account locked, etc.).
	RefreshToken(ctx context.Context) error
}

// retryTransport is an [http.RoundTripper] that adds retry logic with
// exponential backoff around a base transport. It handles 429, 5xx, network
// errors, and 401 (with token refresh) transparently.
type retryTransport struct {
	base        http.RoundTripper
	refresher   TokenRefresher
	maxRetries  int
	baseBackoff time.Duration
}

// retryOption configures a [retryTransport].
type retryOption func(*retryTransport)

// withMaxRetries sets the maximum number of retry attempts. Default: 3.
func withMaxRetries(n int) retryOption {
	return func(rt *retryTransport) {
		rt.maxRetries = n
	}
}

// withBaseBackoff sets the base duration for exponential backoff. Default: 1s.
func withBaseBackoff(d time.Duration) retryOption {
	return func(rt *retryTransport) {
		rt.baseBackoff = d
	}
}

// withTokenRefresher sets the [TokenRefresher] used for 401 handling.
func withTokenRefresher(r TokenRefresher) retryOption {
	return func(rt *retryTransport) {
		rt.refresher = r
	}
}

// newRetryTransport creates a retryTransport wrapping the given base transport.
func newRetryTransport(base http.RoundTripper, opts ...retryOption) *retryTransport {
	rt := &retryTransport{
		base:        base,
		maxRetries:  defaultMaxRetries,
		baseBackoff: defaultBaseBackoff,
	}
	for _, opt := range opts {
		opt(rt)
	}
	return rt
}

// RoundTrip executes the request with retry logic. It retries on 429, 5xx,
// and network errors with exponential backoff. On 401, it attempts a single
// token refresh and retries once. Non-retryable 4xx errors are returned
// immediately.
func (rt *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error

	for attempt := range rt.maxRetries + 1 {
		resp, err = rt.base.RoundTrip(req)

		if err != nil {
			// Network error — retryable.
			if attempt >= rt.maxRetries {
				return nil, err
			}
			if waitErr := rt.backoff(req.Context(), attempt); waitErr != nil {
				return nil, waitErr
			}
			continue
		}

		switch {
		case resp.StatusCode == http.StatusUnauthorized:
			// 401: attempt token refresh once, then retry.
			if attempt > 0 || rt.refresher == nil {
				return resp, nil
			}
			drainBody(resp)
			if refreshErr := rt.refresher.RefreshToken(req.Context()); refreshErr != nil {
				// Refresh failed — re-issue the request to get a fresh 401
				// response the caller can inspect.
				return rt.base.RoundTrip(req)
			}
			// Refreshed successfully — retry immediately (no backoff).
			continue

		case resp.StatusCode == http.StatusTooManyRequests:
			// 429: respect Retry-After, then retry.
			if attempt >= rt.maxRetries {
				return resp, nil
			}
			wait := rt.retryAfterDuration(resp)
			drainBody(resp)
			if waitErr := rt.sleep(req.Context(), wait); waitErr != nil {
				return nil, waitErr
			}
			continue

		case resp.StatusCode >= 500:
			// 5xx: exponential backoff and retry.
			if attempt >= rt.maxRetries {
				return resp, nil
			}
			drainBody(resp)
			if waitErr := rt.backoff(req.Context(), attempt); waitErr != nil {
				return nil, waitErr
			}
			continue

		default:
			// 2xx, 3xx, or non-retryable 4xx — return as-is.
			return resp, nil
		}
	}

	// Shouldn't be reached, but satisfies the compiler.
	return resp, err
}

// backoff sleeps for an exponentially increasing duration with jitter.
func (rt *retryTransport) backoff(ctx context.Context, attempt int) error {
	base := float64(rt.baseBackoff)
	wait := time.Duration(base * math.Pow(2, float64(attempt)))
	// Add jitter: ±25% of the computed wait.
	jitter := time.Duration(float64(wait) * (rand.Float64()*0.5 - 0.25))
	wait += jitter
	return rt.sleep(ctx, wait)
}

// sleep waits for the given duration, respecting context cancellation.
func (rt *retryTransport) sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// retryAfterDuration parses the Retry-After header from a 429 response.
// It handles both delta-seconds and HTTP-date formats. Falls back to the
// base backoff duration if the header is missing or unparseable.
func (rt *retryTransport) retryAfterDuration(resp *http.Response) time.Duration {
	val := resp.Header.Get("Retry-After")
	if val == "" {
		return rt.baseBackoff
	}

	// Try delta-seconds first.
	if seconds, err := strconv.ParseInt(val, 10, 64); err == nil {
		return time.Duration(seconds) * time.Second
	}

	// Try HTTP-date format (RFC 7231 §7.1.1.1).
	if t, err := http.ParseTime(val); err == nil {
		wait := time.Until(t)
		if wait > 0 {
			return wait
		}
	}

	return rt.baseBackoff
}

// drainBody reads and closes a response body to release the underlying
// connection back to the pool.
func drainBody(resp *http.Response) {
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
