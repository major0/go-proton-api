package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError represents a non-2xx response from the Proton API. Proton returns
// JSON error bodies with a numeric Code and a human-readable Error message.
type APIError struct {
	StatusCode int    // HTTP status code
	Code       int    // Proton error code from response body
	Message    string // Error message from response body
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("proton: %d %s (code %d)", e.StatusCode, e.Message, e.Code)
	}
	return fmt.Sprintf("proton: HTTP %d (code %d)", e.StatusCode, e.Code)
}

// protonError is the JSON error structure returned by the Proton API on
// non-2xx responses.
type protonError struct {
	Code  int    `json:"Code"`
	Error string `json:"Error"`
}

// DecodeResponse reads an HTTP response and decodes the JSON body into the
// target type based on the status code.
//
// For 204 No Content and 202 Accepted with an empty body, it returns the zero
// value of T without attempting to decode. For other 2xx responses, it decodes
// the body as JSON into T.
//
// For non-2xx responses, it returns an [*APIError] containing the HTTP status
// code and, if available, the Proton error code and message from the response
// body.
//
// The response body is always closed before returning.
func DecodeResponse[T any](resp *http.Response) (T, error) {
	defer func() {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}()

	var zero T

	// Non-2xx: parse Proton error body and return APIError.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return zero, parseAPIError(resp)
	}

	// 204 No Content: never has a body.
	if resp.StatusCode == http.StatusNoContent {
		return zero, nil
	}

	// 202 Accepted: may or may not have a body.
	if resp.StatusCode == http.StatusAccepted {
		if resp.Body == nil {
			return zero, nil
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return zero, fmt.Errorf("reading 202 response body: %w", err)
		}
		if len(body) == 0 {
			return zero, nil
		}
		var result T
		if err := json.Unmarshal(body, &result); err != nil {
			return zero, fmt.Errorf("decoding 202 response body: %w", err)
		}
		return result, nil
	}

	// 200, 201, and other 2xx: decode JSON body.
	if resp.Body == nil {
		return zero, fmt.Errorf("expected response body for status %d", resp.StatusCode)
	}
	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return zero, fmt.Errorf("decoding response body: %w", err)
	}
	return result, nil
}

// parseAPIError reads the response body and constructs an [*APIError].
func parseAPIError(resp *http.Response) *APIError {
	apiErr := &APIError{StatusCode: resp.StatusCode}

	if resp.Body == nil {
		return apiErr
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) == 0 {
		return apiErr
	}

	var pe protonError
	if json.Unmarshal(body, &pe) == nil {
		apiErr.Code = pe.Code
		apiErr.Message = pe.Error
	}

	return apiErr
}
