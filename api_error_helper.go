package proton

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// apiErrorFromGenResponse extracts an APIError from a generated client response.
// The rawBody parameter is the pre-read Body field from the generated response struct,
// since the generated client consumes resp.Body during parsing.
func apiErrorFromGenResponse(httpResp *http.Response, rawBody []byte) error {
	if httpResp == nil {
		return fmt.Errorf("nil HTTP response")
	}

	apiErr := &APIError{
		Status: httpResp.StatusCode,
	}

	if len(rawBody) > 0 {
		if jsonErr := json.Unmarshal(rawBody, apiErr); jsonErr == nil {
			apiErr.Status = httpResp.StatusCode
			return apiErr
		}
	}

	// Fallback: use HTTP status as the error message.
	apiErr.Message = httpResp.Status
	return apiErr
}

// readBody reads the full body from an HTTP response.
func readBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}
	return body, nil
}
