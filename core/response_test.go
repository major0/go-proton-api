package core

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type testPayload struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func TestDecodeResponse_200_DecodesBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"id":"abc","name":"test"}`)),
	}

	got, err := DecodeResponse[testPayload](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "abc" || got.Name != "test" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDecodeResponse_201_DecodesBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusCreated,
		Body:       io.NopCloser(strings.NewReader(`{"id":"new-1","name":"created"}`)),
	}

	got, err := DecodeResponse[testPayload](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "new-1" || got.Name != "created" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDecodeResponse_202_EmptyBody_ReturnsZero(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusAccepted,
		Body:       io.NopCloser(strings.NewReader("")),
	}

	got, err := DecodeResponse[testPayload](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "" || got.Name != "" {
		t.Fatalf("expected zero value, got: %+v", got)
	}
}

func TestDecodeResponse_202_NilBody_ReturnsZero(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusAccepted,
		Body:       nil,
	}

	got, err := DecodeResponse[testPayload](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "" || got.Name != "" {
		t.Fatalf("expected zero value, got: %+v", got)
	}
}

func TestDecodeResponse_202_WithBody_DecodesIt(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusAccepted,
		Body:       io.NopCloser(strings.NewReader(`{"id":"async-1","name":"queued"}`)),
	}

	got, err := DecodeResponse[testPayload](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "async-1" || got.Name != "queued" {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestDecodeResponse_204_ReturnsZero(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusNoContent,
		Body:       http.NoBody,
	}

	got, err := DecodeResponse[testPayload](resp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.ID != "" || got.Name != "" {
		t.Fatalf("expected zero value, got: %+v", got)
	}
}

func TestDecodeResponse_NonSuccess_ReturnsAPIError(t *testing.T) {
	body := `{"Code":9001,"Error":"human verification required"}`
	resp := &http.Response{
		StatusCode: http.StatusUnprocessableEntity,
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	_, err := DecodeResponse[testPayload](resp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected status 422, got %d", apiErr.StatusCode)
	}
	if apiErr.Code != 9001 {
		t.Fatalf("expected code 9001, got %d", apiErr.Code)
	}
	if apiErr.Message != "human verification required" {
		t.Fatalf("expected message 'human verification required', got %q", apiErr.Message)
	}
}

func TestDecodeResponse_NonSuccess_EmptyBody(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(strings.NewReader("")),
	}

	_, err := DecodeResponse[testPayload](resp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", apiErr.StatusCode)
	}
	if apiErr.Code != 0 {
		t.Fatalf("expected code 0 (unparsed), got %d", apiErr.Code)
	}
}

func TestDecodeResponse_MalformedJSON_ReturnsDecodeError(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{not valid json`)),
	}

	_, err := DecodeResponse[testPayload](resp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if errors.As(err, new(*APIError)) {
		t.Fatal("should not be APIError for decode failure")
	}
}

func TestAPIError_ErrorString(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want string
	}{
		{
			name: "with message",
			err:  &APIError{StatusCode: 422, Code: 9001, Message: "verification required"},
			want: "proton: 422 verification required (code 9001)",
		},
		{
			name: "without message",
			err:  &APIError{StatusCode: 500, Code: 0, Message: ""},
			want: "proton: HTTP 500 (code 0)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}
