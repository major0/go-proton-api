package calendar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://mail.proton.me")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if c == nil || c.gen == nil {
		t.Fatal("expected initialized client")
	}
}

func TestWithUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL, WithUserAgent("MyApp-Calendar/1.0"))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := c.ListEvents(context.Background(), "cal-id"); err != nil {
		t.Fatalf("list events: %v", err)
	}
	if gotUA != "MyApp-Calendar/1.0" {
		t.Fatalf("User-Agent mismatch: got %q", gotUA)
	}
}

func TestListEvents_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"Code":1000,"Events":[]}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	events, err := c.ListEvents(context.Background(), "cal-id")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestListEvents_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"Code":2001,"Error":"Invalid calendar"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.ListEvents(context.Background(), "cal-id")
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status mismatch: got %d", apiErr.StatusCode)
	}
	if apiErr.Code != 2001 || apiErr.Message != "Invalid calendar" {
		t.Fatalf("error body mismatch: %+v", apiErr)
	}
}

func TestListEvents_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"Code":2501,"Error":"No such calendar"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	_, err = c.ListEvents(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSkeletonMethodsNotWired(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://mail.proton.me")
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx := context.Background()

	if _, err := c.ListCalendars(ctx); err == nil {
		t.Error("expected ListCalendars to report not-yet-wired")
	}
	if _, err := c.GetCalendar(ctx, "id"); err == nil {
		t.Error("expected GetCalendar to report not-yet-wired")
	}
	if _, err := c.CreateEvent(ctx, Event{}); err == nil {
		t.Error("expected CreateEvent to report not-yet-wired")
	}
}
