package contacts

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	t.Run("nil doer", func(t *testing.T) {
		if _, err := NewClient(nil, "https://example.com"); err == nil {
			t.Fatal("expected error for nil doer")
		}
	})

	t.Run("empty host", func(t *testing.T) {
		if _, err := NewClient(http.DefaultClient, ""); err == nil {
			t.Fatal("expected error for empty host")
		}
	})

	t.Run("trailing slash trimmed", func(t *testing.T) {
		c, err := NewClient(http.DefaultClient, "https://example.com/")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c.host != "https://example.com" {
			t.Fatalf("host = %q, want %q", c.host, "https://example.com")
		}
	})
}

func TestWithUserAgent(t *testing.T) {
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(`{"Contacts":[]}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL, WithUserAgent("MyApp-Contacts/1.0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := c.ListContacts(context.Background()); err != nil {
		t.Fatalf("ListContacts: %v", err)
	}

	if gotUA != "MyApp-Contacts/1.0" {
		t.Fatalf("User-Agent = %q, want %q", gotUA, "MyApp-Contacts/1.0")
	}
}

func TestListContacts(t *testing.T) {
	const payload = `{
		"Contacts": [
			{"ID": "c1", "Name": "Alice", "ContactEmails": [{"Email": "alice@example.com"}]},
			{"ID": "c2", "Name": "Bob", "ContactEmails": [{"Email": "bob@example.com"}, {"Email": "b2@example.com"}]}
		]
	}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/contacts/v4/contacts" {
			t.Errorf("path = %q, want /contacts/v4/contacts", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := c.ListContacts(context.Background())
	if err != nil {
		t.Fatalf("ListContacts: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("len(contacts) = %d, want 2", len(got))
	}
	if got[0].ID != "c1" || got[0].Name != "Alice" {
		t.Errorf("contact[0] = %+v, want ID=c1 Name=Alice", got[0])
	}
	if len(got[0].Emails) != 1 || got[0].Emails[0] != "alice@example.com" {
		t.Errorf("contact[0].Emails = %v, want [alice@example.com]", got[0].Emails)
	}
	if len(got[1].Emails) != 2 {
		t.Errorf("contact[1].Emails = %v, want 2 entries", got[1].Emails)
	}
}

func TestListContactsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"Error": "Invalid access token"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = c.ListContacts(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v, want *APIError", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusUnauthorized)
	}
	if apiErr.Message != "Invalid access token" {
		t.Errorf("Message = %q, want %q", apiErr.Message, "Invalid access token")
	}
}

func TestGetContactNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"Error": "Contact does not exist"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = c.GetContact(context.Background(), "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestGetContactEmptyID(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := c.GetContact(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty contact ID")
	}
}

func TestCreateContactNotWired(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := c.CreateContact(context.Background(), CreateContactReq{}); err == nil {
		t.Fatal("expected not-wired error")
	}
}
