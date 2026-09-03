package domains

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
		_, _ = w.Write([]byte(`{"Domains":[]}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL, WithUserAgent("MyApp-Domains/1.0"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.ListDomains(context.Background()); err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if gotUA != "MyApp-Domains/1.0" {
		t.Fatalf("User-Agent = %q, want %q", gotUA, "MyApp-Domains/1.0")
	}
}

func TestListDomains(t *testing.T) {
	const payload = `{
		"Domains": [
			{"ID": "d1", "DomainName": "example.com", "State": 1, "VerifyState": 1, "MxState": 1, "SpfState": 1, "DKIMState": 2, "DmarcState": 0, "CatchAll": "addr-1"},
			{"ID": "d2", "DomainName": "example.org", "State": 0, "VerifyState": 0, "MxState": 0, "SpfState": 0, "DKIMState": 0, "DmarcState": 0, "CatchAll": ""}
		]
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/core/v4/domains" {
			t.Errorf("path = %q, want /core/v4/domains", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(domains) = %d, want 2", len(got))
	}
	if got[0].ID != "d1" || got[0].Name != "example.com" {
		t.Errorf("domain[0] = %+v, want ID=d1 Name=example.com", got[0])
	}
	if got[0].State != DomainStateActive || got[0].VerifyState != VerifyStateGood {
		t.Errorf("domain[0] state = %d verify = %d, want active/good", got[0].State, got[0].VerifyState)
	}
	if got[0].DKIMState != DNSRecordStatusInvalid {
		t.Errorf("domain[0].DKIMState = %d, want invalid", got[0].DKIMState)
	}
	if got[0].CatchAll != "addr-1" {
		t.Errorf("domain[0].CatchAll = %q, want addr-1", got[0].CatchAll)
	}
	if got[1].State != DomainStateUnverified {
		t.Errorf("domain[1].State = %d, want unverified", got[1].State)
	}
}

func TestGetDomain(t *testing.T) {
	const payload = `{
		"Domain": {
			"ID": "d1",
			"DomainName": "example.com",
			"State": 1,
			"VerifyState": 1,
			"MxState": 1,
			"SpfState": 1,
			"DKIMState": 1,
			"DmarcState": 1,
			"CatchAll": "addr-9",
			"DNS": [
				{"Type": "TXT", "Hostname": "example.com", "Value": "protonmail-verification=abc", "Status": 1},
				{"Type": "MX", "Hostname": "example.com", "Value": "mail.protonmail.ch", "Status": 0}
			]
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/core/v4/domains/d1" {
			t.Errorf("path = %q, want /core/v4/domains/d1", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := c.GetDomain(context.Background(), "d1")
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if got.ID != "d1" || got.Name != "example.com" {
		t.Errorf("domain = %+v, want ID=d1 Name=example.com", got)
	}
	if len(got.DNSRecords) != 2 {
		t.Fatalf("len(DNSRecords) = %d, want 2", len(got.DNSRecords))
	}
	if got.DNSRecords[0].Type != "TXT" || got.DNSRecords[0].Status != DNSRecordStatusValid {
		t.Errorf("DNSRecords[0] = %+v, want TXT/valid", got.DNSRecords[0])
	}
	if got.DNSRecords[1].Status != DNSRecordStatusNotConfigured {
		t.Errorf("DNSRecords[1].Status = %d, want not-configured", got.DNSRecords[1].Status)
	}
}

func TestGetDomainNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"Error": "Domain does not exist"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.GetDomain(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", err)
	}
}

func TestGetDomainEmptyID(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.GetDomain(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty domain ID")
	}
}

func TestAddDomain(t *testing.T) {
	const payload = `{"Domain": {"ID": "new-1", "DomainName": "new.example.com", "State": 0, "VerifyState": 0}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/core/v4/domains" {
			t.Errorf("path = %q, want /core/v4/domains", r.URL.Path)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := c.AddDomain(context.Background(), "new.example.com")
	if err != nil {
		t.Fatalf("AddDomain: %v", err)
	}
	if got.ID != "new-1" || got.Name != "new.example.com" {
		t.Errorf("domain = %+v, want ID=new-1 Name=new.example.com", got)
	}
}

func TestAddDomainEmptyName(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.AddDomain(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestDeleteDomain(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"Code": 1000}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.DeleteDomain(context.Background(), "d1"); err != nil {
		t.Fatalf("DeleteDomain: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Errorf("method = %q, want DELETE", gotMethod)
	}
	if gotPath != "/core/v4/domains/d1" {
		t.Errorf("path = %q, want /core/v4/domains/d1", gotPath)
	}
}

func TestDeleteDomainEmptyID(t *testing.T) {
	c, err := NewClient(http.DefaultClient, "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.DeleteDomain(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty domain ID")
	}
}

func TestListDNSRecords(t *testing.T) {
	const payload = `{
		"Domain": {
			"ID": "d1",
			"DomainName": "example.com",
			"DNS": [
				{"Type": "TXT", "Hostname": "example.com", "Value": "protonmail-verification=abc", "Status": 1},
				{"Type": "MX", "Hostname": "example.com", "Value": "mail.protonmail.ch", "Status": 2}
			]
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/core/v4/domains/d1" {
			t.Errorf("path = %q, want /core/v4/domains/d1", r.URL.Path)
		}
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got, err := c.ListDNSRecords(context.Background(), "d1")
	if err != nil {
		t.Fatalf("ListDNSRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(records) = %d, want 2", len(got))
	}
	if got[0].Type != "TXT" || got[0].Status != DNSRecordStatusValid {
		t.Errorf("records[0] = %+v, want TXT/valid", got[0])
	}
	if got[1].Status != DNSRecordStatusInvalid {
		t.Errorf("records[1].Status = %d, want invalid", got[1].Status)
	}
}

func TestListDomainsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"Error": "Invalid access token"}`))
	}))
	defer srv.Close()

	c, err := NewClient(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = c.ListDomains(context.Background())
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
