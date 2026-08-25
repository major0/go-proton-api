package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// --- Mock AuthHandler ---

type refreshCall struct {
	service string
	data    SessionData
}

type mockAuthHandler struct {
	mu             sync.Mutex
	refreshCalls   []refreshCall
	convertedTrees []SessionTree
	deauthErrors   []error
}

func (m *mockAuthHandler) OnTokenRefresh(_ context.Context, service string, data SessionData) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refreshCalls = append(m.refreshCalls, refreshCall{service: service, data: data})
	return nil
}

func (m *mockAuthHandler) OnSessionConverted(_ context.Context, tree SessionTree) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.convertedTrees = append(m.convertedTrees, tree)
	return nil
}

func (m *mockAuthHandler) OnDeauth(_ context.Context, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deauthErrors = append(m.deauthErrors, err)
}

// --- Helpers ---

func newTestSession(t *testing.T, opts ...SessionOption) *Session {
	t.Helper()
	transport := NewTransport()
	data := SessionData{
		Type:         SessionBearer,
		UID:          "test-uid-123",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
	}
	s, err := Login(context.Background(), "https://api.proton.me", data, transport, opts...)
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	return s
}

// --- Login tests ---

func TestLogin_Success(t *testing.T) {
	transport := NewTransport()
	data := SessionData{
		Type:         SessionBearer,
		UID:          "uid-abc",
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
	}

	s, err := Login(context.Background(), "https://api.proton.me", data, transport)
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	if s.Host() != "https://api.proton.me" {
		t.Errorf("Host: got %q, want %q", s.Host(), "https://api.proton.me")
	}

	primary := s.Primary()
	if primary.UID != "uid-abc" {
		t.Errorf("Primary UID: got %q, want %q", primary.UID, "uid-abc")
	}
	if primary.AccessToken != "access-123" {
		t.Errorf("Primary AccessToken: got %q, want %q", primary.AccessToken, "access-123")
	}
	if primary.RefreshToken != "refresh-456" {
		t.Errorf("Primary RefreshToken: got %q, want %q", primary.RefreshToken, "refresh-456")
	}
	if primary.Type != SessionBearer {
		t.Errorf("Primary Type: got %v, want %v", primary.Type, SessionBearer)
	}
}

func TestLogin_Validation(t *testing.T) {
	transport := NewTransport()
	validData := SessionData{
		Type:         SessionBearer,
		UID:          "uid-abc",
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
	}

	tests := []struct {
		name      string
		host      string
		data      SessionData
		transport *Transport
	}{
		{
			name:      "empty host",
			host:      "",
			data:      validData,
			transport: transport,
		},
		{
			name: "empty UID",
			host: "https://api.proton.me",
			data: SessionData{
				UID:          "",
				AccessToken:  "access-123",
				RefreshToken: "refresh-456",
			},
			transport: transport,
		},
		{
			name: "empty AccessToken",
			host: "https://api.proton.me",
			data: SessionData{
				UID:          "uid-abc",
				AccessToken:  "",
				RefreshToken: "refresh-456",
			},
			transport: transport,
		},
		{
			name:      "nil transport",
			host:      "https://api.proton.me",
			data:      validData,
			transport: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Login(context.Background(), tc.host, tc.data, tc.transport)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestLogin_WithOptions(t *testing.T) {
	transport := NewTransport()
	data := SessionData{
		Type:         SessionBearer,
		UID:          "uid-abc",
		AccessToken:  "access-123",
		RefreshToken: "refresh-456",
	}

	handler := &mockAuthHandler{}
	s, err := Login(context.Background(), "https://api.proton.me", data, transport,
		WithMaxRetries(5),
		WithRetryBackoff(2*time.Second),
		WithAuthHandler(handler),
	)
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}

	if s.maxRetries != 5 {
		t.Errorf("maxRetries: got %d, want 5", s.maxRetries)
	}
	if s.baseBackoff != 2*time.Second {
		t.Errorf("baseBackoff: got %v, want %v", s.baseBackoff, 2*time.Second)
	}
	if s.authHandler == nil {
		t.Error("authHandler: got nil, want non-nil")
	}
}

// --- Fork tests ---

func TestFork_CreatesServiceSession(t *testing.T) {
	s := newTestSession(t)

	svcData := SessionData{
		Type:         SessionBearer,
		UID:          "svc-uid",
		AccessToken:  "svc-access",
		RefreshToken: "svc-refresh",
	}

	ss := s.Fork("drive", svcData)
	if ss == nil {
		t.Fatal("Fork returned nil")
	}

	got := s.Service("drive")
	if got == nil {
		t.Fatal("Service(\"drive\") returned nil after Fork")
	}
	if got != ss {
		t.Error("Service(\"drive\") returned different pointer than Fork")
	}
	if got.Name() != "drive" {
		t.Errorf("Name: got %q, want %q", got.Name(), "drive")
	}

	data := got.Data()
	if data.AccessToken != "svc-access" {
		t.Errorf("AccessToken: got %q, want %q", data.AccessToken, "svc-access")
	}
}

func TestFork_MultipleServices(t *testing.T) {
	s := newTestSession(t)

	services := []string{"drive", "mail", "calendar"}
	for _, name := range services {
		s.Fork(name, SessionData{
			Type:         SessionBearer,
			UID:          "uid-" + name,
			AccessToken:  "access-" + name,
			RefreshToken: "refresh-" + name,
		})
	}

	all := s.Services()
	if len(all) != 3 {
		t.Fatalf("Services() length: got %d, want 3", len(all))
	}

	for _, name := range services {
		if _, ok := all[name]; !ok {
			t.Errorf("Services() missing %q", name)
		}
	}
}

func TestFork_EmptyName_Panics(t *testing.T) {
	s := newTestSession(t)

	defer func() {
		if r := recover(); r == nil {
			t.Error("Fork with empty name did not panic")
		}
	}()

	s.Fork("", SessionData{
		UID:          "uid",
		AccessToken:  "access",
		RefreshToken: "refresh",
	})
}

// --- ConvertToCookie tests ---

func TestConvertToCookie_InvalidatesForks(t *testing.T) {
	s := newTestSession(t)

	s.Fork("drive", SessionData{
		UID:          "drive-uid",
		AccessToken:  "drive-access",
		RefreshToken: "drive-refresh",
	})
	s.Fork("mail", SessionData{
		UID:          "mail-uid",
		AccessToken:  "mail-access",
		RefreshToken: "mail-refresh",
	})

	err := s.ConvertToCookie(context.Background(), SessionData{
		UID:          "cookie-uid",
		AccessToken:  "cookie-access",
		RefreshToken: "cookie-refresh",
	})
	if err != nil {
		t.Fatalf("ConvertToCookie: %v", err)
	}

	if svc := s.Service("drive"); svc != nil {
		t.Error("Service(\"drive\") should be nil after ConvertToCookie")
	}
	if svc := s.Service("mail"); svc != nil {
		t.Error("Service(\"mail\") should be nil after ConvertToCookie")
	}

	all := s.Services()
	if len(all) != 0 {
		t.Errorf("Services() should be empty after ConvertToCookie, got %d", len(all))
	}

	// Primary should now be Cookie type.
	primary := s.Primary()
	if primary.Type != SessionCookie {
		t.Errorf("Primary Type after convert: got %v, want %v", primary.Type, SessionCookie)
	}
	if primary.AccessToken != "cookie-access" {
		t.Errorf("Primary AccessToken: got %q, want %q", primary.AccessToken, "cookie-access")
	}
}

func TestConvertToCookie_AlreadyConverted(t *testing.T) {
	s := newTestSession(t)

	err := s.ConvertToCookie(context.Background(), SessionData{
		UID:          "cookie-uid",
		AccessToken:  "cookie-access",
		RefreshToken: "cookie-refresh",
	})
	if err != nil {
		t.Fatalf("first ConvertToCookie: %v", err)
	}

	err = s.ConvertToCookie(context.Background(), SessionData{
		UID:          "cookie-uid-2",
		AccessToken:  "cookie-access-2",
		RefreshToken: "cookie-refresh-2",
	})
	if err != ErrAlreadyConverted {
		t.Errorf("second ConvertToCookie: got %v, want %v", err, ErrAlreadyConverted)
	}
}

func TestConvertToCookie_NotifiesHandler(t *testing.T) {
	handler := &mockAuthHandler{}
	s := newTestSession(t, WithAuthHandler(handler))

	err := s.ConvertToCookie(context.Background(), SessionData{
		UID:          "cookie-uid",
		AccessToken:  "cookie-access",
		RefreshToken: "cookie-refresh",
	})
	if err != nil {
		t.Fatalf("ConvertToCookie: %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()

	if len(handler.convertedTrees) != 1 {
		t.Fatalf("OnSessionConverted calls: got %d, want 1", len(handler.convertedTrees))
	}

	tree := handler.convertedTrees[0]
	if tree.Primary.Type != SessionCookie {
		t.Errorf("tree.Primary.Type: got %v, want %v", tree.Primary.Type, SessionCookie)
	}
	if tree.Primary.AccessToken != "cookie-access" {
		t.Errorf("tree.Primary.AccessToken: got %q, want %q", tree.Primary.AccessToken, "cookie-access")
	}
}

// --- Resume tests ---

func TestResume_RestoresAllSessions(t *testing.T) {
	transport := NewTransport()
	tree := SessionTree{
		Primary: SessionData{
			Type:         SessionBearer,
			UID:          "primary-uid",
			AccessToken:  "primary-access",
			RefreshToken: "primary-refresh",
		},
		Services: map[string]SessionData{
			"drive": {
				Type:         SessionBearer,
				UID:          "drive-uid",
				AccessToken:  "drive-access",
				RefreshToken: "drive-refresh",
			},
			"mail": {
				Type:         SessionBearer,
				UID:          "mail-uid",
				AccessToken:  "mail-access",
				RefreshToken: "mail-refresh",
			},
		},
	}

	s, err := Resume(context.Background(), "https://api.proton.me", tree, transport)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}

	primary := s.Primary()
	if primary.UID != "primary-uid" {
		t.Errorf("Primary UID: got %q, want %q", primary.UID, "primary-uid")
	}
	if primary.AccessToken != "primary-access" {
		t.Errorf("Primary AccessToken: got %q, want %q", primary.AccessToken, "primary-access")
	}

	drive := s.Service("drive")
	if drive == nil {
		t.Fatal("Service(\"drive\") returned nil")
	}
	if drive.Data().AccessToken != "drive-access" {
		t.Errorf("drive AccessToken: got %q, want %q", drive.Data().AccessToken, "drive-access")
	}

	mail := s.Service("mail")
	if mail == nil {
		t.Fatal("Service(\"mail\") returned nil")
	}
	if mail.Data().AccessToken != "mail-access" {
		t.Errorf("mail AccessToken: got %q, want %q", mail.Data().AccessToken, "mail-access")
	}
}

func TestResume_CookieSession_SetsConverted(t *testing.T) {
	transport := NewTransport()
	tree := SessionTree{
		Primary: SessionData{
			Type:         SessionCookie,
			UID:          "cookie-uid",
			AccessToken:  "cookie-access",
			RefreshToken: "cookie-refresh",
		},
		Services: map[string]SessionData{},
	}

	s, err := Resume(context.Background(), "https://api.proton.me", tree, transport)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}

	// Verify converted flag is set by attempting ConvertToCookie — should fail.
	err = s.ConvertToCookie(context.Background(), SessionData{
		UID:          "new-uid",
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
	})
	if err != ErrAlreadyConverted {
		t.Errorf("ConvertToCookie after Resume(Cookie): got %v, want %v", err, ErrAlreadyConverted)
	}
}

// --- UpdateTokens tests ---

func TestUpdateTokens_UpdatesServiceData(t *testing.T) {
	s := newTestSession(t)

	s.Fork("drive", SessionData{
		Type:         SessionBearer,
		UID:          "drive-uid",
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
	})

	err := s.UpdateTokens(context.Background(), "drive", SessionData{
		Type:         SessionBearer,
		UID:          "drive-uid",
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
	})
	if err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}

	data := s.Service("drive").Data()
	if data.AccessToken != "new-access" {
		t.Errorf("AccessToken: got %q, want %q", data.AccessToken, "new-access")
	}
	if data.RefreshToken != "new-refresh" {
		t.Errorf("RefreshToken: got %q, want %q", data.RefreshToken, "new-refresh")
	}
}

func TestUpdateTokens_NotFound(t *testing.T) {
	s := newTestSession(t)

	err := s.UpdateTokens(context.Background(), "nonexistent", SessionData{
		UID:          "uid",
		AccessToken:  "access",
		RefreshToken: "refresh",
	})
	if err != ErrServiceNotFound {
		t.Errorf("UpdateTokens for unknown service: got %v, want %v", err, ErrServiceNotFound)
	}
}

func TestUpdateTokens_NotifiesHandler(t *testing.T) {
	handler := &mockAuthHandler{}
	s := newTestSession(t, WithAuthHandler(handler))

	s.Fork("drive", SessionData{
		Type:         SessionBearer,
		UID:          "drive-uid",
		AccessToken:  "old-access",
		RefreshToken: "old-refresh",
	})

	err := s.UpdateTokens(context.Background(), "drive", SessionData{
		Type:         SessionBearer,
		UID:          "drive-uid",
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
	})
	if err != nil {
		t.Fatalf("UpdateTokens: %v", err)
	}

	handler.mu.Lock()
	defer handler.mu.Unlock()

	if len(handler.refreshCalls) != 1 {
		t.Fatalf("OnTokenRefresh calls: got %d, want 1", len(handler.refreshCalls))
	}

	call := handler.refreshCalls[0]
	if call.service != "drive" {
		t.Errorf("OnTokenRefresh service: got %q, want %q", call.service, "drive")
	}
	if call.data.AccessToken != "new-access" {
		t.Errorf("OnTokenRefresh AccessToken: got %q, want %q", call.data.AccessToken, "new-access")
	}
}

// --- UpdatePrimaryTokens tests ---

func TestUpdatePrimaryTokens_UpdatesTokens(t *testing.T) {
	s := newTestSession(t)
	original := s.Primary()

	s.UpdatePrimaryTokens(context.Background(), SessionData{
		Type:         SessionCookie, // this should be ignored
		UID:          "different-uid",
		AccessToken:  "updated-access",
		RefreshToken: "updated-refresh",
	})

	updated := s.Primary()
	if updated.AccessToken != "updated-access" {
		t.Errorf("AccessToken: got %q, want %q", updated.AccessToken, "updated-access")
	}
	if updated.RefreshToken != "updated-refresh" {
		t.Errorf("RefreshToken: got %q, want %q", updated.RefreshToken, "updated-refresh")
	}
	// UID and Type must be preserved.
	if updated.UID != original.UID {
		t.Errorf("UID changed: got %q, want %q", updated.UID, original.UID)
	}
	if updated.Type != original.Type {
		t.Errorf("Type changed: got %v, want %v", updated.Type, original.Type)
	}
}

// --- HTTPClient header injection tests ---

func TestHTTPClient_InjectsBearer(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := NewTransport()
	data := SessionData{
		Type:         SessionBearer,
		UID:          "primary-uid",
		AccessToken:  "primary-access",
		RefreshToken: "primary-refresh",
	}

	s, err := Login(context.Background(), srv.URL, data, transport)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	ss := s.Fork("drive", SessionData{
		Type:         SessionBearer,
		UID:          "svc-uid",
		AccessToken:  "svc-bearer-token",
		RefreshToken: "svc-refresh",
	})

	client := ss.HTTPClient()
	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	want := "Bearer svc-bearer-token"
	if gotAuth != want {
		t.Errorf("Authorization header: got %q, want %q", gotAuth, want)
	}
}

func TestHTTPClient_InjectsCookie(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("AUTH-cookie-uid")
		if err == nil {
			gotCookie = c.Value
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := NewTransport()
	data := SessionData{
		Type:         SessionCookie,
		UID:          "primary-uid",
		AccessToken:  "primary-access",
		RefreshToken: "primary-refresh",
	}

	s, err := Login(context.Background(), srv.URL, data, transport)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	ss := s.Fork("drive", SessionData{
		Type:         SessionCookie,
		UID:          "cookie-uid",
		AccessToken:  "cookie-token-value",
		RefreshToken: "svc-refresh",
	})

	client := ss.HTTPClient()
	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if gotCookie != "cookie-token-value" {
		t.Errorf("Cookie AUTH-cookie-uid: got %q, want %q", gotCookie, "cookie-token-value")
	}
}

func TestHTTPClient_InjectsUID(t *testing.T) {
	var gotUID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUID = r.Header.Get("X-Pm-Uid")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	transport := NewTransport()
	data := SessionData{
		Type:         SessionBearer,
		UID:          "primary-uid",
		AccessToken:  "primary-access",
		RefreshToken: "primary-refresh",
	}

	s, err := Login(context.Background(), srv.URL, data, transport)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	ss := s.Fork("drive", SessionData{
		Type:         SessionBearer,
		UID:          "injected-uid-value",
		AccessToken:  "svc-access",
		RefreshToken: "svc-refresh",
	})

	client := ss.HTTPClient()
	resp, err := client.Get(srv.URL + "/test")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if gotUID != "injected-uid-value" {
		t.Errorf("X-Pm-Uid header: got %q, want %q", gotUID, "injected-uid-value")
	}
}

// --- Concurrency test ---

func TestConcurrent_TokenUpdate(t *testing.T) {
	handler := &mockAuthHandler{}
	s := newTestSession(t, WithAuthHandler(handler))

	s.Fork("drive", SessionData{
		Type:         SessionBearer,
		UID:          "drive-uid",
		AccessToken:  "initial-access",
		RefreshToken: "initial-refresh",
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Writers: update tokens concurrently.
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			_ = s.UpdateTokens(context.Background(), "drive", SessionData{
				Type:         SessionBearer,
				UID:          "drive-uid",
				AccessToken:  "access-updated",
				RefreshToken: "refresh-updated",
			})
			_ = i
		}(i)
	}

	// Readers: read service data concurrently.
	for range goroutines {
		go func() {
			defer wg.Done()
			svc := s.Service("drive")
			if svc != nil {
				_ = svc.Data()
			}
			_ = s.Primary()
		}()
	}

	wg.Wait()

	// If we reach here without race detector failure, concurrency is safe.
	svc := s.Service("drive")
	if svc == nil {
		t.Fatal("Service(\"drive\") is nil after concurrent updates")
	}
	data := svc.Data()
	if data.UID != "drive-uid" {
		t.Errorf("UID changed during concurrent access: got %q", data.UID)
	}
}
