package drive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// recordingServer returns a server plus an accessor for the last request.
func recordingServer(t *testing.T, status int, body string) (*httptest.Server, func() *http.Request) {
	t.Helper()

	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	return srv, func() *http.Request { return last }
}

func TestNewClient(t *testing.T) {
	c := NewClient(http.DefaultClient, "https://api.example.com", WithUserAgent("test-agent/1.0"))

	if c.host != "https://api.example.com" {
		t.Errorf("host: got %q, want %q", c.host, "https://api.example.com")
	}
	if c.ua != "test-agent/1.0" {
		t.Errorf("ua: got %q, want %q", c.ua, "test-agent/1.0")
	}
	if c.http == nil {
		t.Error("http doer must not be nil")
	}
}

func TestListShares(t *testing.T) {
	body := `{"Shares":[
		{"ShareID":"s1","VolumeID":"v1","LinkID":"l1","Type":1,"State":1},
		{"ShareID":"s2","VolumeID":"v2","LinkID":"l2","Type":2,"State":2}
	]}`
	srv, _ := recordingServer(t, http.StatusOK, body)
	c := NewClient(srv.Client(), srv.URL)

	shares, err := c.ListShares(context.Background())
	if err != nil {
		t.Fatalf("ListShares: %v", err)
	}
	if len(shares) != 2 {
		t.Fatalf("got %d shares, want 2", len(shares))
	}
	if shares[0].ID != "s1" || shares[0].VolumeID != "v1" || shares[0].LinkID != "l1" {
		t.Errorf("share[0] mapping wrong: %+v", shares[0])
	}
	if shares[0].Type != ShareTypeMain || shares[0].State != ShareStateActive {
		t.Errorf("share[0] enum mapping wrong: type=%d state=%d", shares[0].Type, shares[0].State)
	}
	if shares[1].Type != ShareTypeStandard || shares[1].State != ShareStateDeleted {
		t.Errorf("share[1] enum mapping wrong: type=%d state=%d", shares[1].Type, shares[1].State)
	}
}

func TestGetShare(t *testing.T) {
	body := `{"Share":{"ShareID":"s1","VolumeID":"v1","LinkID":"l1","Type":4,"State":1}}`
	srv, _ := recordingServer(t, http.StatusOK, body)
	c := NewClient(srv.Client(), srv.URL)

	s, err := c.GetShare(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetShare: %v", err)
	}
	if s.ID != "s1" || s.VolumeID != "v1" || s.LinkID != "l1" {
		t.Errorf("share mapping wrong: %+v", s)
	}
	if s.Type != ShareTypePhotos {
		t.Errorf("share type: got %d, want %d", s.Type, ShareTypePhotos)
	}
}

func TestListVolumes(t *testing.T) {
	body := `{"Volumes":[{"VolumeID":"v1","State":1},{"VolumeID":"v2","State":3}]}`
	srv, _ := recordingServer(t, http.StatusOK, body)
	c := NewClient(srv.Client(), srv.URL)

	vols, err := c.ListVolumes(context.Background())
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	if len(vols) != 2 {
		t.Fatalf("got %d volumes, want 2", len(vols))
	}
	if vols[0].ID != "v1" || vols[0].State != VolumeStateActive {
		t.Errorf("volume[0] mapping wrong: %+v", vols[0])
	}
	if vols[1].State != VolumeStateLocked {
		t.Errorf("volume[1] state: got %d, want %d", vols[1].State, VolumeStateLocked)
	}
}

func TestListChildren(t *testing.T) {
	body := `{"Links":[
		{"LinkID":"l1","ParentLinkID":"p1","Name":"enc-name-1","Type":2,"MIMEType":"text/plain","Size":100,"State":1,"CreateTime":10,"ModifyTime":20,"SignatureEmail":"a@proton.me"},
		{"LinkID":"l2","ParentLinkID":"p1","Name":"enc-name-2","Type":1,"MIMEType":"","Size":0,"State":1,"CreateTime":30,"ModifyTime":40,"SignatureEmail":"b@proton.me"}
	]}`
	srv, _ := recordingServer(t, http.StatusOK, body)
	c := NewClient(srv.Client(), srv.URL)

	entries, err := c.ListChildren(context.Background(), "s1", "p1")
	if err != nil {
		t.Fatalf("ListChildren: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	l0 := entries[0].Link
	if l0.ID != "l1" || l0.ParentID != "p1" || l0.Type != LinkTypeFile {
		t.Errorf("entry[0] mapping wrong: %+v", l0)
	}
	if l0.MIMEType != "text/plain" || l0.Size != 100 || l0.State != LinkStateActive {
		t.Errorf("entry[0] fields wrong: %+v", l0)
	}
	if l0.CreateTime != 10 || l0.ModifyTime != 20 || l0.SignatureEmail != "a@proton.me" {
		t.Errorf("entry[0] metadata wrong: %+v", l0)
	}
	if entries[1].Link.Type != LinkTypeFolder {
		t.Errorf("entry[1] type: got %d, want %d", entries[1].Link.Type, LinkTypeFolder)
	}
}

func TestGetLink(t *testing.T) {
	body := `{"Links":[{"LinkID":"l1","ParentLinkID":"p1","Name":"enc","Type":2,"MIMEType":"application/pdf","Size":42,"State":1,"CreateTime":1,"ModifyTime":2,"SignatureEmail":"x@proton.me"}]}`
	srv, getReq := recordingServer(t, http.StatusOK, body)
	c := NewClient(srv.Client(), srv.URL)

	link, err := c.GetLink(context.Background(), "s1", "l1")
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if link.ID != "l1" || link.ParentID != "p1" || link.MIMEType != "application/pdf" || link.Size != 42 {
		t.Errorf("link mapping wrong: %+v", link)
	}

	// GetLink must issue a POST (fetch_metadata) rather than a GET.
	if r := getReq(); r != nil && r.Method != http.MethodPost {
		t.Errorf("GetLink method: got %s, want POST", r.Method)
	}
}

func TestGetLink_NotFound(t *testing.T) {
	srv, _ := recordingServer(t, http.StatusOK, `{"Links":[]}`)
	c := NewClient(srv.Client(), srv.URL)

	_, err := c.GetLink(context.Background(), "s1", "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestListRevisions(t *testing.T) {
	body := `{"Revisions":[
		{"ID":"r1","Size":500,"State":1,"CreateTime":100,"ModifyTime":200,"XAttr":"","Blocks":[{"Index":0,"URL":"http://b/0","Size":250},{"Index":1,"URL":"http://b/1","Size":250}]},
		{"ID":"r2","Size":10,"State":2,"CreateTime":1,"ModifyTime":2,"XAttr":"","Blocks":[]}
	]}`
	srv, _ := recordingServer(t, http.StatusOK, body)
	c := NewClient(srv.Client(), srv.URL)

	revs, err := c.ListRevisions(context.Background(), "s1", "l1")
	if err != nil {
		t.Fatalf("ListRevisions: %v", err)
	}
	if len(revs) != 2 {
		t.Fatalf("got %d revisions, want 2", len(revs))
	}
	if revs[0].ID != "r1" || revs[0].Size != 500 || revs[0].State != RevisionStateActive {
		t.Errorf("rev[0] mapping wrong: %+v", revs[0])
	}
	if len(revs[0].Blocks) != 2 {
		t.Fatalf("rev[0] blocks: got %d, want 2", len(revs[0].Blocks))
	}
	if revs[0].Blocks[1].Index != 1 || revs[0].Blocks[1].URL != "http://b/1" || revs[0].Blocks[1].Size != 250 {
		t.Errorf("rev[0] block[1] mapping wrong: %+v", revs[0].Blocks[1])
	}
	if revs[1].State != RevisionStateObsolete {
		t.Errorf("rev[1] state: got %d, want %d", revs[1].State, RevisionStateObsolete)
	}
}

func TestAPIError(t *testing.T) {
	body := `{"Code":2501,"Error":"Invalid share","Details":"bad"}`
	srv, _ := recordingServer(t, http.StatusUnprocessableEntity, body)
	c := NewClient(srv.Client(), srv.URL)

	_, err := c.GetShare(context.Background(), "bad")
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("StatusCode: got %d, want %d", apiErr.StatusCode, http.StatusUnprocessableEntity)
	}
	if apiErr.Code != 2501 {
		t.Errorf("Code: got %d, want 2501", apiErr.Code)
	}
	if apiErr.Message != "Invalid share" {
		t.Errorf("Message: got %q, want %q", apiErr.Message, "Invalid share")
	}
}

func TestUserAgentHeader(t *testing.T) {
	srv, getReq := recordingServer(t, http.StatusOK, `{"Shares":[]}`)
	c := NewClient(srv.Client(), srv.URL, WithUserAgent("kiro-drive/2.0"))

	if _, err := c.ListShares(context.Background()); err != nil {
		t.Fatalf("ListShares: %v", err)
	}

	r := getReq()
	if r == nil {
		t.Fatal("no request recorded")
	}
	if got := r.Header.Get("User-Agent"); got != "kiro-drive/2.0" {
		t.Errorf("User-Agent: got %q, want %q", got, "kiro-drive/2.0")
	}
}

func TestCreateFile_NotWired(t *testing.T) {
	c := NewClient(http.DefaultClient, "https://api.example.com")

	_, err := c.CreateFile(context.Background(), "s1", CreateFileReq{
		Name:         "new.txt",
		MIMEType:     "text/plain",
		ParentLinkID: "p1",
	})
	if err == nil {
		t.Fatal("expected not-wired error, got nil")
	}
	if !strings.Contains(err.Error(), "not yet wired") {
		t.Errorf("expected 'not yet wired' error, got %v", err)
	}
}
