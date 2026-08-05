package proton_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProtonMail/go-proton-api"
	"github.com/stretchr/testify/require"
)

func TestRenameByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/links/link-id-1/rename")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "encrypted-new-name", body["Name"])
		require.Equal(t, "name-hash-123", body["Hash"])
		require.Equal(t, "application/pdf", body["MIMEType"])
		require.Equal(t, "user@proton.me", body["SignatureAddress"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.RenameReq{
		Name:             "encrypted-new-name",
		Hash:             "name-hash-123",
		MIMEType:         "application/pdf",
		SignatureAddress: "user@proton.me",
	}

	err := c.RenameByShare(context.Background(), "test-share-id", "link-id-1", req)
	require.NoError(t, err)
}

func TestRenameByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/links/link-id-2/rename")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "encrypted-name-v2", body["Name"])
		require.Equal(t, "hash-v2", body["Hash"])
		require.Equal(t, "user@proton.me", body["NameSignatureEmail"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.RenameReq{
		Name:               "encrypted-name-v2",
		Hash:               "hash-v2",
		NameSignatureEmail: "user@proton.me",
	}

	err := c.RenameByVolume(context.Background(), "test-volume-id", "link-id-2", req)
	require.NoError(t, err)
}

func TestRenameByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2500,
			"Error": "Name already exists",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.RenameReq{
		Name: "conflicting-name",
		Hash: "hash-conflict",
	}

	err := c.RenameByShare(context.Background(), "share-id", "link-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Name already exists")
}

func TestTrashDeleteMultipleByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/trash/delete_multiple")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		linkIDs, ok := body["LinkIDs"].([]any)
		require.True(t, ok)
		require.Len(t, linkIDs, 2)
		require.Equal(t, "link-id-1", linkIDs[0])
		require.Equal(t, "link-id-2", linkIDs[1])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.TrashDeleteMultipleByShare(context.Background(), "test-share-id", []string{"link-id-1", "link-id-2"})
	require.NoError(t, err)
}

func TestTrashDeleteMultipleByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/trash/delete_multiple")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		linkIDs, ok := body["LinkIDs"].([]any)
		require.True(t, ok)
		require.Len(t, linkIDs, 3)
		require.Equal(t, "link-a", linkIDs[0])
		require.Equal(t, "link-b", linkIDs[1])
		require.Equal(t, "link-c", linkIDs[2])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.TrashDeleteMultipleByVolume(context.Background(), "test-volume-id", []string{"link-a", "link-b", "link-c"})
	require.NoError(t, err)
}

func TestTrashDeleteMultipleByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2500,
			"Error": "Link does not exist",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.TrashDeleteMultipleByShare(context.Background(), "share-id", []string{"bad-link-id"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Link does not exist")
}

func TestTrashRestoreMultipleByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/trash/restore_multiple")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		linkIDs, ok := body["LinkIDs"].([]any)
		require.True(t, ok)
		require.Len(t, linkIDs, 2)
		require.Equal(t, "link-id-1", linkIDs[0])
		require.Equal(t, "link-id-2", linkIDs[1])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.TrashRestoreMultipleByShare(context.Background(), "test-share-id", []string{"link-id-1", "link-id-2"})
	require.NoError(t, err)
}

func TestTrashRestoreMultipleByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/trash/restore_multiple")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		linkIDs, ok := body["LinkIDs"].([]any)
		require.True(t, ok)
		require.Len(t, linkIDs, 3)
		require.Equal(t, "link-a", linkIDs[0])
		require.Equal(t, "link-b", linkIDs[1])
		require.Equal(t, "link-c", linkIDs[2])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.TrashRestoreMultipleByVolume(context.Background(), "test-volume-id", []string{"link-a", "link-b", "link-c"})
	require.NoError(t, err)
}

func TestTrashRestoreMultipleByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2500,
			"Error": "Link is not trashed",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.TrashRestoreMultipleByShare(context.Background(), "share-id", []string{"bad-link-id"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Link is not trashed")
}

func TestCreateDocumentByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/documents")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "parent-link-id", body["ParentLinkID"])
		require.Equal(t, "encrypted-doc-name", body["Name"])
		require.Equal(t, "doc-hash", body["Hash"])
		require.Equal(t, "1", body["DocumentType"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Document": map[string]any{
				"LinkID":     "doc-link-id-123",
				"RevisionID": "doc-revision-id-456",
				"VolumeID":   "vol-id-789",
			},
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.CreateDocumentReq{
		ParentLinkID:              "parent-link-id",
		Name:                      "encrypted-doc-name",
		Hash:                      "doc-hash",
		ContentKeyPacket:          "content-key-packet",
		ContentKeyPacketSignature: "cks",
		NodeKey:                   "node-key",
		NodePassphrase:            "node-passphrase",
		NodePassphraseSignature:   "nps",
		SignatureAddress:          "user@proton.me",
		ManifestSignature:         "manifest-sig",
		DocumentType:              "1",
	}

	res, err := c.CreateDocumentByShare(context.Background(), "test-share-id", req)
	require.NoError(t, err)
	require.Equal(t, "doc-link-id-123", res.LinkID)
	require.Equal(t, "doc-revision-id-456", res.RevisionID)
	require.Equal(t, "vol-id-789", res.VolumeID)
}

func TestCreateDocumentByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/documents")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "parent-link-id", body["ParentLinkID"])
		require.Equal(t, "encrypted-doc-name-v2", body["Name"])
		require.Equal(t, "doc-hash-v2", body["Hash"])
		require.Equal(t, "2", body["DocumentType"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Document": map[string]any{
				"LinkID":     "doc-link-id-v2",
				"RevisionID": "doc-revision-id-v2",
				"VolumeID":   "vol-id-v2",
			},
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.CreateDocumentReq{
		ParentLinkID:              "parent-link-id",
		Name:                      "encrypted-doc-name-v2",
		Hash:                      "doc-hash-v2",
		ContentKeyPacket:          "content-key-packet",
		ContentKeyPacketSignature: "cks",
		NodeKey:                   "node-key",
		NodePassphrase:            "node-passphrase",
		NodePassphraseSignature:   "nps",
		SignatureAddress:          "user@proton.me",
		ManifestSignature:         "manifest-sig-v2",
		DocumentType:              "2",
	}

	res, err := c.CreateDocumentByVolume(context.Background(), "test-volume-id", req)
	require.NoError(t, err)
	require.Equal(t, "doc-link-id-v2", res.LinkID)
	require.Equal(t, "doc-revision-id-v2", res.RevisionID)
	require.Equal(t, "vol-id-v2", res.VolumeID)
}

func TestCreateDocumentByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2001,
			"Error": "Invalid document name",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.CreateDocumentReq{
		ParentLinkID: "parent-link-id",
		Name:         "bad-name",
	}

	_, err := c.CreateDocumentByShare(context.Background(), "share-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid document name")
}

func TestPostLinksByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/links")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		linkIDs, ok := body["LinkIDs"].([]any)
		require.True(t, ok)
		require.Len(t, linkIDs, 2)
		require.Equal(t, "link-id-1", linkIDs[0])
		require.Equal(t, "link-id-2", linkIDs[1])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":  "1000",
			"Links": []string{"link-id-1", "link-id-2"},
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.PostLinksReq{
		LinkIDs: []string{"link-id-1", "link-id-2"},
	}

	res, err := c.PostLinksByVolume(context.Background(), "test-volume-id", req)
	require.NoError(t, err)
	require.Equal(t, []string{"link-id-1", "link-id-2"}, res.Links)
}

func TestPostLinksByVolume_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Link not found",
		}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	req := proton.PostLinksReq{
		LinkIDs: []string{"nonexistent-link"},
	}

	_, err := c.PostLinksByVolume(context.Background(), "vol-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Link not found")
}
