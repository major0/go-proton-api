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

func TestCreateFileByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/files")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"File": map[string]any{
				"ID":         "link-id-123",
				"RevisionID": "revision-id-456",
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

	req := proton.CreateFileReq{
		ParentLinkID:              "parent-link-id",
		Name:                      "encrypted-name",
		Hash:                      "hash-value",
		MIMEType:                  "application/octet-stream",
		ContentKeyPacket:          "content-key-packet",
		ContentKeyPacketSignature: "cks",
		NodeKey:                   "node-key",
		NodePassphrase:            "node-passphrase",
		NodePassphraseSignature:   "nps",
		SignatureAddress:          "user@proton.me",
	}

	res, err := c.CreateFileByShare(context.Background(), "test-share-id", req)
	require.NoError(t, err)
	require.Equal(t, "link-id-123", res.ID)
	require.Equal(t, "revision-id-456", res.RevisionID)
}

func TestCreateFileByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"File": map[string]any{
				"ID":         "link-id-789",
				"RevisionID": "revision-id-012",
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

	req := proton.CreateFileReq{
		ParentLinkID:              "parent-link-id",
		Name:                      "encrypted-name",
		Hash:                      "hash-value",
		MIMEType:                  "image/png",
		ContentKeyPacket:          "content-key-packet",
		ContentKeyPacketSignature: "cks",
		NodeKey:                   "node-key",
		NodePassphrase:            "node-passphrase",
		NodePassphraseSignature:   "nps",
		SignatureAddress:          "user@proton.me",
	}

	res, err := c.CreateFileByVolume(context.Background(), "test-volume-id", req)
	require.NoError(t, err)
	require.Equal(t, "link-id-789", res.ID)
	require.Equal(t, "revision-id-012", res.RevisionID)
}

func TestCreateFileByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2001,
			"Error": "Invalid file name",
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

	req := proton.CreateFileReq{
		ParentLinkID: "parent-link-id",
		Name:         "bad-name",
	}

	_, err := c.CreateFileByShare(context.Background(), "share-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid file name")
}

func TestCreateFileByVolume_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2001,
			"Error": "Invalid file name",
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

	req := proton.CreateFileReq{
		ParentLinkID: "parent-link-id",
		Name:         "bad-name",
	}

	_, err := c.CreateFileByVolume(context.Background(), "volume-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid file name")
}

func TestGetRevisionByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/files/link-id/revisions/rev-id")
		require.Equal(t, "1", r.URL.Query().Get("FromBlockIndex"))
		require.Equal(t, "50", r.URL.Query().Get("PageSize"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Revision": map[string]any{
				"ID":                "rev-id",
				"CreateTime":        1700000000,
				"Size":              4096,
				"ManifestSignature": "manifest-sig",
				"SignatureEmail":    "user@proton.me",
				"State":             1,
				"Thumbnail":         0,
				"ThumbnailHash":     "",
				"Blocks": []map[string]any{
					{
						"Index":          1,
						"BareURL":        "https://block1.example.com",
						"Token":          "token-1",
						"Hash":           "hash-1",
						"EncSignature":   "enc-sig-1",
						"SignatureEmail": "user@proton.me",
					},
					{
						"Index":          2,
						"BareURL":        "https://block2.example.com",
						"Token":          "token-2",
						"Hash":           "hash-2",
						"EncSignature":   "enc-sig-2",
						"SignatureEmail": "user@proton.me",
					},
				},
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

	rev, err := c.GetRevisionByShare(context.Background(), "test-share-id", "link-id", "rev-id", 1, 50)
	require.NoError(t, err)
	require.Equal(t, "rev-id", rev.ID)
	require.Equal(t, int64(1700000000), rev.CreateTime)
	require.Equal(t, int64(4096), rev.Size)
	require.Equal(t, "manifest-sig", rev.ManifestSignature)
	require.Equal(t, "user@proton.me", rev.SignatureEmail)
	require.Equal(t, proton.RevisionStateActive, rev.State)
	require.Len(t, rev.Blocks, 2)
	require.Equal(t, 1, rev.Blocks[0].Index)
	require.Equal(t, "https://block1.example.com", rev.Blocks[0].BareURL)
	require.Equal(t, "token-1", rev.Blocks[0].Token)
	require.Equal(t, "hash-1", rev.Blocks[0].Hash)
	require.Equal(t, "enc-sig-1", rev.Blocks[0].EncSignature)
	require.Equal(t, 2, rev.Blocks[1].Index)
	require.Equal(t, "https://block2.example.com", rev.Blocks[1].BareURL)
}

func TestGetRevisionByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files/link-id/revisions/rev-id")
		require.Equal(t, "1", r.URL.Query().Get("FromBlockIndex"))
		require.Equal(t, "10", r.URL.Query().Get("PageSize"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Revision": map[string]any{
				"ID":                "rev-id",
				"CreateTime":        1700000000,
				"Size":              8192,
				"ManifestSignature": "manifest-sig-v2",
				"SignatureEmail":    "user@proton.me",
				"State":             1,
				"Thumbnail":         0,
				"ThumbnailHash":     "",
				"Blocks": []map[string]any{
					{
						"Index":          1,
						"BareURL":        "https://block1-v2.example.com",
						"Token":          "token-v2-1",
						"Hash":           "hash-v2-1",
						"EncSignature":   "enc-sig-v2-1",
						"SignatureEmail": "user@proton.me",
					},
				},
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

	rev, err := c.GetRevisionByVolume(context.Background(), "test-volume-id", "link-id", "rev-id", 1, 10)
	require.NoError(t, err)
	require.Equal(t, "rev-id", rev.ID)
	require.Equal(t, int64(8192), rev.Size)
	require.Equal(t, "manifest-sig-v2", rev.ManifestSignature)
	require.Len(t, rev.Blocks, 1)
	require.Equal(t, "https://block1-v2.example.com", rev.Blocks[0].BareURL)
	require.Equal(t, "token-v2-1", rev.Blocks[0].Token)
}

func TestGetRevisionByShare_ValidationErrors(t *testing.T) {
	m := proton.New(
		proton.WithHostURL("http://localhost"),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	_, err := c.GetRevisionByShare(context.Background(), "share-id", "link-id", "rev-id", 0, 50)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fromBlock must be greater than 0")

	_, err = c.GetRevisionByShare(context.Background(), "share-id", "link-id", "rev-id", 1, 0)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pageSize must be greater than 0")
}

func TestGetRevisionByVolume_ValidationErrors(t *testing.T) {
	m := proton.New(
		proton.WithHostURL("http://localhost"),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	_, err := c.GetRevisionByVolume(context.Background(), "volume-id", "link-id", "rev-id", -1, 50)
	require.Error(t, err)
	require.Contains(t, err.Error(), "fromBlock must be greater than 0")

	_, err = c.GetRevisionByVolume(context.Background(), "volume-id", "link-id", "rev-id", 1, -5)
	require.Error(t, err)
	require.Contains(t, err.Error(), "pageSize must be greater than 0")
}

func TestGetRevisionByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Revision not found",
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

	_, err := c.GetRevisionByShare(context.Background(), "share-id", "link-id", "rev-id", 1, 50)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Revision not found")
}

func TestGetRevisionByVolume_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Revision not found",
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

	_, err := c.GetRevisionByVolume(context.Background(), "volume-id", "link-id", "rev-id", 1, 50)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Revision not found")
}

func TestCreateRevisionByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/files/link-id-1/revisions")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Revision": map[string]any{
				"ID": "new-revision-id",
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

	res, err := c.CreateRevisionByShare(context.Background(), "test-share-id", "link-id-1", proton.CreateRevisionReq{})
	require.NoError(t, err)
	require.Equal(t, "new-revision-id", res.ID)
}

func TestCreateRevisionByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files/link-id-2/revisions")

		// Verify CurrentRevisionID is sent in the body.
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "prev-rev-id", body["CurrentRevisionID"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Revision": map[string]any{
				"ID": "new-revision-v2",
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

	req := proton.CreateRevisionReq{
		CurrentRevisionID: "prev-rev-id",
	}

	res, err := c.CreateRevisionByVolume(context.Background(), "test-volume-id", "link-id-2", req)
	require.NoError(t, err)
	require.Equal(t, "new-revision-v2", res.ID)
}

func TestCreateRevisionByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)

		resp := map[string]any{
			"Code":  2500,
			"Error": "Active revision already exists",
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

	_, err := c.CreateRevisionByShare(context.Background(), "share-id", "link-id", proton.CreateRevisionReq{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Active revision already exists")
}

func TestUpdateRevisionByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/files/link-id/revisions/rev-id")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, float64(1), body["State"])
		require.Equal(t, "manifest-sig", body["ManifestSignature"])
		require.Equal(t, "user@proton.me", body["SignatureAddress"])

		blockList := body["BlockList"].([]any)
		require.Len(t, blockList, 2)

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

	req := proton.UpdateRevisionReq{
		BlockList: []proton.BlockToken{
			{Index: 1, Token: "token-1"},
			{Index: 2, Token: "token-2"},
		},
		State:             proton.RevisionStateActive,
		ManifestSignature: "manifest-sig",
		SignatureAddress:   "user@proton.me",
	}

	err := c.UpdateRevisionByShare(context.Background(), "test-share-id", "link-id", "rev-id", req)
	require.NoError(t, err)
}

func TestUpdateRevisionByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files/link-id/revisions/rev-id")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, float64(1), body["State"])
		require.Equal(t, "manifest-sig-v2", body["ManifestSignature"])

		blockList := body["BlockList"].([]any)
		require.Len(t, blockList, 1)

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

	req := proton.UpdateRevisionReq{
		BlockList: []proton.BlockToken{
			{Index: 1, Token: "block-token-1"},
		},
		State:             proton.RevisionStateActive,
		ManifestSignature: "manifest-sig-v2",
		SignatureAddress:   "user@proton.me",
	}

	err := c.UpdateRevisionByVolume(context.Background(), "test-volume-id", "link-id", "rev-id", req)
	require.NoError(t, err)
}

func TestUpdateRevisionByVolume_COW(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files/link-id/revisions/rev-id")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, float64(1), body["State"])

		// BlockList should be null for COW — nil slices marshal as null.
		require.Nil(t, body["BlockList"], "BlockList should be null for COW")

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

	req := proton.UpdateRevisionReq{
		BlockList:         nil, // COW: no blocks, server uses inherited blocks.
		State:             proton.RevisionStateActive,
		ManifestSignature: "manifest-sig-cow",
		SignatureAddress:   "user@proton.me",
	}

	err := c.UpdateRevisionByVolume(context.Background(), "test-volume-id", "link-id", "rev-id", req)
	require.NoError(t, err)
}

func TestUpdateRevisionByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)

		resp := map[string]any{
			"Code":  2500,
			"Error": "Revision state conflict",
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

	req := proton.UpdateRevisionReq{
		BlockList: []proton.BlockToken{
			{Index: 1, Token: "token-1"},
		},
		State:             proton.RevisionStateActive,
		ManifestSignature: "manifest-sig",
		SignatureAddress:   "user@proton.me",
	}

	err := c.UpdateRevisionByShare(context.Background(), "share-id", "link-id", "rev-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Revision state conflict")
}

func TestDeleteRevisionByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/files/link-id/revisions/rev-id")

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

	err := c.DeleteRevisionByShare(context.Background(), "test-share-id", "link-id", "rev-id")
	require.NoError(t, err)
}

func TestDeleteRevisionByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files/link-id/revisions/rev-id")

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

	err := c.DeleteRevisionByVolume(context.Background(), "test-volume-id", "link-id", "rev-id")
	require.NoError(t, err)
}

func TestDeleteRevisionByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Revision not found",
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

	err := c.DeleteRevisionByShare(context.Background(), "test-share-id", "link-id", "rev-id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Revision not found")
}

func TestRestoreRevisionByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/files/link-id/revisions/rev-id/restore")

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

	err := c.RestoreRevisionByShare(context.Background(), "test-share-id", "link-id", "rev-id")
	require.NoError(t, err)
}

func TestRestoreRevisionByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/files/link-id/revisions/rev-id/restore")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)

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

	err := c.RestoreRevisionByVolume(context.Background(), "test-volume-id", "link-id", "rev-id")
	require.NoError(t, err)
}

func TestRestoreRevisionByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Revision not found",
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

	err := c.RestoreRevisionByShare(context.Background(), "test-share-id", "link-id", "rev-id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Revision not found")
}

func TestGetRevisionVerificationByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/links/link-id/revisions/rev-id/verification")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":             1000,
			"VerificationCode": "verification-code-abc",
			"ContentKeyPacket": "content-key-packet-xyz",
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

	v, err := c.GetRevisionVerificationByShare(context.Background(), "test-share-id", "link-id", "rev-id")
	require.NoError(t, err)
	require.Equal(t, "verification-code-abc", v.VerificationCode)
	require.Equal(t, "content-key-packet-xyz", v.ContentKeyPacket)
}

func TestGetRevisionVerificationByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/links/link-id/revisions/rev-id/verification")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":             1000,
			"VerificationCode": "verification-code-v2",
			"ContentKeyPacket": "content-key-packet-v2",
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

	v, err := c.GetRevisionVerificationByVolume(context.Background(), "test-volume-id", "link-id", "rev-id")
	require.NoError(t, err)
	require.Equal(t, "verification-code-v2", v.VerificationCode)
	require.Equal(t, "content-key-packet-v2", v.ContentKeyPacket)
}

func TestGetRevisionVerificationByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Revision not found",
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

	_, err := c.GetRevisionVerificationByShare(context.Background(), "share-id", "link-id", "rev-id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Revision not found")
}
