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

func TestMoveByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/links/link-id-1/move")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "encrypted-name", body["Name"])
		require.Equal(t, "name-hash", body["Hash"])
		require.Equal(t, "new-parent-link-id", body["ParentLinkID"])
		require.Equal(t, "target-share-id", body["NewShareID"])
		require.Equal(t, "node-passphrase-data", body["NodePassphrase"])
		require.Equal(t, "node-passphrase-sig", body["NodePassphraseSignature"])
		require.Equal(t, "user@proton.me", body["SignatureAddress"])
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

	req := proton.MoveByShareReq{
		Name:                    "encrypted-name",
		Hash:                    "name-hash",
		ParentLinkID:            "new-parent-link-id",
		NewShareID:              "target-share-id",
		NodePassphrase:          "node-passphrase-data",
		NodePassphraseSignature: "node-passphrase-sig",
		SignatureAddress:        "user@proton.me",
		NameSignatureEmail:      "user@proton.me",
	}

	err := c.MoveByShare(context.Background(), "test-share-id", "link-id-1", req)
	require.NoError(t, err)
}

func TestMoveByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/links/link-id-2/move")

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "encrypted-name-v2", body["Name"])
		require.Equal(t, "name-hash-v2", body["Hash"])
		require.Equal(t, "new-parent-link-id", body["ParentLinkID"])
		require.Equal(t, "node-passphrase-v2", body["NodePassphrase"])
		require.Equal(t, "node-passphrase-sig-v2", body["NodePassphraseSignature"])
		require.Equal(t, "user@proton.me", body["NameSignatureEmail"])

		// v2 must NOT have NewShareID or SignatureAddress
		_, hasNewShareID := body["NewShareID"]
		require.False(t, hasNewShareID, "v2 request must not include NewShareID")
		_, hasSignatureAddress := body["SignatureAddress"]
		require.False(t, hasSignatureAddress, "v2 request must not include SignatureAddress")

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

	req := proton.MoveByVolumeReq{
		Name:                    "encrypted-name-v2",
		Hash:                    "name-hash-v2",
		ParentLinkID:            "new-parent-link-id",
		NodePassphrase:          "node-passphrase-v2",
		NodePassphraseSignature: "node-passphrase-sig-v2",
		NameSignatureEmail:      "user@proton.me",
	}

	err := c.MoveByVolume(context.Background(), "test-volume-id", "link-id-2", req)
	require.NoError(t, err)
}

func TestMoveByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Invalid destination folder",
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

	req := proton.MoveByShareReq{
		Name:                    "encrypted-name",
		Hash:                    "hash",
		ParentLinkID:            "bad-parent",
		NodePassphrase:          "passphrase",
		NodePassphraseSignature: "sig",
	}

	err := c.MoveByShare(context.Background(), "share-id", "link-id", req)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Invalid destination folder")
}
