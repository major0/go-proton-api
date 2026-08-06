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

func TestDeleteMultipleByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/delete_multiple")

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

	err := c.DeleteMultipleByVolume(context.Background(), "test-volume-id", []string{"link-id-1", "link-id-2"})
	require.NoError(t, err)
}

func TestDeleteMultipleByVolume_Error(t *testing.T) {
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

	err := c.DeleteMultipleByVolume(context.Background(), "vol-id", []string{"bad-link-id"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Link does not exist")
}

func TestTrashMultipleByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/trash_multiple")

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

	err := c.TrashMultipleByVolume(context.Background(), "test-volume-id", []string{"link-a", "link-b", "link-c"})
	require.NoError(t, err)
}

func TestTrashMultipleByVolume_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)

		resp := map[string]any{
			"Code":  2011,
			"Error": "Permission denied",
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

	err := c.TrashMultipleByVolume(context.Background(), "vol-id", []string{"link-x"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "Permission denied")
}

func TestSmallFileUploadByVolume_NotImplemented(t *testing.T) {
	err := (&proton.Client{}).SmallFileUploadByVolume(context.Background(), "vol-id")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not yet implemented")
}
