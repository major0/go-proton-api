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

func TestListTrashByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/trash")
		require.Equal(t, "0", r.URL.Query().Get("Page"))
		require.Equal(t, "50", r.URL.Query().Get("PageSize"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
			"Trash": []map[string]any{
				{
					"LinkID":       "trashed-link-1",
					"ParentLinkID": "parent-1",
					"Type":         1,
					"Name":         "encrypted-trashed-file",
				},
				{
					"LinkID":       "trashed-link-2",
					"ParentLinkID": "parent-2",
					"Type":         2,
					"Name":         "encrypted-trashed-folder",
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

	links, err := c.ListTrashByShare(context.Background(), "test-share-id", 0, 50)
	require.NoError(t, err)
	require.Len(t, links, 2)
	require.Equal(t, "trashed-link-1", links[0].LinkID)
	require.Equal(t, "trashed-link-2", links[1].LinkID)
}

func TestListTrashIDsByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/trash")
		require.Equal(t, "0", r.URL.Query().Get("Page"))
		require.Equal(t, "100", r.URL.Query().Get("PageSize"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":           1000,
			"TrashedLinkIDs": []string{"id-1", "id-2", "id-3"},
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

	cursor, err := c.ListTrashIDsByVolume(context.Background(), "test-volume-id", 0, 100)
	require.NoError(t, err)
	require.Equal(t, []string{"id-1", "id-2", "id-3"}, cursor.TrashedLinkIDs)
}

func TestListTrashByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Share does not exist",
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

	_, err := c.ListTrashByShare(context.Background(), "bad-share-id", 0, 50)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Share does not exist")
}
