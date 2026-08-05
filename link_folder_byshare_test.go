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

func TestListChildrenByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/test-share-id/folders/folder-link-id/children")
		require.Equal(t, "0", r.URL.Query().Get("Page"))
		require.Equal(t, "150", r.URL.Query().Get("PageSize"))
		require.Equal(t, "1", r.URL.Query().Get("ShowAll"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
			"Links": []map[string]any{
				{
					"LinkID":       "child-link-1",
					"ParentLinkID": "folder-link-id",
					"Type":         1,
					"Name":         "encrypted-name-1",
				},
				{
					"LinkID":       "child-link-2",
					"ParentLinkID": "folder-link-id",
					"Type":         2,
					"Name":         "encrypted-name-2",
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

	links, err := c.ListChildrenByShare(context.Background(), "test-share-id", "folder-link-id", 0, 150, true)
	require.NoError(t, err)
	require.Len(t, links, 2)
	require.Equal(t, "child-link-1", links[0].LinkID)
	require.Equal(t, "child-link-2", links[1].LinkID)
}

func TestListChildrenIDsByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/folders/folder-link-id/children")
		require.Empty(t, r.URL.Query().Get("AnchorID"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":     1000,
			"LinkIDs":  []string{"link-id-1", "link-id-2", "link-id-3"},
			"AnchorID": "cursor-abc",
			"More":     true,
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

	cursor, err := c.ListChildrenIDsByVolume(context.Background(), "test-volume-id", "folder-link-id", "")
	require.NoError(t, err)
	require.Equal(t, []string{"link-id-1", "link-id-2", "link-id-3"}, cursor.LinkIDs)
	require.Equal(t, "cursor-abc", cursor.AnchorID)
	require.True(t, cursor.More)
}

func TestListChildrenIDsByVolume_Pagination(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/vol-id/folders/folder-id/children")

		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if callCount == 1 {
			require.Empty(t, r.URL.Query().Get("AnchorID"))
			resp := map[string]any{
				"Code":     1000,
				"LinkIDs":  []string{"link-a", "link-b"},
				"AnchorID": "page-2-cursor",
				"More":     true,
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		} else {
			require.Equal(t, "page-2-cursor", r.URL.Query().Get("AnchorID"))
			resp := map[string]any{
				"Code":     1000,
				"LinkIDs":  []string{"link-c"},
				"AnchorID": "",
				"More":     false,
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		}
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	// First page.
	cursor, err := c.ListChildrenIDsByVolume(context.Background(), "vol-id", "folder-id", "")
	require.NoError(t, err)
	require.Equal(t, []string{"link-a", "link-b"}, cursor.LinkIDs)
	require.Equal(t, "page-2-cursor", cursor.AnchorID)
	require.True(t, cursor.More)

	// Second page using returned AnchorID.
	cursor, err = c.ListChildrenIDsByVolume(context.Background(), "vol-id", "folder-id", cursor.AnchorID)
	require.NoError(t, err)
	require.Equal(t, []string{"link-c"}, cursor.LinkIDs)
	require.Empty(t, cursor.AnchorID)
	require.False(t, cursor.More)

	require.Equal(t, 2, callCount)
}

func TestListChildrenByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Folder does not exist",
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

	_, err := c.ListChildrenByShare(context.Background(), "bad-share", "bad-folder", 0, 50, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Folder does not exist")
}
