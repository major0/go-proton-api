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

func TestListSharesByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/test-volume-id/shares")
		require.Empty(t, r.URL.Query().Get("AnchorID"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
			"Shares": []map[string]any{
				{"ShareID": "share-1", "LinkID": "link-1", "VolumeID": "test-volume-id", "Type": 1, "State": 1},
				{"ShareID": "share-2", "LinkID": "link-2", "VolumeID": "test-volume-id", "Type": 2, "State": 1},
			},
			"Links": []map[string]any{
				{"LinkID": "link-1", "ParentLinkID": "", "Type": 1},
				{"LinkID": "link-2", "ParentLinkID": "link-1", "Type": 2},
			},
			"AnchorID": "cursor-xyz",
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

	cursor, err := c.ListSharesByVolume(context.Background(), "test-volume-id", "")
	require.NoError(t, err)
	require.Len(t, cursor.Shares, 2)
	require.Equal(t, "share-1", cursor.Shares[0].ShareID)
	require.Equal(t, "share-2", cursor.Shares[1].ShareID)
	require.Len(t, cursor.Links, 2)
	require.Equal(t, "link-1", cursor.Links[0].LinkID)
	require.Equal(t, "link-2", cursor.Links[1].LinkID)
	require.Equal(t, "cursor-xyz", cursor.AnchorID)
	require.True(t, cursor.More)
}

func TestListSharesByVolume_Pagination(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/vol-id/shares")

		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if callCount == 1 {
			require.Empty(t, r.URL.Query().Get("AnchorID"))
			resp := map[string]any{
				"Code": 1000,
				"Shares": []map[string]any{
					{"ShareID": "share-a", "LinkID": "link-a", "VolumeID": "vol-id", "Type": 1, "State": 1},
				},
				"Links":    []map[string]any{},
				"AnchorID": "page-2-cursor",
				"More":     true,
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		} else {
			require.Equal(t, "page-2-cursor", r.URL.Query().Get("AnchorID"))
			resp := map[string]any{
				"Code": 1000,
				"Shares": []map[string]any{
					{"ShareID": "share-b", "LinkID": "link-b", "VolumeID": "vol-id", "Type": 2, "State": 1},
				},
				"Links":    []map[string]any{},
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
	cursor, err := c.ListSharesByVolume(context.Background(), "vol-id", "")
	require.NoError(t, err)
	require.Len(t, cursor.Shares, 1)
	require.Equal(t, "share-a", cursor.Shares[0].ShareID)
	require.Equal(t, "page-2-cursor", cursor.AnchorID)
	require.True(t, cursor.More)

	// Second page using returned AnchorID.
	cursor, err = c.ListSharesByVolume(context.Background(), "vol-id", cursor.AnchorID)
	require.NoError(t, err)
	require.Len(t, cursor.Shares, 1)
	require.Equal(t, "share-b", cursor.Shares[0].ShareID)
	require.Empty(t, cursor.AnchorID)
	require.False(t, cursor.More)

	require.Equal(t, 2, callCount)
}

func TestListSharesByVolume_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Volume does not exist",
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

	_, err := c.ListSharesByVolume(context.Background(), "bad-volume-id", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Volume does not exist")
}
