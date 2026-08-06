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

func TestGetMyFiles_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/drive/v2/shares/my-files", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":     1000,
			"VolumeID": "vol-main-123",
			"ShareID":  "share-main-456",
			"LinkID":   "link-root-789",
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

	info, err := c.GetMyFiles(context.Background())
	require.NoError(t, err)
	require.Equal(t, "vol-main-123", info.VolumeID)
	require.Equal(t, "share-main-456", info.ShareID)
	require.Equal(t, "link-root-789", info.LinkID)
}

func TestGetMyFiles_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "No main share found",
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

	_, err := c.GetMyFiles(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "No main share found")
}

func TestGetPhotosShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/drive/v2/shares/photos", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":     1000,
			"VolumeID": "vol-photos-111",
			"ShareID":  "share-photos-222",
			"LinkID":   "link-photos-333",
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

	info, err := c.GetPhotosShare(context.Background())
	require.NoError(t, err)
	require.Equal(t, "vol-photos-111", info.VolumeID)
	require.Equal(t, "share-photos-222", info.ShareID)
	require.Equal(t, "link-photos-333", info.LinkID)
}

func TestGetSharedWithMe_Success(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/sharedwithme")

		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if callCount == 1 {
			require.Empty(t, r.URL.Query().Get("AnchorID"))
			resp := map[string]any{
				"Code": 1000,
				"Shares": []map[string]any{
					{"ShareID": "shared-1", "VolumeID": "vol-1", "LinkID": "link-1"},
					{"ShareID": "shared-2", "VolumeID": "vol-2", "LinkID": "link-2"},
				},
				"AnchorID": "next-page-cursor",
				"More":     true,
			}
			require.NoError(t, json.NewEncoder(w).Encode(resp))
		} else {
			require.Equal(t, "next-page-cursor", r.URL.Query().Get("AnchorID"))
			resp := map[string]any{
				"Code": 1000,
				"Shares": []map[string]any{
					{"ShareID": "shared-3", "VolumeID": "vol-3", "LinkID": "link-3"},
				},
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
	cursor, err := c.GetSharedWithMe(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, cursor.Shares, 2)
	require.Equal(t, "shared-1", cursor.Shares[0].ShareID)
	require.Equal(t, "vol-1", cursor.Shares[0].VolumeID)
	require.Equal(t, "link-1", cursor.Shares[0].LinkID)
	require.Equal(t, "shared-2", cursor.Shares[1].ShareID)
	require.Equal(t, "next-page-cursor", cursor.AnchorID)
	require.True(t, cursor.More)

	// Second page using returned AnchorID.
	cursor, err = c.GetSharedWithMe(context.Background(), cursor.AnchorID)
	require.NoError(t, err)
	require.Len(t, cursor.Shares, 1)
	require.Equal(t, "shared-3", cursor.Shares[0].ShareID)
	require.Empty(t, cursor.AnchorID)
	require.False(t, cursor.More)

	require.Equal(t, 2, callCount)
}
