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

func TestGetDevicesByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/devices")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": "1000",
			"Devices": map[string]any{
				"Device": map[string]any{
					"DeviceID":   "device-id-123",
					"CreateTime": 1000000,
					"ModifyTime": 1000100,
					"Type":       1,
				},
				"ShareID": "share-id-abc",
				"LinkID":  "link-id-xyz",
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

	devices, err := c.GetDevicesByVolume(context.Background())
	require.NoError(t, err)
	require.Len(t, devices, 1)
	require.Equal(t, "device-id-123", devices[0].DeviceID)
	require.Equal(t, "share-id-abc", devices[0].ShareID)
	require.Equal(t, "link-id-xyz", devices[0].LinkID)
	require.Equal(t, 1, devices[0].Type)
	require.Equal(t, int64(1000000), devices[0].CreateTime)
	require.Equal(t, int64(1000100), devices[0].ModifyTime)
}

func TestGetDevicesByVolume_Error(t *testing.T) {
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

	_, err := c.GetDevicesByVolume(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "Permission denied")
}
