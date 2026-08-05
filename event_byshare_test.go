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

func TestGetEventByShare_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/shares/share-123/events/event-abc")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":    1000,
			"EventID": "event-next-456",
			"Events": []map[string]any{
				{
					"EventID":    "evt-1",
					"EventType":  1,
					"CreateTime": 1700000000,
					"Link": map[string]any{
						"LinkID":       "link-aaa",
						"ParentLinkID": "parent-link",
						"Type":         1,
						"Name":         "encrypted-name",
					},
				},
				{
					"EventID":   "evt-2",
					"EventType": 2,
					"Link": map[string]any{
						"LinkID":       "link-bbb",
						"ParentLinkID": "parent-link",
						"Type":         2,
						"Name":         "encrypted-name-2",
					},
				},
			},
			"More":    1,
			"Refresh": 0,
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

	event, err := c.GetEventByShare(context.Background(), "share-123", "event-abc")
	require.NoError(t, err)
	require.Equal(t, "event-next-456", event.EventID)
	require.Len(t, event.Events, 2)
	require.Equal(t, "evt-1", event.Events[0].EventID)
	require.Equal(t, proton.LinkEventCreate, event.Events[0].EventType)
	require.Equal(t, "link-aaa", event.Events[0].Link.LinkID)
	require.Equal(t, 1700000000, event.Events[0].CreateTime)
	require.Equal(t, "evt-2", event.Events[1].EventID)
	require.Equal(t, proton.LinkEventUpdate, event.Events[1].EventType)
	require.True(t, bool(event.More))
	require.False(t, bool(event.Refresh))
}

func TestGetEventByVolume_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Contains(t, r.URL.Path, "/drive/v2/volumes/vol-xyz/events/event-def")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code":    1000,
			"EventID": "event-next-789",
			"Events": []map[string]any{
				{
					"EventID":   "evt-v2-1",
					"EventType": 1,
					"Link": map[string]any{
						"LinkID":       "link-v2-aaa",
						"ParentLinkID": "parent-v2",
						"IsShared":     true,
						"IsTrashed":    false,
					},
				},
				{
					"EventID":   "evt-v2-2",
					"EventType": 0,
					"Link": map[string]any{
						"LinkID":       "link-v2-bbb",
						"ParentLinkID": "parent-v2-2",
						"IsShared":     false,
						"IsTrashed":    true,
					},
				},
			},
			"More":    true,
			"Refresh": false,
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

	event, err := c.GetEventByVolume(context.Background(), "vol-xyz", "event-def")
	require.NoError(t, err)
	require.Equal(t, "event-next-789", event.EventID)
	require.Len(t, event.Events, 2)

	// First event item.
	require.Equal(t, "evt-v2-1", event.Events[0].EventID)
	require.Equal(t, proton.LinkEventCreate, event.Events[0].EventType)
	require.Equal(t, "link-v2-aaa", event.Events[0].Link.LinkID)
	require.Equal(t, "parent-v2", event.Events[0].Link.ParentLinkID)
	require.True(t, event.Events[0].Link.IsShared)
	require.False(t, event.Events[0].Link.IsTrashed)

	// Second event item.
	require.Equal(t, "evt-v2-2", event.Events[1].EventID)
	require.Equal(t, proton.LinkEventDelete, event.Events[1].EventType)
	require.Equal(t, "link-v2-bbb", event.Events[1].Link.LinkID)
	require.Equal(t, "parent-v2-2", event.Events[1].Link.ParentLinkID)
	require.False(t, event.Events[1].Link.IsShared)
	require.True(t, event.Events[1].Link.IsTrashed)

	require.True(t, event.More)
	require.False(t, event.Refresh)
}

func TestGetEventByShare_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)

		resp := map[string]any{
			"Code":  2501,
			"Error": "Event does not exist",
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

	_, err := c.GetEventByShare(context.Background(), "bad-share", "bad-event")
	require.Error(t, err)
	require.Contains(t, err.Error(), "Event does not exist")
}
