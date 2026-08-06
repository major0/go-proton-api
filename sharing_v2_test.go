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

func TestCreateInvitation_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/drive/v2/shares/share-abc/invitations", r.URL.Path)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "user@example.com", body["InviteeEmail"])
		require.Equal(t, float64(4), body["Permissions"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
			"Invitation": map[string]any{
				"InvitationID": "inv-123",
				"ShareID":      "share-abc",
				"InviterEmail": "owner@proton.me",
				"InviteeEmail": "user@example.com",
				"Permissions":  4,
				"State":        1,
				"CreateTime":   1700000000,
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

	inv, err := c.CreateInvitation(context.Background(), "share-abc", proton.CreateInvitationReq{
		InviteeEmail: "user@example.com",
		Permissions:  4,
	})
	require.NoError(t, err)
	require.Equal(t, "inv-123", inv.InvitationID)
	require.Equal(t, "share-abc", inv.ShareID)
	require.Equal(t, "owner@proton.me", inv.InviterEmail)
	require.Equal(t, "user@example.com", inv.InviteeEmail)
	require.Equal(t, 4, inv.Permissions)
	require.Equal(t, 1, inv.State)
	require.Equal(t, int64(1700000000), inv.CreateTime)
}

func TestListInvitations_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/drive/v2/shares/invitations", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
			"Invitations": []map[string]any{
				{
					"InvitationID": "inv-1",
					"ShareID":      "share-1",
					"InviterEmail": "owner@proton.me",
					"InviteeEmail": "user1@example.com",
					"Permissions":  4,
					"State":        1,
					"CreateTime":   1700000001,
				},
				{
					"InvitationID": "inv-2",
					"ShareID":      "share-2",
					"InviterEmail": "owner@proton.me",
					"InviteeEmail": "user2@example.com",
					"Permissions":  6,
					"State":        1,
					"CreateTime":   1700000002,
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

	invitations, err := c.ListInvitations(context.Background())
	require.NoError(t, err)
	require.Len(t, invitations, 2)
	require.Equal(t, "inv-1", invitations[0].InvitationID)
	require.Equal(t, 4, invitations[0].Permissions)
	require.Equal(t, "inv-2", invitations[1].InvitationID)
	require.Equal(t, 6, invitations[1].Permissions)
}

func TestAcceptInvitation_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/drive/v2/shares/invitations/inv-456/accept", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{"Code": 1000}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.AcceptInvitation(context.Background(), "inv-456")
	require.NoError(t, err)
}

func TestListShareMembers_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/drive/v2/shares/share-xyz/members", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{
			"Code": 1000,
			"Members": []map[string]any{
				{
					"MemberID":    "member-1",
					"ShareID":     "share-xyz",
					"Email":       "owner@proton.me",
					"Permissions": 22,
					"CreateTime":  1700000000,
				},
				{
					"MemberID":    "member-2",
					"ShareID":     "share-xyz",
					"Email":       "collaborator@proton.me",
					"Permissions": 6,
					"CreateTime":  1700000100,
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

	members, err := c.ListShareMembers(context.Background(), "share-xyz")
	require.NoError(t, err)
	require.Len(t, members, 2)
	require.Equal(t, "member-1", members[0].MemberID)
	require.Equal(t, 22, members[0].Permissions)
	require.Equal(t, "member-2", members[1].MemberID)
	require.Equal(t, 6, members[1].Permissions)
}

func TestUpdateShareMember_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPut, r.Method)
		require.Equal(t, "/drive/v2/shares/share-xyz/members/member-2", r.URL.Path)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, float64(4), body["Permissions"])

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{"Code": 1000}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.UpdateShareMember(context.Background(), "share-xyz", "member-2", proton.UpdateMemberReq{
		Permissions: 4,
	})
	require.NoError(t, err)
}

func TestDeleteInvitation_Success(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/drive/v2/shares/share-abc/invitations/inv-789", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		resp := map[string]any{"Code": 1000}
		require.NoError(t, json.NewEncoder(w).Encode(resp))
	}))
	defer ts.Close()

	m := proton.New(
		proton.WithHostURL(ts.URL),
		proton.WithRetryCount(0),
	)

	c := m.NewClient("", "", "")
	defer c.Close()

	err := c.DeleteInvitation(context.Background(), "share-abc", "inv-789")
	require.NoError(t, err)
}
