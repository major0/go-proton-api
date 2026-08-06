package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateInvitation invites a user to a share (v2 only).
func (c *Client) CreateInvitation(ctx context.Context, shareID string, req CreateInvitationReq) (Invitation, error) {
	path := fmt.Sprintf("/drive/v2/shares/%s/invitations", shareID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPost, path, req)
	if err != nil {
		return Invitation{}, fmt.Errorf("creating invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return Invitation{}, fmt.Errorf("creating invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return Invitation{}, fmt.Errorf("creating invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Invitation Invitation `json:"Invitation"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Invitation{}, fmt.Errorf("creating invitation: parsing response: %w", err)
	}

	return parsed.Invitation, nil
}

// ListInvitations returns all pending invitations for the current user (v2 only).
func (c *Client) ListInvitations(ctx context.Context) ([]Invitation, error) {
	httpResp, err := c.doGenGet(ctx, "/drive/v2/shares/invitations")
	if err != nil {
		return nil, fmt.Errorf("listing invitations: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return nil, fmt.Errorf("listing invitations: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing invitations: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Invitations []Invitation `json:"Invitations"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("listing invitations: parsing response: %w", err)
	}

	return parsed.Invitations, nil
}

// GetInvitation fetches a single invitation by ID (v2 only).
func (c *Client) GetInvitation(ctx context.Context, invitationID string) (Invitation, error) {
	path := fmt.Sprintf("/drive/v2/shares/invitations/%s", invitationID)

	httpResp, err := c.doGenGet(ctx, path)
	if err != nil {
		return Invitation{}, fmt.Errorf("getting invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return Invitation{}, fmt.Errorf("getting invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return Invitation{}, fmt.Errorf("getting invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Invitation Invitation `json:"Invitation"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Invitation{}, fmt.Errorf("getting invitation: parsing response: %w", err)
	}

	return parsed.Invitation, nil
}

// UpdateInvitation updates an invitation's permissions (v2 only).
func (c *Client) UpdateInvitation(ctx context.Context, shareID, invitationID string, req UpdateInvitationReq) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/invitations/%s", shareID, invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPut, path, req)
	if err != nil {
		return fmt.Errorf("updating invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("updating invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("updating invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// DeleteInvitation revokes a pending invitation (v2 only).
func (c *Client) DeleteInvitation(ctx context.Context, shareID, invitationID string) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/invitations/%s", shareID, invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("deleting invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("deleting invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("deleting invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// AcceptInvitation accepts a pending share invitation (v2 only).
func (c *Client) AcceptInvitation(ctx context.Context, invitationID string) error {
	path := fmt.Sprintf("/drive/v2/shares/invitations/%s/accept", invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("accepting invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("accepting invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("accepting invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// RejectInvitation rejects a pending share invitation (v2 only).
func (c *Client) RejectInvitation(ctx context.Context, invitationID string) error {
	path := fmt.Sprintf("/drive/v2/shares/invitations/%s/reject", invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("rejecting invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("rejecting invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("rejecting invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// ResendInvitation resends a pending invitation email (v2 only).
func (c *Client) ResendInvitation(ctx context.Context, shareID, invitationID string) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/invitations/%s/sendemail", shareID, invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("resending invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("resending invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("resending invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// CreateExternalInvitation invites a non-Proton user to a share (v2 only).
func (c *Client) CreateExternalInvitation(ctx context.Context, shareID string, req CreateExternalInvitationReq) (ExternalInvitation, error) {
	path := fmt.Sprintf("/drive/v2/shares/%s/external-invitations", shareID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPost, path, req)
	if err != nil {
		return ExternalInvitation{}, fmt.Errorf("creating external invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return ExternalInvitation{}, fmt.Errorf("creating external invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return ExternalInvitation{}, fmt.Errorf("creating external invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Invitation ExternalInvitation `json:"Invitation"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ExternalInvitation{}, fmt.Errorf("creating external invitation: parsing response: %w", err)
	}

	return parsed.Invitation, nil
}

// UpdateExternalInvitation updates an external invitation's permissions (v2 only).
func (c *Client) UpdateExternalInvitation(ctx context.Context, shareID, invitationID string, req UpdateInvitationReq) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/external-invitations/%s", shareID, invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPut, path, req)
	if err != nil {
		return fmt.Errorf("updating external invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("updating external invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("updating external invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// DeleteExternalInvitation revokes a pending external invitation (v2 only).
func (c *Client) DeleteExternalInvitation(ctx context.Context, shareID, invitationID string) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/external-invitations/%s", shareID, invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("deleting external invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("deleting external invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("deleting external invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// ResendExternalInvitation resends an external invitation email (v2 only).
func (c *Client) ResendExternalInvitation(ctx context.Context, shareID, invitationID string) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/external-invitations/%s/sendemail", shareID, invitationID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPost, path, nil)
	if err != nil {
		return fmt.Errorf("resending external invitation: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("resending external invitation: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("resending external invitation: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// ListShareMembers returns all members of a share (v2 only).
func (c *Client) ListShareMembers(ctx context.Context, shareID string) ([]ShareMember, error) {
	path := fmt.Sprintf("/drive/v2/shares/%s/members", shareID)

	httpResp, err := c.doGenGet(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("listing share members: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return nil, fmt.Errorf("listing share members: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("listing share members: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Members []ShareMember `json:"Members"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("listing share members: parsing response: %w", err)
	}

	return parsed.Members, nil
}

// UpdateShareMember updates a member's permissions on a share (v2 only).
func (c *Client) UpdateShareMember(ctx context.Context, shareID, memberID string, req UpdateMemberReq) error {
	path := fmt.Sprintf("/drive/v2/shares/%s/members/%s", shareID, memberID)

	httpResp, err := c.doGenJSON(ctx, http.MethodPut, path, req)
	if err != nil {
		return fmt.Errorf("updating share member: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("updating share member: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("updating share member: %w", apiErrorFromGenResponse(httpResp, body))
	}

	return nil
}

// doGenJSON makes a JSON request through the underlying HTTP client.
// Used for v2 endpoints not yet in the generated client.
func (c *Client) doGenJSON(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	baseURL := c.m.rc.BaseURL
	url := baseURL + path

	var reqBody *bytes.Buffer
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshaling request body: %w", err)
		}
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	return c.m.rc.GetClient().Do(req)
}
