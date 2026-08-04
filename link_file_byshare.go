package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	driveapi "github.com/ProtonMail/go-proton-api/internal/openapi-client"
)

// CreateFileByShare creates a file via the v1 share-scoped endpoint.
func (c *Client) CreateFileByShare(ctx context.Context, shareID string, req CreateFileReq) (CreateFileRes, error) {
	body := driveapi.CreateSharesFilesJSONRequestBody{
		ParentLinkID:              &req.ParentLinkID,
		Name:                      &req.Name,
		Hash:                      &req.Hash,
		MIMEType:                  &req.MIMEType,
		ContentKeyPacket:          &req.ContentKeyPacket,
		ContentKeyPacketSignature: &req.ContentKeyPacketSignature,
		NodeKey:                   &req.NodeKey,
		NodePassphrase:            &req.NodePassphrase,
		NodePassphraseSignature:   &req.NodePassphraseSignature,
		SignatureAddress:          &req.SignatureAddress,
	}

	resp, err := c.gen.CreateSharesFilesWithResponse(ctx, shareID, body)
	if err != nil {
		return CreateFileRes{}, fmt.Errorf("creating file by share: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateFileRes{}, fmt.Errorf("creating file by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	file := resp.JSON200.File
	if file == nil {
		return CreateFileRes{}, fmt.Errorf("creating file by share: response missing File field")
	}

	return CreateFileRes{
		ID:         derefString(file.ID),
		RevisionID: derefString(file.RevisionID),
	}, nil
}

// CreateFileByVolume creates a file via the v2 volume-scoped endpoint.
func (c *Client) CreateFileByVolume(ctx context.Context, volumeID string, req CreateFileReq) (CreateFileRes, error) {
	body := driveapi.CreateV2VolumesFilesJSONRequestBody{
		ParentLinkID:              &req.ParentLinkID,
		Name:                      &req.Name,
		Hash:                      &req.Hash,
		MIMEType:                  &req.MIMEType,
		ContentKeyPacket:          &req.ContentKeyPacket,
		ContentKeyPacketSignature: &req.ContentKeyPacketSignature,
		NodeKey:                   &req.NodeKey,
		NodePassphrase:            &req.NodePassphrase,
		NodePassphraseSignature:   &req.NodePassphraseSignature,
		SignatureAddress:          &req.SignatureAddress,
	}

	resp, err := c.gen.CreateV2VolumesFilesWithResponse(ctx, volumeID, body)
	if err != nil {
		return CreateFileRes{}, fmt.Errorf("creating file by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateFileRes{}, fmt.Errorf("creating file by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	file := resp.JSON200.File
	if file == nil {
		return CreateFileRes{}, fmt.Errorf("creating file by volume: response missing File field")
	}

	return CreateFileRes{
		ID:         derefString(file.ID),
		RevisionID: derefString(file.RevisionID),
	}, nil
}

// derefString safely dereferences a *string, returning "" if nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// CreateRevisionByShare creates a draft revision via the v1 share-scoped endpoint.
func (c *Client) CreateRevisionByShare(ctx context.Context, shareID, linkID string, req CreateRevisionReq) (CreateRevisionRes, error) {
	body := driveapi.CreateSharesFilesRevisionsJSONRequestBody{}
	if req.CurrentRevisionID != "" {
		body.CurrentRevisionID = &req.CurrentRevisionID
	}

	resp, err := c.gen.CreateSharesFilesRevisionsWithResponse(ctx, shareID, linkID, body)
	if err != nil {
		return CreateRevisionRes{}, fmt.Errorf("creating revision by share: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateRevisionRes{}, fmt.Errorf("creating revision by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	revision := resp.JSON200.Revision
	if revision == nil {
		return CreateRevisionRes{}, fmt.Errorf("creating revision by share: response missing Revision field")
	}

	return CreateRevisionRes{
		ID: derefString(revision.ID),
	}, nil
}

// CreateRevisionByVolume creates a draft revision via the v2 volume-scoped endpoint.
// ByVolume supports dirty-block-only writes via the same wire format.
func (c *Client) CreateRevisionByVolume(ctx context.Context, volumeID, linkID string, req CreateRevisionReq) (CreateRevisionRes, error) {
	body := driveapi.CreateV2VolumesFilesRevisionsJSONRequestBody{}
	if req.CurrentRevisionID != "" {
		body.CurrentRevisionID = &req.CurrentRevisionID
	}

	resp, err := c.gen.CreateV2VolumesFilesRevisionsWithResponse(ctx, volumeID, linkID, body)
	if err != nil {
		return CreateRevisionRes{}, fmt.Errorf("creating revision by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateRevisionRes{}, fmt.Errorf("creating revision by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	revision := resp.JSON200.Revision
	if revision == nil {
		return CreateRevisionRes{}, fmt.Errorf("creating revision by volume: response missing Revision field")
	}

	return CreateRevisionRes{
		ID: derefString(revision.ID),
	}, nil
}

// GetRevisionByShare fetches a specific revision via the v1 share-scoped endpoint.
func (c *Client) GetRevisionByShare(ctx context.Context, shareID, linkID, revisionID string, fromBlock, pageSize int) (Revision, error) {
	if fromBlock < 1 {
		return Revision{}, fmt.Errorf("getting revision by share: fromBlock must be greater than 0")
	}
	if pageSize < 1 {
		return Revision{}, fmt.Errorf("getting revision by share: pageSize must be greater than 0")
	}

	fromBlockStr := strconv.Itoa(fromBlock)
	pageSizeStr := strconv.Itoa(pageSize)

	params := &driveapi.GetSharesFilesRevisionParams{
		FromBlockIndex: &fromBlockStr,
		PageSize:       &pageSizeStr,
	}

	httpResp, err := c.gen.GetSharesFilesRevision(ctx, shareID, linkID, revisionID, params)
	if err != nil {
		return Revision{}, fmt.Errorf("getting revision by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return Revision{}, fmt.Errorf("getting revision by share: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return Revision{}, fmt.Errorf("getting revision by share: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Revision Revision
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Revision{}, fmt.Errorf("getting revision by share: parsing response: %w", err)
	}

	return parsed.Revision, nil
}

// GetRevisionByVolume fetches a specific revision via the v2 volume-scoped endpoint.
func (c *Client) GetRevisionByVolume(ctx context.Context, volumeID, linkID, revisionID string, fromBlock, pageSize int) (Revision, error) {
	if fromBlock < 1 {
		return Revision{}, fmt.Errorf("getting revision by volume: fromBlock must be greater than 0")
	}
	if pageSize < 1 {
		return Revision{}, fmt.Errorf("getting revision by volume: pageSize must be greater than 0")
	}

	fromBlockStr := strconv.Itoa(fromBlock)
	pageSizeStr := strconv.Itoa(pageSize)

	params := &driveapi.GetV2VolumesFilesRevisionParams{
		FromBlockIndex: &fromBlockStr,
		PageSize:       &pageSizeStr,
	}

	httpResp, err := c.gen.GetV2VolumesFilesRevision(ctx, volumeID, linkID, revisionID, params)
	if err != nil {
		return Revision{}, fmt.Errorf("getting revision by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return Revision{}, fmt.Errorf("getting revision by volume: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return Revision{}, fmt.Errorf("getting revision by volume: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Revision Revision
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return Revision{}, fmt.Errorf("getting revision by volume: parsing response: %w", err)
	}

	return parsed.Revision, nil
}

// DeleteRevisionByShare deletes a revision via the v1 share-scoped endpoint.
func (c *Client) DeleteRevisionByShare(ctx context.Context, shareID, linkID, revisionID string) error {
	httpResp, err := c.gen.DeleteSharesFilesRevision(ctx, shareID, linkID, revisionID)
	if err != nil {
		return fmt.Errorf("deleting revision by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode == 200 {
		return nil
	}

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("deleting revision by share: %w", err)
	}

	return fmt.Errorf("deleting revision by share: %w", apiErrorFromGenResponse(httpResp, body))
}

// DeleteRevisionByVolume deletes a revision via the v2 volume-scoped endpoint.
func (c *Client) DeleteRevisionByVolume(ctx context.Context, volumeID, linkID, revisionID string) error {
	httpResp, err := c.gen.DeleteV2VolumesFilesRevision(ctx, volumeID, linkID, revisionID)
	if err != nil {
		return fmt.Errorf("deleting revision by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode == 200 {
		return nil
	}

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("deleting revision by volume: %w", err)
	}

	return fmt.Errorf("deleting revision by volume: %w", apiErrorFromGenResponse(httpResp, body))
}

// UpdateRevisionByShare commits a revision via the v1 share-scoped endpoint.
func (c *Client) UpdateRevisionByShare(ctx context.Context, shareID, linkID, revisionID string, req UpdateRevisionReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("updating revision by share: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateSharesFilesRevisionWithBodyWithResponse(ctx, shareID, linkID, revisionID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("updating revision by share: %w", err)
	}

	if resp.JSON200 == nil {
		return fmt.Errorf("updating revision by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// UpdateRevisionByVolume commits a revision via the v2 volume-scoped endpoint.
// ByVolume supports dirty-block-only writes — BlockList can be nil/empty for COW.
func (c *Client) UpdateRevisionByVolume(ctx context.Context, volumeID, linkID, revisionID string, req UpdateRevisionReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("updating revision by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateV2VolumesFilesRevisionWithBodyWithResponse(ctx, volumeID, linkID, revisionID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("updating revision by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return fmt.Errorf("updating revision by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// RestoreRevisionByShare restores a revision via the v1 share-scoped endpoint.
func (c *Client) RestoreRevisionByShare(ctx context.Context, shareID, linkID, revisionID string) error {
	httpResp, err := c.gen.CreateSharesFilesRevisionsRestore(ctx, shareID, linkID, revisionID)
	if err != nil {
		return fmt.Errorf("restoring revision by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode == 200 || httpResp.StatusCode == 202 {
		return nil
	}

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("restoring revision by share: %w", err)
	}

	return fmt.Errorf("restoring revision by share: %w", apiErrorFromGenResponse(httpResp, body))
}

// RestoreRevisionByVolume restores a revision via the v2 volume-scoped endpoint.
func (c *Client) RestoreRevisionByVolume(ctx context.Context, volumeID, linkID, revisionID string) error {
	httpResp, err := c.gen.CreateV2VolumesFilesRevisionsRestore(ctx, volumeID, linkID, revisionID)
	if err != nil {
		return fmt.Errorf("restoring revision by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	if httpResp.StatusCode == 200 || httpResp.StatusCode == 202 {
		return nil
	}

	body, err := readBody(httpResp)
	if err != nil {
		return fmt.Errorf("restoring revision by volume: %w", err)
	}

	return fmt.Errorf("restoring revision by volume: %w", apiErrorFromGenResponse(httpResp, body))
}

// GetRevisionVerificationByShare fetches revision verification data via the v1 share-scoped endpoint.
func (c *Client) GetRevisionVerificationByShare(ctx context.Context, shareID, linkID, revisionID string) (RevisionVerification, error) {
	path := fmt.Sprintf("/drive/shares/%s/links/%s/revisions/%s/verification", shareID, linkID, revisionID)

	httpResp, err := c.doGenGet(ctx, path)
	if err != nil {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by share: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by share: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed RevisionVerification
	if err := json.Unmarshal(body, &parsed); err != nil {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by share: parsing response: %w", err)
	}

	return parsed, nil
}

// GetRevisionVerificationByVolume fetches revision verification data via the v2 volume-scoped endpoint.
func (c *Client) GetRevisionVerificationByVolume(ctx context.Context, volumeID, linkID, revisionID string) (RevisionVerification, error) {
	path := fmt.Sprintf("/drive/v2/volumes/%s/links/%s/revisions/%s/verification", volumeID, linkID, revisionID)

	httpResp, err := c.doGenGet(ctx, path)
	if err != nil {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by volume: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by volume: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed RevisionVerification
	if err := json.Unmarshal(body, &parsed); err != nil {
		return RevisionVerification{}, fmt.Errorf("getting revision verification by volume: parsing response: %w", err)
	}

	return parsed, nil
}

// doGenGet makes a GET request through the generated client's underlying HTTP client.
// This is used for endpoints that are not yet in the generated client.
func (c *Client) doGenGet(ctx context.Context, path string) (*http.Response, error) {
	baseURL := c.m.rc.BaseURL
	url := baseURL + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	return c.m.rc.GetClient().Do(req)
}
