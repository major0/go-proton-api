package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	driveapi "github.com/ProtonMail/go-proton-api/internal/openapi-client/drive"
)

// CreateFolderByShare creates a folder via the v1 share-scoped endpoint.
func (c *Client) CreateFolderByShare(ctx context.Context, shareID string, req CreateFolderReq) (CreateFolderRes, error) {
	body := driveapi.CreateSharesFoldersJSONRequestBody{
		ParentLinkID:            &req.ParentLinkID,
		Name:                    &req.Name,
		Hash:                    &req.Hash,
		NodeKey:                 &req.NodeKey,
		NodeHashKey:             &req.NodeHashKey,
		NodePassphrase:          &req.NodePassphrase,
		NodePassphraseSignature: &req.NodePassphraseSignature,
		SignatureAddress:        &req.SignatureAddress,
	}

	resp, err := c.gen.CreateSharesFoldersWithResponse(ctx, shareID, body)
	if err != nil {
		return CreateFolderRes{}, fmt.Errorf("creating folder by share: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateFolderRes{}, fmt.Errorf("creating folder by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	folder := resp.JSON200.Folder
	if folder == nil {
		return CreateFolderRes{}, fmt.Errorf("creating folder by share: response missing Folder field")
	}

	return CreateFolderRes{
		ID: derefString(folder.ID),
	}, nil
}

// CreateFolderByVolume creates a folder via the v2 volume-scoped endpoint.
func (c *Client) CreateFolderByVolume(ctx context.Context, volumeID string, req CreateFolderByVolumeReq) (CreateFolderRes, error) {
	body := driveapi.CreateV2VolumesFoldersJSONRequestBody{
		ParentLinkID:            &req.ParentLinkID,
		Name:                    &req.Name,
		Hash:                    &req.Hash,
		NodeKey:                 &req.NodeKey,
		NodeHashKey:             &req.NodeHashKey,
		NodePassphrase:          &req.NodePassphrase,
		NodePassphraseSignature: &req.NodePassphraseSignature,
		SignatureEmail:          &req.SignatureEmail,
	}

	resp, err := c.gen.CreateV2VolumesFoldersWithResponse(ctx, volumeID, body)
	if err != nil {
		return CreateFolderRes{}, fmt.Errorf("creating folder by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateFolderRes{}, fmt.Errorf("creating folder by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	folder := resp.JSON200.Folder
	if folder == nil {
		return CreateFolderRes{}, fmt.Errorf("creating folder by volume: response missing Folder field")
	}

	return CreateFolderRes{
		ID: derefString(folder.ID),
	}, nil
}

// ChildrenCursor is the cursor-paginated response from the v2 children endpoint.
type ChildrenCursor struct {
	LinkIDs  []string `json:"LinkIDs"`
	AnchorID string   `json:"AnchorID"`
	More     bool     `json:"More"`
}

// ListChildrenByShare lists children via the v1 share-scoped endpoint (offset pagination, full Link objects).
func (c *Client) ListChildrenByShare(ctx context.Context, shareID, linkID string, page, pageSize int, showAll bool) ([]Link, error) {
	pageStr := strconv.Itoa(page)
	pageSizeStr := strconv.Itoa(pageSize)

	var showAllParam driveapi.ListSharesFoldersChildrenParamsShowAll
	if showAll {
		showAllParam = 1
	} else {
		showAllParam = 0
	}

	params := &driveapi.ListSharesFoldersChildrenParams{
		Page:     &pageStr,
		PageSize: &pageSizeStr,
		ShowAll:  &showAllParam,
	}

	httpResp, err := c.gen.ListSharesFoldersChildren(ctx, shareID, linkID, params)
	if err != nil {
		return nil, fmt.Errorf("listing children by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return nil, fmt.Errorf("listing children by share: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("listing children by share: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Links []Link
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("listing children by share: parsing response: %w", err)
	}

	return parsed.Links, nil
}

// ListChildrenIDsByVolume lists children via the v2 volume-scoped endpoint (cursor pagination, LinkIDs only).
func (c *Client) ListChildrenIDsByVolume(ctx context.Context, volumeID, linkID, anchorID string) (ChildrenCursor, error) {
	params := &driveapi.ListV2VolumesFoldersChildrenParams{}
	if anchorID != "" {
		params.AnchorID = &anchorID
	}

	httpResp, err := c.gen.ListV2VolumesFoldersChildren(ctx, volumeID, linkID, params)
	if err != nil {
		return ChildrenCursor{}, fmt.Errorf("listing children IDs by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return ChildrenCursor{}, fmt.Errorf("listing children IDs by volume: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return ChildrenCursor{}, fmt.Errorf("listing children IDs by volume: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed ChildrenCursor
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ChildrenCursor{}, fmt.Errorf("listing children IDs by volume: parsing response: %w", err)
	}

	return parsed, nil
}
