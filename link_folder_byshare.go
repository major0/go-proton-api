package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	driveapi "github.com/ProtonMail/go-proton-api/internal/openapi-client"
)

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
