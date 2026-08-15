package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	driveapi "github.com/ProtonMail/go-proton-api/internal/openapi-client/drive"
)

// TrashCursor is the response from the v2 trash endpoint.
type TrashCursor struct {
	TrashedLinkIDs []string `json:"TrashedLinkIDs"`
}

// ListTrashByShare lists trashed items via the v1 share-scoped endpoint.
// Returns full Link objects.
func (c *Client) ListTrashByShare(ctx context.Context, shareID string, page, pageSize int) ([]Link, error) {
	pageStr := strconv.Itoa(page)
	pageSizeStr := strconv.Itoa(pageSize)

	params := &driveapi.DriveListSharesTrashParams{
		Page:     &pageStr,
		PageSize: &pageSizeStr,
	}

	httpResp, err := c.gen.DriveListSharesTrash(ctx, shareID, params)
	if err != nil {
		return nil, fmt.Errorf("listing trash by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return nil, fmt.Errorf("listing trash by share: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return nil, fmt.Errorf("listing trash by share: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed struct {
		Trash []Link
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("listing trash by share: parsing response: %w", err)
	}

	return parsed.Trash, nil
}

// ListTrashIDsByVolume lists trashed item IDs via the v2 volume-scoped endpoint.
func (c *Client) ListTrashIDsByVolume(ctx context.Context, volumeID string, page, pageSize int) (TrashCursor, error) {
	pageStr := strconv.Itoa(page)
	pageSizeStr := strconv.Itoa(pageSize)

	params := &driveapi.DriveListV2VolumesTrashParams{
		Page:     &pageStr,
		PageSize: &pageSizeStr,
	}

	httpResp, err := c.gen.DriveListV2VolumesTrash(ctx, volumeID, params)
	if err != nil {
		return TrashCursor{}, fmt.Errorf("listing trash IDs by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return TrashCursor{}, fmt.Errorf("listing trash IDs by volume: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return TrashCursor{}, fmt.Errorf("listing trash IDs by volume: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed TrashCursor
	if err := json.Unmarshal(body, &parsed); err != nil {
		return TrashCursor{}, fmt.Errorf("listing trash IDs by volume: parsing response: %w", err)
	}

	return parsed, nil
}
