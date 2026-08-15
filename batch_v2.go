package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// DeleteMultipleByVolume permanently deletes links via the v2 volume-scoped endpoint.
// This is distinct from TrashDeleteMultipleByVolume which deletes items already in trash.
// POST /drive/v2/volumes/{volumeId}/delete_multiple
func (c *Client) DeleteMultipleByVolume(ctx context.Context, volumeID string, linkIDs []string) error {
	req := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: linkIDs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("delete multiple by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.DriveCreateV2VolumesDeleteMultipleWithBodyWithResponse(ctx, volumeID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("delete multiple by volume: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("delete multiple by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// TrashMultipleByVolume moves links to trash via the v2 volume-scoped endpoint.
// This is distinct from TrashDeleteMultipleByVolume which permanently deletes from trash.
// POST /drive/v2/volumes/{volumeId}/trash_multiple
func (c *Client) TrashMultipleByVolume(ctx context.Context, volumeID string, linkIDs []string) error {
	req := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: linkIDs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("trash multiple by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.DriveCreateV2VolumesTrashMultipleWithBodyWithResponse(ctx, volumeID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("trash multiple by volume: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("trash multiple by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// SmallFileUploadByVolume uploads a small file via the v2 volume-scoped endpoint.
// POST /drive/v2/volumes/{volumeId}/files/small
//
// NOTE: The generated client method for this endpoint does not accept a request body,
// indicating the OpenAPI spec does not define the body schema (likely multipart/streaming).
// This is a placeholder until the spec is updated with proper body handling.
func (c *Client) SmallFileUploadByVolume(_ context.Context, _ string) error {
	return fmt.Errorf("SmallFileUploadByVolume: not yet implemented")
}
