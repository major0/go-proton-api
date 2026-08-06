package proton

import (
	"context"
	"encoding/json"
	"fmt"

	driveapi "github.com/ProtonMail/go-proton-api/internal/openapi-client"
)

// SharesCursor is the cursor-paginated response from the v2 shares endpoint.
type SharesCursor struct {
	Shares   []ShareMetadata `json:"Shares"`
	Links    []Link          `json:"Links"`
	AnchorID string          `json:"AnchorID"`
	More     bool            `json:"More"`
}

// ListSharesByVolume lists shares via the v2 volume-scoped endpoint (cursor pagination).
func (c *Client) ListSharesByVolume(ctx context.Context, volumeID, anchorID string) (SharesCursor, error) {
	params := &driveapi.ListV2VolumesSharesParams{}
	if anchorID != "" {
		params.AnchorID = &anchorID
	}

	httpResp, err := c.gen.ListV2VolumesShares(ctx, volumeID, params)
	if err != nil {
		return SharesCursor{}, fmt.Errorf("listing shares by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return SharesCursor{}, fmt.Errorf("listing shares by volume: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return SharesCursor{}, fmt.Errorf("listing shares by volume: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed SharesCursor
	if err := json.Unmarshal(body, &parsed); err != nil {
		return SharesCursor{}, fmt.Errorf("listing shares by volume: parsing response: %w", err)
	}

	return parsed, nil
}
