package proton

import (
	"context"
	"encoding/json"
	"fmt"
)

// GetEventByShare fetches a single page of drive events via the v1 share-scoped endpoint.
// The caller is responsible for pagination (looping while More == true).
func (c *Client) GetEventByShare(ctx context.Context, shareID, eventID string) (ShareEvent, error) {
	httpResp, err := c.gen.DriveGetSharesEvent(ctx, shareID, eventID)
	if err != nil {
		return ShareEvent{}, fmt.Errorf("getting event by share: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return ShareEvent{}, fmt.Errorf("getting event by share: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return ShareEvent{}, fmt.Errorf("getting event by share: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed ShareEvent
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ShareEvent{}, fmt.Errorf("getting event by share: parsing response: %w", err)
	}

	return parsed, nil
}

// GetEventByVolume fetches a single page of drive events via the v2 volume-scoped endpoint.
// The caller is responsible for pagination (looping while More == true).
func (c *Client) GetEventByVolume(ctx context.Context, volumeID, eventID string) (VolumeEvent, error) {
	httpResp, err := c.gen.DriveGetV2VolumesEvent(ctx, volumeID, eventID)
	if err != nil {
		return VolumeEvent{}, fmt.Errorf("getting event by volume: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return VolumeEvent{}, fmt.Errorf("getting event by volume: %w", err)
	}

	if httpResp.StatusCode != 200 {
		return VolumeEvent{}, fmt.Errorf("getting event by volume: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed VolumeEvent
	if err := json.Unmarshal(body, &parsed); err != nil {
		return VolumeEvent{}, fmt.Errorf("getting event by volume: parsing response: %w", err)
	}

	return parsed, nil
}
