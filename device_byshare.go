package proton

import (
	"context"
	"fmt"
)

// DeviceV2 is the v2 device response structure returned by GET /drive/v2/devices.
type DeviceV2 struct {
	DeviceID   string `json:"DeviceID"`
	ShareID    string `json:"ShareID"`
	LinkID     string `json:"LinkID"`
	Type       int    `json:"Type"`
	CreateTime int64  `json:"CreateTime"`
	ModifyTime int64  `json:"ModifyTime"`
}

// GetDevicesByVolume lists devices via the v2 endpoint (GET /drive/v2/devices).
func (c *Client) GetDevicesByVolume(ctx context.Context) ([]DeviceV2, error) {
	resp, err := c.gen.ListV2DevicesWithResponse(ctx)
	if err != nil {
		return nil, fmt.Errorf("get devices by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return nil, fmt.Errorf("get devices by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	if resp.JSON200.Devices == nil {
		return nil, nil
	}

	d := resp.JSON200.Devices
	dev := DeviceV2{
		ShareID: derefString(d.ShareID),
		LinkID:  derefString(d.LinkID),
	}

	if d.Device != nil {
		dev.DeviceID = derefString(d.Device.DeviceID)
		if d.Device.Type != nil {
			dev.Type = int(*d.Device.Type)
		}
		if d.Device.CreateTime != nil {
			dev.CreateTime = int64(*d.Device.CreateTime)
		}
		if d.Device.ModifyTime != nil {
			dev.ModifyTime = int64(*d.Device.ModifyTime)
		}
	}

	return []DeviceV2{dev}, nil
}
