package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// MyFilesInfo is the bootstrap response for the user's main files share.
type MyFilesInfo struct {
	VolumeID string `json:"VolumeID"`
	ShareID  string `json:"ShareID"`
	LinkID   string `json:"LinkID"`
}

// PhotosShareInfo is the bootstrap response for the photos share.
type PhotosShareInfo struct {
	VolumeID string `json:"VolumeID"`
	ShareID  string `json:"ShareID"`
	LinkID   string `json:"LinkID"`
}

// SharedWithMeItem represents a share the user has access to.
type SharedWithMeItem struct {
	ShareID  string `json:"ShareID"`
	VolumeID string `json:"VolumeID"`
	LinkID   string `json:"LinkID"`
}

// SharedWithMeCursor is the cursor-paginated response from the shared-with-me endpoint.
type SharedWithMeCursor struct {
	Shares   []SharedWithMeItem `json:"Shares"`
	AnchorID string             `json:"AnchorID"`
	More     bool               `json:"More"`
}

// GetMyFiles returns bootstrap info for the user's main files share (v2 only).
func (c *Client) GetMyFiles(ctx context.Context) (MyFilesInfo, error) {
	httpResp, err := c.doGenGet(ctx, "/drive/v2/shares/my-files")
	if err != nil {
		return MyFilesInfo{}, fmt.Errorf("getting my-files bootstrap: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return MyFilesInfo{}, fmt.Errorf("getting my-files bootstrap: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return MyFilesInfo{}, fmt.Errorf("getting my-files bootstrap: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed MyFilesInfo
	if err := json.Unmarshal(body, &parsed); err != nil {
		return MyFilesInfo{}, fmt.Errorf("getting my-files bootstrap: parsing response: %w", err)
	}

	return parsed, nil
}

// GetPhotosShare returns bootstrap info for the photos share (v2 only).
func (c *Client) GetPhotosShare(ctx context.Context) (PhotosShareInfo, error) {
	httpResp, err := c.doGenGet(ctx, "/drive/v2/shares/photos")
	if err != nil {
		return PhotosShareInfo{}, fmt.Errorf("getting photos share bootstrap: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return PhotosShareInfo{}, fmt.Errorf("getting photos share bootstrap: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return PhotosShareInfo{}, fmt.Errorf("getting photos share bootstrap: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed PhotosShareInfo
	if err := json.Unmarshal(body, &parsed); err != nil {
		return PhotosShareInfo{}, fmt.Errorf("getting photos share bootstrap: parsing response: %w", err)
	}

	return parsed, nil
}

// GetSharedWithMe returns shares the user has access to (v2 only, paginated).
func (c *Client) GetSharedWithMe(ctx context.Context, anchorID string) (SharedWithMeCursor, error) {
	path := "/drive/v2/sharedwithme"
	if anchorID != "" {
		path += "?AnchorID=" + anchorID
	}

	httpResp, err := c.doGenGet(ctx, path)
	if err != nil {
		return SharedWithMeCursor{}, fmt.Errorf("getting shared-with-me: %w", err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	body, err := readBody(httpResp)
	if err != nil {
		return SharedWithMeCursor{}, fmt.Errorf("getting shared-with-me: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return SharedWithMeCursor{}, fmt.Errorf("getting shared-with-me: %w", apiErrorFromGenResponse(httpResp, body))
	}

	var parsed SharedWithMeCursor
	if err := json.Unmarshal(body, &parsed); err != nil {
		return SharedWithMeCursor{}, fmt.Errorf("getting shared-with-me: parsing response: %w", err)
	}

	return parsed, nil
}
