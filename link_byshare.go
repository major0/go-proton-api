package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	driveapi "github.com/ProtonMail/go-proton-api/internal/openapi-client"
)

// PostLinksReq is the request body for batch-fetching link metadata.
type PostLinksReq struct {
	LinkIDs []string `json:"LinkIDs"`
}

// PostLinksRes is the response from batch-fetching link metadata.
type PostLinksRes struct {
	Links []string // Link IDs returned by the server.
}

// PostLinksByVolume creates/fetches links via the v2 volume-scoped endpoint.
// In v1 this was under /drive/photos/volumes/{volumeId}/links; in v2 it is
// generalized to /drive/v2/volumes/{volumeId}/links.
func (c *Client) PostLinksByVolume(ctx context.Context, volumeID string, req PostLinksReq) (PostLinksRes, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return PostLinksRes{}, fmt.Errorf("post links by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.CreateV2VolumesLinksWithBodyWithResponse(ctx, volumeID, "application/json", bytes.NewReader(body))
	if err != nil {
		return PostLinksRes{}, fmt.Errorf("post links by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return PostLinksRes{}, fmt.Errorf("post links by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	var links []string
	if resp.JSON200.Links != nil {
		links = *resp.JSON200.Links
	}

	return PostLinksRes{Links: links}, nil
}

// RenameReq is the request body for renaming a link.
type RenameReq struct {
	Name               string `json:"Name"`
	Hash               string `json:"Hash,omitempty"`
	MIMEType           string `json:"MIMEType,omitempty"`
	SignatureAddress   string `json:"SignatureAddress,omitempty"`
	NameSignatureEmail string `json:"NameSignatureEmail,omitempty"`
	OriginalHash       string `json:"OriginalHash,omitempty"`
}

// RenameByShare renames a link via the v1 share-scoped endpoint.
func (c *Client) RenameByShare(ctx context.Context, shareID, linkID string, req RenameReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("renaming by share: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateSharesLinksRenameWithBodyWithResponse(ctx, shareID, linkID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("renaming by share: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("renaming by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// RenameByVolume renames a link via the v2 volume-scoped endpoint.
func (c *Client) RenameByVolume(ctx context.Context, volumeID, linkID string, req RenameReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("renaming by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateV2VolumesLinksRenameWithBodyWithResponse(ctx, volumeID, linkID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("renaming by volume: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("renaming by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// TrashDeleteMultipleByShare permanently deletes trashed items via the v1 share-scoped endpoint.
func (c *Client) TrashDeleteMultipleByShare(ctx context.Context, shareID string, linkIDs []string) error {
	req := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: linkIDs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("trash delete multiple by share: marshaling request: %w", err)
	}

	resp, err := c.gen.CreateSharesTrashDeleteMultipleWithBodyWithResponse(ctx, shareID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("trash delete multiple by share: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("trash delete multiple by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// TrashDeleteMultipleByVolume permanently deletes trashed items via the v2 volume-scoped endpoint.
func (c *Client) TrashDeleteMultipleByVolume(ctx context.Context, volumeID string, linkIDs []string) error {
	req := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: linkIDs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("trash delete multiple by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.CreateV2VolumesTrashDeleteMultipleWithBodyWithResponse(ctx, volumeID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("trash delete multiple by volume: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("trash delete multiple by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// TrashRestoreMultipleByShare restores trashed items via the v1 share-scoped endpoint.
func (c *Client) TrashRestoreMultipleByShare(ctx context.Context, shareID string, linkIDs []string) error {
	req := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: linkIDs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("trash restore multiple by share: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateSharesTrashRestoreMultipleWithBodyWithResponse(ctx, shareID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("trash restore multiple by share: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("trash restore multiple by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// TrashRestoreMultipleByVolume restores trashed items via the v2 volume-scoped endpoint.
func (c *Client) TrashRestoreMultipleByVolume(ctx context.Context, volumeID string, linkIDs []string) error {
	req := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: linkIDs,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("trash restore multiple by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateV2VolumesTrashRestoreMultipleWithBodyWithResponse(ctx, volumeID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("trash restore multiple by volume: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("trash restore multiple by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// CreateDocumentByShare creates a document via the v1 share-scoped endpoint.
func (c *Client) CreateDocumentByShare(ctx context.Context, shareID string, req CreateDocumentReq) (CreateDocumentRes, error) {
	body := driveapi.CreateSharesDocumentsJSONRequestBody{
		ParentLinkID:              &req.ParentLinkID,
		Name:                      &req.Name,
		Hash:                      &req.Hash,
		ContentKeyPacket:          &req.ContentKeyPacket,
		ContentKeyPacketSignature: &req.ContentKeyPacketSignature,
		NodeKey:                   &req.NodeKey,
		NodePassphrase:            &req.NodePassphrase,
		NodePassphraseSignature:   &req.NodePassphraseSignature,
		SignatureAddress:          &req.SignatureAddress,
		ManifestSignature:         &req.ManifestSignature,
		DocumentType:              &req.DocumentType,
	}

	resp, err := c.gen.CreateSharesDocumentsWithResponse(ctx, shareID, body)
	if err != nil {
		return CreateDocumentRes{}, fmt.Errorf("creating document by share: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateDocumentRes{}, fmt.Errorf("creating document by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	doc := resp.JSON200.Document
	if doc == nil {
		return CreateDocumentRes{}, fmt.Errorf("creating document by share: response missing Document field")
	}

	return CreateDocumentRes{
		LinkID:     derefString(doc.LinkID),
		RevisionID: derefString(doc.RevisionID),
		VolumeID:   derefString(doc.VolumeID),
	}, nil
}

// CreateDocumentByVolume creates a document via the v2 volume-scoped endpoint.
func (c *Client) CreateDocumentByVolume(ctx context.Context, volumeID string, req CreateDocumentReq) (CreateDocumentRes, error) {
	body := driveapi.CreateV2VolumesDocumentsJSONRequestBody{
		ParentLinkID:              &req.ParentLinkID,
		Name:                      &req.Name,
		Hash:                      &req.Hash,
		ContentKeyPacket:          &req.ContentKeyPacket,
		ContentKeyPacketSignature: &req.ContentKeyPacketSignature,
		NodeKey:                   &req.NodeKey,
		NodePassphrase:            &req.NodePassphrase,
		NodePassphraseSignature:   &req.NodePassphraseSignature,
		SignatureAddress:          &req.SignatureAddress,
		ManifestSignature:         &req.ManifestSignature,
		DocumentType:              &req.DocumentType,
	}

	resp, err := c.gen.CreateV2VolumesDocumentsWithResponse(ctx, volumeID, body)
	if err != nil {
		return CreateDocumentRes{}, fmt.Errorf("creating document by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return CreateDocumentRes{}, fmt.Errorf("creating document by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	doc := resp.JSON200.Document
	if doc == nil {
		return CreateDocumentRes{}, fmt.Errorf("creating document by volume: response missing Document field")
	}

	return CreateDocumentRes{
		LinkID:     derefString(doc.LinkID),
		RevisionID: derefString(doc.RevisionID),
		VolumeID:   derefString(doc.VolumeID),
	}, nil
}

// CheckAvailableHashesByShareReq is the v1 request (ClientUID only).
type CheckAvailableHashesByShareReq struct {
	ClientUID string `json:"ClientUID,omitempty"`
}

// CheckAvailableHashesByVolumeReq is the v2 request (includes required Hashes field).
type CheckAvailableHashesByVolumeReq struct {
	Hashes    []string `json:"Hashes"`
	ClientUID string   `json:"ClientUID,omitempty"`
}

// CheckAvailableHashesRes is the response for both v1 and v2.
type CheckAvailableHashesRes struct {
	AvailableHashes []string `json:"AvailableHashes"`
}

// CheckAvailableHashesByShare checks available hashes via the v1 share-scoped endpoint.
func (c *Client) CheckAvailableHashesByShare(ctx context.Context, shareID, linkID string, req CheckAvailableHashesByShareReq) (CheckAvailableHashesRes, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CheckAvailableHashesRes{}, fmt.Errorf("check available hashes by share: marshaling request: %w", err)
	}

	resp, err := c.gen.CreateSharesLinksCheckavailablehashesWithBodyWithResponse(ctx, shareID, linkID, "application/json", bytes.NewReader(body))
	if err != nil {
		return CheckAvailableHashesRes{}, fmt.Errorf("check available hashes by share: %w", err)
	}

	if resp.JSON200 == nil {
		return CheckAvailableHashesRes{}, fmt.Errorf("check available hashes by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	var hashes []string
	if resp.JSON200.AvailableHashes != nil {
		hashes = *resp.JSON200.AvailableHashes
	}

	return CheckAvailableHashesRes{AvailableHashes: hashes}, nil
}

// CheckAvailableHashesByVolume checks available hashes via the v2 volume-scoped endpoint.
func (c *Client) CheckAvailableHashesByVolume(ctx context.Context, volumeID, linkID string, req CheckAvailableHashesByVolumeReq) (CheckAvailableHashesRes, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return CheckAvailableHashesRes{}, fmt.Errorf("check available hashes by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.CreateV2VolumesLinksCheckavailablehashesWithBodyWithResponse(ctx, volumeID, linkID, "application/json", bytes.NewReader(body))
	if err != nil {
		return CheckAvailableHashesRes{}, fmt.Errorf("check available hashes by volume: %w", err)
	}

	if resp.JSON200 == nil {
		return CheckAvailableHashesRes{}, fmt.Errorf("check available hashes by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	var hashes []string
	if resp.JSON200.AvailableHashes != nil {
		hashes = *resp.JSON200.AvailableHashes
	}

	return CheckAvailableHashesRes{AvailableHashes: hashes}, nil
}

// MoveByShare moves a link via the v1 share-scoped endpoint.
func (c *Client) MoveByShare(ctx context.Context, shareID, linkID string, req MoveByShareReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("moving by share: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateSharesLinksMoveWithBodyWithResponse(ctx, shareID, linkID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("moving by share: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("moving by share: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}

// MoveByVolume moves a link via the v2 volume-scoped endpoint.
func (c *Client) MoveByVolume(ctx context.Context, volumeID, linkID string, req MoveByVolumeReq) error {
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("moving by volume: marshaling request: %w", err)
	}

	resp, err := c.gen.UpdateV2VolumesLinksMoveWithBodyWithResponse(ctx, volumeID, linkID, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("moving by volume: %w", err)
	}

	if resp.HTTPResponse.StatusCode != 200 {
		return fmt.Errorf("moving by volume: %w", apiErrorFromGenResponse(resp.HTTPResponse, resp.Body))
	}

	return nil
}
