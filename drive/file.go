package drive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateFileReq contains the parameters for creating a new file link.
// The Name field should be plaintext — it is encrypted internally before
// being sent to the API.
type CreateFileReq struct {
	// Name is the plaintext filename. Encrypted with the parent folder's
	// keyring before the API call.
	Name string

	// MIMEType is the file's MIME type (e.g., "text/plain").
	MIMEType string

	// ParentLinkID is the link ID of the parent folder.
	ParentLinkID string
}

// CreateFile creates a new file link in the given share under the specified
// parent folder. The file name is encrypted using the parent folder's
// keyring before being sent to the API.
//
// This creates the file metadata (link) only — content blocks are uploaded
// separately via revision operations.
//
// TODO: Wire up actual keyring derivation and name encryption once the
// keyring cache is implemented. Currently returns an error indicating the
// crypto layer is not yet wired.
func (c *Client) CreateFile(ctx context.Context, shareID string, req CreateFileReq) (*Link, error) {
	// Encryption flow:
	// 1. Derive parent folder's keyring from the share keyring chain
	// 2. Generate new node key pair for this file
	//    (crypto.GenerateNodeKeys(parentKR, addrKR) -> armoredKey, encPassphrase, sig)
	// 3. Encrypt the filename with parent keyring
	//    (crypto.EncryptName(req.Name, parentKR, addrKR) -> encName)
	// 4. Compute name hash for deduplication
	// 5. Build wire request with encrypted fields
	// 6. POST to /drive/shares/{shareID}/files
	// 7. Parse response, return domain Link

	return nil, fmt.Errorf("drive: CreateFile: crypto layer not yet wired")
}

// GetRevision retrieves a specific revision of a file. The revision's XAttr
// field is decrypted using the file's node keyring before being returned.
//
// TODO: Wire up XAttr decryption once the keyring cache is implemented.
func (c *Client) GetRevision(ctx context.Context, shareID, linkID, revisionID string) (*Revision, error) {
	path := fmt.Sprintf("/drive/shares/%s/files/%s/revisions/%s", shareID, linkID, revisionID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("drive: get revision %s: %w", revisionID, err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: get revision %s: %w", revisionID, err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: get revision %s: %w", revisionID, err)
	}

	var body struct {
		Revision wireRevision `json:"Revision"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: get revision %s: decode: %w", revisionID, err)
	}

	// Decryption flow:
	// 1. Derive file's node keyring from parent chain
	// 2. Decrypt XAttr blob: crypto.DecryptXAttr(body.Revision.XAttr, nodeKR, addrKR)
	// 3. Map wire revision + decrypted XAttr -> domain Revision
	//
	// For now, return the revision without XAttr decryption until the
	// keyring cache is wired.
	rev := body.Revision.toDomain()
	return &rev, nil
}

// ListRevisions returns all revisions for a file link.
func (c *Client) ListRevisions(ctx context.Context, shareID, linkID string) ([]Revision, error) {
	path := fmt.Sprintf("/drive/shares/%s/files/%s/revisions", shareID, linkID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("drive: list revisions for %s: %w", linkID, err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: list revisions for %s: %w", linkID, err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: list revisions for %s: %w", linkID, err)
	}

	var body struct {
		Revisions []wireRevision `json:"Revisions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: list revisions for %s: decode: %w", linkID, err)
	}

	revisions := make([]Revision, 0, len(body.Revisions))
	for _, wr := range body.Revisions {
		revisions = append(revisions, wr.toDomain())
	}
	return revisions, nil
}

// wireRevision is the JSON representation of a revision from the API.
type wireRevision struct {
	RevisionID string `json:"ID"`
	Size       int64  `json:"Size"`
	State      int    `json:"State"`
	CreateTime int64  `json:"CreateTime"`
	ModifyTime int64  `json:"ModifyTime"`
	XAttr      string `json:"XAttr"` // encrypted, armored PGP message
	Blocks     []struct {
		Index int    `json:"Index"`
		URL   string `json:"URL"`
		Size  int64  `json:"Size"`
	} `json:"Blocks"`
}

func (wr wireRevision) toDomain() Revision {
	blocks := make([]Block, 0, len(wr.Blocks))
	for _, wb := range wr.Blocks {
		blocks = append(blocks, Block{
			Index: wb.Index,
			URL:   wb.URL,
			Size:  wb.Size,
		})
	}

	rev := Revision{
		ID:         wr.RevisionID,
		Size:       wr.Size,
		State:      RevisionState(wr.State),
		CreateTime: wr.CreateTime,
		ModifyTime: wr.ModifyTime,
		Blocks:     blocks,
	}

	// XAttr decryption happens when keyring is available.
	// The encrypted XAttr blob is not exposed in the domain type — it will
	// be decrypted and populated once the keyring cache is wired.

	return rev
}
