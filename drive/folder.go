package drive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateFolderReq contains the parameters for creating a new folder.
// The Name field should be plaintext — it is encrypted internally before
// being sent to the API.
type CreateFolderReq struct {
	// Name is the plaintext folder name. Encrypted with the parent folder's
	// keyring before the API call.
	Name string

	// ParentLinkID is the link ID of the parent folder.
	ParentLinkID string
}

// CreateFolder creates a new folder link in the given share under the
// specified parent folder. The folder name is encrypted using the parent
// folder's keyring before being sent to the API.
//
// TODO: Wire up actual keyring derivation and name encryption once the
// keyring cache is implemented. Currently returns an error indicating the
// crypto layer is not yet wired.
func (c *Client) CreateFolder(ctx context.Context, shareID string, req CreateFolderReq) (*Link, error) {
	// Encryption flow:
	// 1. Derive parent folder's keyring from the share keyring chain
	// 2. Generate new node key pair for this folder
	//    (crypto.GenerateNodeKeys(parentKR, addrKR) -> armoredKey, encPassphrase, sig)
	// 3. Encrypt the folder name with parent keyring
	//    (crypto.EncryptName(req.Name, parentKR, addrKR) -> encName)
	// 4. Compute name hash for deduplication
	// 5. Generate NodeHashKey for the new folder
	// 6. Encrypt initial XAttr for the folder
	//    (crypto.EncryptXAttr(xattr, nodeKR, addrKR) -> encXAttr)
	// 7. Build wire request with all encrypted fields
	// 8. POST to /drive/shares/{shareID}/folders
	// 9. Parse response, return domain Link

	return nil, fmt.Errorf("drive: CreateFolder: crypto layer not yet wired")
}

// ListChildren lists the direct children of a folder. Each child's
// encrypted name is decrypted using the parent folder's keyring before
// being returned in the DirEntry.
//
// TODO: Wire up name decryption once the keyring cache is implemented.
// Currently returns entries with encrypted names in the Link.Name field.
func (c *Client) ListChildren(ctx context.Context, shareID, linkID string) ([]DirEntry, error) {
	path := fmt.Sprintf("/drive/shares/%s/folders/%s/children", shareID, linkID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.host+path, nil)
	if err != nil {
		return nil, fmt.Errorf("drive: list children of %s: %w", linkID, err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: list children of %s: %w", linkID, err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: list children of %s: %w", linkID, err)
	}

	var body struct {
		Links []wireLink `json:"Links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: list children of %s: decode: %w", linkID, err)
	}

	// Decryption flow (per child):
	// 1. Derive parent folder's keyring from share keyring chain
	// 2. Decrypt each child's Name field:
	//    crypto.DecryptName(wl.Name, parentKR, addrKR) -> plaintext name
	// 3. Map wire link -> domain DirEntry with decrypted name
	//
	// Until the keyring cache is wired, names remain in their encrypted form.
	entries := make([]DirEntry, 0, len(body.Links))
	for _, wl := range body.Links {
		entries = append(entries, DirEntry{
			Link: wl.toDomain(),
		})
	}
	return entries, nil
}

// GetLink retrieves a single link by ID within a share. The link's name is
// decrypted using the parent folder's keyring.
//
// TODO: Wire up name decryption once the keyring cache is implemented.
func (c *Client) GetLink(ctx context.Context, shareID, linkID string) (*Link, error) {
	// The Proton API uses fetch_metadata for individual link retrieval.
	// This issues a POST to /drive/shares/{shareID}/links/fetch_metadata
	// with the link IDs to fetch.
	path := fmt.Sprintf("/drive/shares/%s/links/fetch_metadata", shareID)

	reqBody := struct {
		LinkIDs []string `json:"LinkIDs"`
	}{
		LinkIDs: []string{linkID},
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("drive: get link %s: marshal: %w", linkID, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+path, jsonReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("drive: get link %s: %w", linkID, err)
	}
	c.setHeaders(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("drive: get link %s: %w", linkID, err)
	}
	defer resp.Body.Close()

	if err := checkResponse(resp); err != nil {
		return nil, fmt.Errorf("drive: get link %s: %w", linkID, err)
	}

	var body struct {
		Links []wireLink `json:"Links"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("drive: get link %s: decode: %w", linkID, err)
	}

	if len(body.Links) == 0 {
		return nil, fmt.Errorf("drive: get link %s: %w", linkID, ErrNotFound)
	}

	// Decryption flow:
	// 1. Derive parent's keyring from share chain
	// 2. Decrypt Name: crypto.DecryptName(encName, parentKR, addrKR)
	// 3. Return domain Link with plaintext name
	link := body.Links[0].toDomain()
	return &link, nil
}

// wireLink is the JSON representation of a link from the API.
type wireLink struct {
	LinkID         string `json:"LinkID"`
	ParentLinkID   string `json:"ParentLinkID"`
	Name           string `json:"Name"` // encrypted, armored PGP message
	Type           int    `json:"Type"`
	MIMEType       string `json:"MIMEType"`
	Size           int64  `json:"Size"`
	State          int    `json:"State"`
	CreateTime     int64  `json:"CreateTime"`
	ModifyTime     int64  `json:"ModifyTime"`
	SignatureEmail string `json:"SignatureEmail"`
}

func (wl wireLink) toDomain() Link {
	return Link{
		ID:             wl.LinkID,
		ParentID:       wl.ParentLinkID,
		Name:           wl.Name, // TODO: decrypt with parent keyring
		Type:           LinkType(wl.Type),
		MIMEType:       wl.MIMEType,
		Size:           wl.Size,
		State:          LinkState(wl.State),
		CreateTime:     wl.CreateTime,
		ModifyTime:     wl.ModifyTime,
		SignatureEmail: wl.SignatureEmail,
	}
}
