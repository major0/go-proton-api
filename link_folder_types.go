package proton

// CreateFolderReq is the v1 request for folder creation (uses SignatureAddress).
type CreateFolderReq struct {
	ParentLinkID string

	Name string
	Hash string

	NodeKey     string
	NodeHashKey string

	NodePassphrase          string
	NodePassphraseSignature string

	SignatureAddress string
}

// CreateFolderByVolumeReq is the v2 request for folder creation (uses SignatureEmail).
type CreateFolderByVolumeReq struct {
	ParentLinkID string

	Name string
	Hash string

	NodeKey     string
	NodeHashKey string

	NodePassphrase          string
	NodePassphraseSignature string

	SignatureEmail string
}

// CreateFolderRes is the response from folder creation (same shape for v1 and v2).
type CreateFolderRes struct {
	ID string // Encrypted Link ID
}

// MoveByShareReq is the v1 request for moving a link (includes NewShareID and SignatureAddress).
type MoveByShareReq struct {
	Name                    string `json:"Name"`
	Hash                    string `json:"Hash"`
	ParentLinkID            string `json:"ParentLinkID"`
	NewShareID              string `json:"NewShareID,omitempty"`
	NodePassphrase          string `json:"NodePassphrase"`
	NodePassphraseSignature string `json:"NodePassphraseSignature"`
	SignatureAddress        string `json:"SignatureAddress,omitempty"`
	NameSignatureEmail      string `json:"NameSignatureEmail,omitempty"`
}

// MoveByVolumeReq is the v2 request for moving a link (no NewShareID or SignatureAddress).
type MoveByVolumeReq struct {
	Name                    string `json:"Name"`
	Hash                    string `json:"Hash"`
	ParentLinkID            string `json:"ParentLinkID"`
	NodePassphrase          string `json:"NodePassphrase"`
	NodePassphraseSignature string `json:"NodePassphraseSignature"`
	NameSignatureEmail      string `json:"NameSignatureEmail,omitempty"`
}
