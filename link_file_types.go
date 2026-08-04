package proton

type CreateFileReq struct {
	ParentLinkID string

	Name     string // Encrypted File Name
	Hash     string // Encrypted content hash
	MIMEType string // MIME Type

	ContentKeyPacket          string // The block's key packet, encrypted with the node key.
	ContentKeyPacketSignature string // Unencrypted signature of the content session key, signed with the NodeKey

	NodeKey                 string // The private NodeKey, used to decrypt any file/folder content.
	NodePassphrase          string // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
	NodePassphraseSignature string // The signature of the NodePassphrase

	SignatureAddress string // Signature email address used to sign passphrase and name
}

type CreateFileRes struct {
	ID         string // Encrypted Link ID
	RevisionID string // Encrypted Revision ID
}

// CreateRevisionReq holds optional parameters for creating a new draft revision.
type CreateRevisionReq struct {
	// CurrentRevisionID is the active revision to inherit dirty blocks from (COW).
	// Optional — omit for a fresh upload.
	CurrentRevisionID string
}

// CreateRevisionRes is the response from creating a draft revision.
type CreateRevisionRes struct {
	ID string // Revision ID
}

type UpdateRevisionReq struct {
	BlockList         []BlockToken
	State             RevisionState
	ManifestSignature string
	SignatureAddress  string
}

type BlockToken struct {
	Index int
	Token string
}

// RevisionVerification holds the verification data for a revision, used to verify block integrity.
type RevisionVerification struct {
	VerificationCode string
	ContentKeyPacket string
}
