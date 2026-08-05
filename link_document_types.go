package proton

// CreateDocumentReq is the request body for creating a Proton Doc.
type CreateDocumentReq struct {
	ParentLinkID string

	Name string // Encrypted document name
	Hash string // Encrypted content hash

	ContentKeyPacket          string // The block's key packet, encrypted with the node key.
	ContentKeyPacketSignature string // Unencrypted signature of the content session key, signed with the NodeKey.

	NodeKey                 string // The private NodeKey, used to decrypt any file/folder content.
	NodePassphrase          string // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
	NodePassphraseSignature string // The signature of the NodePassphrase.

	SignatureAddress  string // Signature email address used to sign passphrase and name.
	ManifestSignature string // Manifest signature for the document.
	DocumentType      string // Document type: "1" = Document, "2" = Sheet.
}

// CreateDocumentRes is the response from creating a Proton Doc.
type CreateDocumentRes struct {
	LinkID     string // The created document's Link ID.
	RevisionID string // The created document's initial Revision ID.
	VolumeID   string // The Volume ID the document belongs to.
}
