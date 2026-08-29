// Package drive provides the public Proton Drive API client.
package drive

// LinkType distinguishes files from folders.
type LinkType int

const (
	// LinkTypeFolder represents a folder link.
	LinkTypeFolder LinkType = 1
	// LinkTypeFile represents a file link.
	LinkTypeFile LinkType = 2
)

// LinkState represents the lifecycle state of a link.
type LinkState int

const (
	// LinkStateDraft is a link that has not been committed.
	LinkStateDraft LinkState = 0
	// LinkStateActive is a live, accessible link.
	LinkStateActive LinkState = 1
	// LinkStateTrashed is a soft-deleted link in the trash.
	LinkStateTrashed LinkState = 2
)

// Link is the universal node type in Proton Drive. It represents both files
// and folders in the tree. The Name field contains the decrypted plaintext
// filename — encryption/decryption is handled by the client layer.
type Link struct {
	ID             string
	ParentID       string
	Name           string // plaintext, decrypted name
	Type           LinkType
	MIMEType       string
	Size           int64
	State          LinkState
	CreateTime     int64
	ModifyTime     int64
	SignatureEmail string
}

// ShareType distinguishes different share categories.
type ShareType int

const (
	// ShareTypeMain is the user's primary share (one per volume).
	ShareTypeMain ShareType = 1
	// ShareTypeStandard is a shared folder or file share.
	ShareTypeStandard ShareType = 2
	// ShareTypeDevice is a device-specific share.
	ShareTypeDevice ShareType = 3
	// ShareTypePhotos is the photos share.
	ShareTypePhotos ShareType = 4
)

// ShareState represents the lifecycle state of a share.
type ShareState int

const (
	// ShareStateActive is a live, accessible share.
	ShareStateActive ShareState = 1
	// ShareStateDeleted is a deleted share.
	ShareStateDeleted ShareState = 2
)

// Share is an entry point to a subtree in the Drive file structure. A share
// holds a key that grants access to the file tree rooted at its LinkID.
type Share struct {
	ID       string
	VolumeID string
	LinkID   string // root link of the share
	Type     ShareType
	State    ShareState
}

// VolumeState represents the lifecycle state of a volume.
type VolumeState int

const (
	// VolumeStateActive is a usable volume.
	VolumeStateActive VolumeState = 1
	// VolumeStateLocked is a volume that cannot accept writes.
	VolumeStateLocked VolumeState = 3
)

// Volume is a top-level container in Proton Drive. Each user has at least one
// volume which holds all their shares and links.
type Volume struct {
	ID    string
	State VolumeState
}

// RevisionState represents the lifecycle state of a file revision.
type RevisionState int

const (
	// RevisionStateDraft is an uncommitted revision being uploaded.
	RevisionStateDraft RevisionState = 0
	// RevisionStateActive is the current live revision.
	RevisionStateActive RevisionState = 1
	// RevisionStateObsolete is a superseded previous revision.
	RevisionStateObsolete RevisionState = 2
)

// Revision represents a version of a file's content. Each file has one active
// revision and may have obsolete or draft revisions.
type Revision struct {
	ID         string
	Size       int64
	State      RevisionState
	CreateTime int64
	ModifyTime int64
	XAttr      *XAttr
	Blocks     []Block
}

// Block represents a single encrypted block of file content. Blocks are
// typically 4 MB each; the session key is shared across all blocks of a
// revision.
type Block struct {
	Index int
	URL   string // upload/download URL
	Size  int64
}

// XAttr holds extended attributes stored on a Drive revision. These are
// decrypted from the wire format before being returned to consumers.
type XAttr struct {
	ModificationTime string
	Size             int64
	BlockSizes       []int64
}

// DirEntry is a single entry returned when listing a directory's children.
type DirEntry struct {
	Link Link
}
