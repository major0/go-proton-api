package proton

// ShareEvent is the v1 event response from the share-scoped endpoint.
// Uses integer More/Refresh (0|1) matching the existing DriveEvent wire format.
type ShareEvent struct {
	EventID string      `json:"EventID"`
	Events  []LinkEvent `json:"Events"`
	More    Bool        `json:"More"`
	Refresh Bool        `json:"Refresh"`
}

// VolumeEvent is the v2 event response from the volume-scoped endpoint.
// Uses boolean More/Refresh and nested Link objects.
type VolumeEvent struct {
	EventID string            `json:"EventID"`
	Events  []VolumeEventItem `json:"Events"`
	More    bool              `json:"More"`
	Refresh bool              `json:"Refresh"`
}

// VolumeEventItem is a single event entry in a v2 volume event response.
type VolumeEventItem struct {
	EventID   string          `json:"EventID"`
	EventType LinkEventType   `json:"EventType"`
	Link      VolumeEventLink `json:"Link"`
	Data      any             `json:"Data,omitempty"`
}

// VolumeEventLink is the nested link object in a v2 volume event.
// Contains only summary fields rather than the full Link struct.
type VolumeEventLink struct {
	LinkID       string `json:"LinkID"`
	ParentLinkID string `json:"ParentLinkID"`
	IsShared     bool   `json:"IsShared"`
	IsTrashed    bool   `json:"IsTrashed"`
}
