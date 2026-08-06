package proton

// Invitation represents a pending share invitation.
type Invitation struct {
	InvitationID string `json:"InvitationID"`
	ShareID      string `json:"ShareID"`
	InviterEmail string `json:"InviterEmail"`
	InviteeEmail string `json:"InviteeEmail"`
	Permissions  int    `json:"Permissions"`
	State        int    `json:"State"`
	CreateTime   int64  `json:"CreateTime"`
}

// CreateInvitationReq is the request for creating a share invitation.
type CreateInvitationReq struct {
	InviteeEmail string `json:"InviteeEmail"`
	Permissions  int    `json:"Permissions"`
}

// UpdateInvitationReq is the request for updating a share invitation.
type UpdateInvitationReq struct {
	Permissions int `json:"Permissions"`
}

// ExternalInvitation represents an invitation for a non-Proton user.
type ExternalInvitation struct {
	InvitationID string `json:"InvitationID"`
	ShareID      string `json:"ShareID"`
	InviterEmail string `json:"InviterEmail"`
	InviteeEmail string `json:"InviteeEmail"`
	Permissions  int    `json:"Permissions"`
	State        int    `json:"State"`
	CreateTime   int64  `json:"CreateTime"`
}

// CreateExternalInvitationReq is the request for inviting a non-Proton user.
type CreateExternalInvitationReq struct {
	InviteeEmail string `json:"InviteeEmail"`
	Permissions  int    `json:"Permissions"`
}

// ShareMember represents a member of a share.
type ShareMember struct {
	MemberID    string `json:"MemberID"`
	ShareID     string `json:"ShareID"`
	Email       string `json:"Email"`
	Permissions int    `json:"Permissions"`
	CreateTime  int64  `json:"CreateTime"`
}

// UpdateMemberReq is the request for updating member permissions.
type UpdateMemberReq struct {
	Permissions int `json:"Permissions"`
}
