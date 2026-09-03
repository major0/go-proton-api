// Package calendar provides a public, plaintext-facing client for the Proton
// Calendar API. It wraps the generated transport client and transparently
// handles Proton's end-to-end encryption: request fields are encrypted before
// each API call and response fields are decrypted afterwards.
//
// Consumers interact only with the domain types declared in this file. The
// generated wire types and the encryption helpers live under internal/ and are
// not importable by external code.
package calendar

import "time"

// CalendarType identifies the kind of calendar.
type CalendarType int

const (
	// CalendarTypeNormal is a standard personal calendar owned by the user.
	CalendarTypeNormal CalendarType = iota
	// CalendarTypeSubscribed is a calendar the user subscribed to (read-only).
	CalendarTypeSubscribed
	// CalendarTypeHolidays is a Proton-provided holidays calendar.
	CalendarTypeHolidays
)

// Calendar is a plaintext-facing view of a Proton calendar. Name and
// Description are decrypted values; on the wire they are stored encrypted
// under the calendar keyring.
type Calendar struct {
	ID          string       // upstream calendar ID
	Name        string       // decrypted calendar name
	Description string       // decrypted calendar description
	Color       string       // display color (e.g. "#ff0000")
	Type        CalendarType // calendar kind
	Flags       int          // server-defined calendar flag bitfield
}

// AttendeeStatus is an attendee's response to an event invitation.
type AttendeeStatus int

const (
	// AttendeeStatusPending means the attendee has not yet responded.
	AttendeeStatusPending AttendeeStatus = iota
	// AttendeeStatusAccepted means the attendee accepted the invitation.
	AttendeeStatusAccepted
	// AttendeeStatusDeclined means the attendee declined the invitation.
	AttendeeStatusDeclined
	// AttendeeStatusTentative means the attendee tentatively accepted.
	AttendeeStatusTentative
)

// AttendeeRole is an attendee's participation role for an event.
type AttendeeRole int

const (
	// AttendeeRoleRequired marks the attendee's presence as required.
	AttendeeRoleRequired AttendeeRole = iota
	// AttendeeRoleOptional marks the attendee's presence as optional.
	AttendeeRoleOptional
)

// Attendee is a plaintext-facing view of an event attendee. Email is a
// decrypted value; on the wire attendee data is stored encrypted under the
// calendar keyring.
type Attendee struct {
	Email  string         // decrypted attendee email address
	Status AttendeeStatus // invitation response status
	Role   AttendeeRole   // required or optional participation
}

// Event is a plaintext-facing view of a Proton calendar event. Title,
// Description, and Location are decrypted values; on the wire they are stored
// encrypted under the calendar keyring.
type Event struct {
	ID          string     // upstream event ID
	CalendarID  string     // ID of the calendar this event belongs to
	Title       string     // decrypted event title
	Description string     // decrypted event description
	Location    string     // decrypted event location
	StartTime   time.Time  // event start time
	EndTime     time.Time  // event end time
	Attendees   []Attendee // decrypted attendee list
}
