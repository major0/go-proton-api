// Package crypto provides the contacts module's own PGP encryption, signing,
// and verification helpers for contact card payloads. Contacts are stored as
// encrypted and/or signed vCards; crypto here is message-level PGP, not a
// keyring-derivation chain.
//
// These helpers are internal to the contacts module and are not part of its
// public API.
package crypto
