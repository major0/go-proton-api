// Package crypto contains the internal encryption helpers for the Proton
// Calendar service. It derives calendar keyrings from member/address keyrings
// and encrypts/decrypts event fields under a calendar keyring.
//
// This package is internal: it is an implementation detail of the public
// calendar client and is not importable by external code. It defines its own
// copies of the helpers rather than depending on any sibling service module.
package crypto
