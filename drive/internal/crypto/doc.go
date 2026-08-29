// Package crypto provides internal encryption, decryption, keyring derivation,
// and signature helpers for the drive module. These are pure cryptographic
// operations that transform between plaintext domain values and the encrypted
// wire format required by the Proton Drive API.
//
// This package is internal to the drive module and not importable by external
// consumers. The public drive layer calls these helpers to encrypt fields
// before API calls and decrypt responses before returning domain types.
package crypto
