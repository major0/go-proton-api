package crypto

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// EncryptEventField encrypts a plaintext event field (title, description,
// location, attendee data, etc.) under the calendar keyring, signing it with
// the address keyring.
//
// The result is an armored PGP message suitable for the wire. calKR is the
// calendar keyring (the encryption target); addrKR is the address keyring used
// to sign the plaintext.
func EncryptEventField(data string, calKR, addrKR *crypto.KeyRing) (string, error) {
	if calKR == nil {
		return "", fmt.Errorf("calendar: encrypt event field: nil calendar keyring")
	}

	msg, err := calKR.Encrypt(crypto.NewPlainMessageFromString(data), addrKR)
	if err != nil {
		return "", fmt.Errorf("calendar: encrypt event field: %w", err)
	}

	armored, err := msg.GetArmored()
	if err != nil {
		return "", fmt.Errorf("calendar: encrypt event field: armor: %w", err)
	}

	return armored, nil
}

// DecryptEventField decrypts an armored event field encrypted under the
// calendar keyring, verifying the signature against the address keyring.
//
// calKR is the calendar keyring (holds the decryption key); addrKR is the
// address keyring used to verify the embedded signature. When addrKR is nil
// the signature is not verified.
func DecryptEventField(encData string, calKR, addrKR *crypto.KeyRing) (string, error) {
	if calKR == nil {
		return "", fmt.Errorf("calendar: decrypt event field: nil calendar keyring")
	}

	msg, err := crypto.NewPGPMessageFromArmored(encData)
	if err != nil {
		return "", fmt.Errorf("calendar: decrypt event field: parse: %w", err)
	}

	verifyKR := addrKR
	if verifyKR == nil {
		verifyKR = calKR
	}

	plain, err := calKR.Decrypt(msg, verifyKR, crypto.GetUnixTime())
	if err != nil {
		return "", fmt.Errorf("calendar: decrypt event field: %w", err)
	}

	return plain.GetString(), nil
}
