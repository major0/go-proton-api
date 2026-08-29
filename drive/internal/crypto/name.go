package crypto

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// EncryptName encrypts a plaintext filename with parentKR and signs it with
// addrKR. Returns the armored PGP message suitable for the Name wire field.
func EncryptName(name string, parentKR, addrKR *crypto.KeyRing) (string, error) {
	plainMsg := crypto.NewPlainMessage([]byte(name))

	encMsg, err := parentKR.Encrypt(plainMsg, addrKR)
	if err != nil {
		return "", fmt.Errorf("crypto.EncryptName: %w", err)
	}

	armored, err := encMsg.GetArmored()
	if err != nil {
		return "", fmt.Errorf("crypto.EncryptName: armor: %w", err)
	}

	return armored, nil
}

// DecryptName decrypts an armored encrypted filename using parentKR and
// verifies the signature against addrKR.
func DecryptName(encName string, parentKR, addrKR *crypto.KeyRing) (string, error) {
	encMsg, err := crypto.NewPGPMessageFromArmored(encName)
	if err != nil {
		return "", fmt.Errorf("crypto.DecryptName: parse: %w", err)
	}

	decMsg, err := parentKR.Decrypt(encMsg, addrKR, crypto.GetUnixTime())
	if err != nil {
		return "", fmt.Errorf("crypto.DecryptName: %w", err)
	}

	return decMsg.GetString(), nil
}
