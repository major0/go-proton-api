package crypto

import (
	"encoding/json"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// XAttr represents the structured extended attributes stored on a Drive
// revision. This is the internal domain type used by the crypto layer; the
// public layer maps to/from this before encryption and after decryption.
type XAttr struct {
	Common XAttrCommon `json:"Common"`
}

// XAttrCommon holds the common extended attribute fields present on every
// Drive revision.
type XAttrCommon struct {
	ModificationTime string  `json:"ModificationTime"`
	Size             int64   `json:"Size"`
	BlockSizes       []int64 `json:"BlockSizes"`
}

// EncryptXAttr marshals xattr to JSON, encrypts it with nodeKR, and signs
// with addrKR. Returns the armored PGP message suitable for the XAttr wire
// field.
func EncryptXAttr(xattr *XAttr, nodeKR, addrKR *crypto.KeyRing) (string, error) {
	data, err := json.Marshal(xattr)
	if err != nil {
		return "", fmt.Errorf("crypto.EncryptXAttr: marshal: %w", err)
	}

	plainMsg := crypto.NewPlainMessage(data)

	encMsg, err := nodeKR.Encrypt(plainMsg, addrKR)
	if err != nil {
		return "", fmt.Errorf("crypto.EncryptXAttr: %w", err)
	}

	armored, err := encMsg.GetArmored()
	if err != nil {
		return "", fmt.Errorf("crypto.EncryptXAttr: armor: %w", err)
	}

	return armored, nil
}

// DecryptXAttr decrypts an armored XAttr blob using nodeKR and verifies the
// signature against addrKR. Returns the unmarshaled XAttr structure.
func DecryptXAttr(encXAttr string, nodeKR, addrKR *crypto.KeyRing) (*XAttr, error) {
	encMsg, err := crypto.NewPGPMessageFromArmored(encXAttr)
	if err != nil {
		return nil, fmt.Errorf("crypto.DecryptXAttr: parse: %w", err)
	}

	decMsg, err := nodeKR.Decrypt(encMsg, addrKR, crypto.GetUnixTime())
	if err != nil {
		return nil, fmt.Errorf("crypto.DecryptXAttr: %w", err)
	}

	var xattr XAttr
	if err := json.Unmarshal(decMsg.GetBinary(), &xattr); err != nil {
		return nil, fmt.Errorf("crypto.DecryptXAttr: unmarshal: %w", err)
	}

	return &xattr, nil
}
