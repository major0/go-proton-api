package crypto

import (
	"encoding/base64"
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// UnlockKeyRing decrypts a node's private key using the parent keyring.
// The passphrase is decrypted with parentKR and its signature is verified
// against addrKR. The decrypted passphrase then unlocks the armored node key.
func UnlockKeyRing(parentKR, addrKR *crypto.KeyRing, armoredKey, encPassphrase, passphraseSig string) (*crypto.KeyRing, error) {
	enc, err := crypto.NewPGPMessageFromArmored(encPassphrase)
	if err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: parse passphrase: %w", err)
	}

	dec, err := parentKR.Decrypt(enc, nil, crypto.GetUnixTime())
	if err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: decrypt passphrase: %w", err)
	}

	sig, err := crypto.NewPGPSignatureFromArmored(passphraseSig)
	if err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: parse signature: %w", err)
	}

	if err := addrKR.VerifyDetached(dec, sig, crypto.GetUnixTime()); err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: verify signature: %w", err)
	}

	lockedKey, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: parse key: %w", err)
	}

	unlockedKey, err := lockedKey.Unlock(dec.GetBinary())
	if err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: unlock key: %w", err)
	}

	kr, err := crypto.NewKeyRing(unlockedKey)
	if err != nil {
		return nil, fmt.Errorf("crypto.UnlockKeyRing: create keyring: %w", err)
	}

	return kr, nil
}

// GenerateNodeKeys creates a new node key pair for a Drive link. The
// passphrase is encrypted with parentKR and signed with addrKR.
// Returns the armored key, encrypted passphrase, and passphrase signature.
func GenerateNodeKeys(parentKR, addrKR *crypto.KeyRing) (armoredKey, encPassphrase, passphraseSig string, err error) {
	passphrase, err := crypto.RandomToken(32)
	if err != nil {
		return "", "", "", fmt.Errorf("crypto.GenerateNodeKeys: random token: %w", err)
	}

	passphraseB64 := base64.StdEncoding.EncodeToString(passphrase)

	key, err := helper.GenerateKey("Drive key", "noreply@protonmail.com", []byte(passphraseB64), "x25519", 0)
	if err != nil {
		return "", "", "", fmt.Errorf("crypto.GenerateNodeKeys: generate key: %w", err)
	}

	plainPassphrase := crypto.NewPlainMessage([]byte(passphraseB64))

	encMsg, err := parentKR.Encrypt(plainPassphrase, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("crypto.GenerateNodeKeys: encrypt passphrase: %w", err)
	}

	encArm, err := encMsg.GetArmored()
	if err != nil {
		return "", "", "", fmt.Errorf("crypto.GenerateNodeKeys: armor passphrase: %w", err)
	}

	sig, err := addrKR.SignDetached(plainPassphrase)
	if err != nil {
		return "", "", "", fmt.Errorf("crypto.GenerateNodeKeys: sign passphrase: %w", err)
	}

	sigArm, err := sig.GetArmored()
	if err != nil {
		return "", "", "", fmt.Errorf("crypto.GenerateNodeKeys: armor signature: %w", err)
	}

	return key, encArm, sigArm, nil
}
