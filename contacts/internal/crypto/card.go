package crypto

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// EncryptCard encrypts a plaintext vCard payload with the given key ring and
// returns the armored PGP message.
func EncryptCard(data string, kr *crypto.KeyRing) (string, error) {
	if kr == nil {
		return "", fmt.Errorf("contacts: encrypt card: nil key ring")
	}

	enc, err := kr.Encrypt(crypto.NewPlainMessageFromString(data), nil)
	if err != nil {
		return "", fmt.Errorf("contacts: encrypt card: %w", err)
	}

	armored, err := enc.GetArmored()
	if err != nil {
		return "", fmt.Errorf("contacts: encrypt card: armor: %w", err)
	}

	return armored, nil
}

// DecryptCard decrypts an armored PGP card payload with the given key ring and
// returns the plaintext vCard.
func DecryptCard(encData string, kr *crypto.KeyRing) (string, error) {
	if kr == nil {
		return "", fmt.Errorf("contacts: decrypt card: nil key ring")
	}

	msg, err := crypto.NewPGPMessageFromArmored(encData)
	if err != nil {
		return "", fmt.Errorf("contacts: decrypt card: parse: %w", err)
	}

	dec, err := kr.Decrypt(msg, nil, crypto.GetUnixTime())
	if err != nil {
		return "", fmt.Errorf("contacts: decrypt card: %w", err)
	}

	return dec.GetString(), nil
}

// SignCard produces an armored detached signature over the plaintext vCard
// payload using the given key ring.
func SignCard(data string, kr *crypto.KeyRing) (string, error) {
	if kr == nil {
		return "", fmt.Errorf("contacts: sign card: nil key ring")
	}

	sig, err := kr.SignDetached(crypto.NewPlainMessageFromString(data))
	if err != nil {
		return "", fmt.Errorf("contacts: sign card: %w", err)
	}

	armored, err := sig.GetArmored()
	if err != nil {
		return "", fmt.Errorf("contacts: sign card: armor: %w", err)
	}

	return armored, nil
}

// VerifyCard verifies an armored detached signature against the plaintext
// vCard payload using the given key ring. It returns nil if the signature is
// valid.
func VerifyCard(data, sig string, kr *crypto.KeyRing) error {
	if kr == nil {
		return fmt.Errorf("contacts: verify card: nil key ring")
	}

	parsed, err := crypto.NewPGPSignatureFromArmored(sig)
	if err != nil {
		return fmt.Errorf("contacts: verify card: parse signature: %w", err)
	}

	if err := kr.VerifyDetached(crypto.NewPlainMessageFromString(data), parsed, crypto.GetUnixTime()); err != nil {
		return fmt.Errorf("contacts: verify card: %w", err)
	}

	return nil
}
