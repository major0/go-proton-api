package crypto

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// UnlockCalendarKeyRing derives an unlocked calendar keyring from a calendar
// key and its encrypted passphrase.
//
// The calendar key (armoredKey) is a locked PGP private key. Its passphrase
// (encPassphrase) is a PGP message encrypted to the member/address keyring
// (addrKR) and signed by the parent keyring (parentKR). The passphrase
// signature (passphraseSig) is verified against parentKR.
//
// The returned keyring can decrypt event fields belonging to the calendar.
// This mirrors Drive's share-keyring derivation: a parent keyring unlocks the
// passphrase, which in turn unlocks the target key.
func UnlockCalendarKeyRing(parentKR, addrKR *crypto.KeyRing, armoredKey, encPassphrase, passphraseSig string) (*crypto.KeyRing, error) {
	if addrKR == nil {
		return nil, fmt.Errorf("calendar: unlock keyring: nil address keyring")
	}

	// Decrypt the calendar key passphrase using the address keyring. When a
	// parent keyring is supplied it is used to verify the passphrase
	// signature; otherwise the signature is only checked for presence.
	encMsg, err := crypto.NewPGPMessageFromArmored(encPassphrase)
	if err != nil {
		return nil, fmt.Errorf("calendar: unlock keyring: parse passphrase: %w", err)
	}

	verifyKR := parentKR
	if verifyKR == nil {
		verifyKR = addrKR
	}

	plainPassphrase, err := addrKR.Decrypt(encMsg, verifyKR, crypto.GetUnixTime())
	if err != nil {
		return nil, fmt.Errorf("calendar: unlock keyring: decrypt passphrase: %w", err)
	}

	if passphraseSig != "" && parentKR != nil {
		if err := verifyDetached(parentKR, plainPassphrase.GetBinary(), passphraseSig); err != nil {
			return nil, fmt.Errorf("calendar: unlock keyring: verify passphrase signature: %w", err)
		}
	}

	// Unlock the calendar key with the decrypted passphrase.
	key, err := crypto.NewKeyFromArmored(armoredKey)
	if err != nil {
		return nil, fmt.Errorf("calendar: unlock keyring: parse key: %w", err)
	}

	unlocked, err := key.Unlock(plainPassphrase.GetBinary())
	if err != nil {
		return nil, fmt.Errorf("calendar: unlock keyring: unlock key: %w", err)
	}

	kr, err := crypto.NewKeyRing(unlocked)
	if err != nil {
		return nil, fmt.Errorf("calendar: unlock keyring: build keyring: %w", err)
	}

	return kr, nil
}

// verifyDetached verifies an armored detached signature over data against the
// given keyring.
func verifyDetached(kr *crypto.KeyRing, data []byte, armoredSig string) error {
	sig, err := crypto.NewPGPSignatureFromArmored(armoredSig)
	if err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	if err := kr.VerifyDetached(crypto.NewPlainMessage(data), sig, crypto.GetUnixTime()); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}
