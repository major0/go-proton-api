package crypto

import (
	"fmt"

	pgp "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// SignDetached creates an armored detached signature over data using kr.
func SignDetached(data []byte, kr *pgp.KeyRing) (string, error) {
	plainMsg := pgp.NewPlainMessage(data)

	sig, err := kr.SignDetached(plainMsg)
	if err != nil {
		return "", fmt.Errorf("crypto.SignDetached: %w", err)
	}

	armored, err := sig.GetArmored()
	if err != nil {
		return "", fmt.Errorf("crypto.SignDetached: armor: %w", err)
	}

	return armored, nil
}

// VerifyDetached verifies an armored detached signature over data using kr.
func VerifyDetached(data []byte, sig string, kr *pgp.KeyRing) error {
	plainMsg := pgp.NewPlainMessage(data)

	pgpSig, err := pgp.NewPGPSignatureFromArmored(sig)
	if err != nil {
		return fmt.Errorf("crypto.VerifyDetached: parse signature: %w", err)
	}

	if err := kr.VerifyDetached(plainMsg, pgpSig, pgp.GetUnixTime()); err != nil {
		return fmt.Errorf("crypto.VerifyDetached: %w", err)
	}

	return nil
}
