package crypto

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

const testVCard = "BEGIN:VCARD\nVERSION:4.0\nFN:Alice\nEMAIL:alice@example.com\nEND:VCARD\n"

// newTestKeyRing generates an unlocked key ring for use in tests.
func newTestKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()

	key, err := crypto.GenerateKey("Test", "test@example.com", "x25519", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	t.Cleanup(func() { key.ClearPrivateParams() })

	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("new key ring: %v", err)
	}

	return kr
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	kr := newTestKeyRing(t)

	enc, err := EncryptCard(testVCard, kr)
	if err != nil {
		t.Fatalf("EncryptCard: %v", err)
	}
	if enc == testVCard {
		t.Fatal("encrypted data equals plaintext")
	}

	dec, err := DecryptCard(enc, kr)
	if err != nil {
		t.Fatalf("DecryptCard: %v", err)
	}
	if dec != testVCard {
		t.Fatalf("decrypted = %q, want %q", dec, testVCard)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	kr := newTestKeyRing(t)

	sig, err := SignCard(testVCard, kr)
	if err != nil {
		t.Fatalf("SignCard: %v", err)
	}

	if err := VerifyCard(testVCard, sig, kr); err != nil {
		t.Fatalf("VerifyCard: %v", err)
	}
}

func TestVerifyTamperedData(t *testing.T) {
	kr := newTestKeyRing(t)

	sig, err := SignCard(testVCard, kr)
	if err != nil {
		t.Fatalf("SignCard: %v", err)
	}

	if err := VerifyCard(testVCard+"tampered", sig, kr); err == nil {
		t.Fatal("expected verification failure for tampered data")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	krA := newTestKeyRing(t)
	krB := newTestKeyRing(t)

	enc, err := EncryptCard(testVCard, krA)
	if err != nil {
		t.Fatalf("EncryptCard: %v", err)
	}

	if _, err := DecryptCard(enc, krB); err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	krA := newTestKeyRing(t)
	krB := newTestKeyRing(t)

	sig, err := SignCard(testVCard, krA)
	if err != nil {
		t.Fatalf("SignCard: %v", err)
	}

	if err := VerifyCard(testVCard, sig, krB); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

func TestNilKeyRing(t *testing.T) {
	if _, err := EncryptCard(testVCard, nil); err == nil {
		t.Error("EncryptCard: expected error for nil key ring")
	}
	if _, err := DecryptCard("data", nil); err == nil {
		t.Error("DecryptCard: expected error for nil key ring")
	}
	if _, err := SignCard(testVCard, nil); err == nil {
		t.Error("SignCard: expected error for nil key ring")
	}
	if err := VerifyCard(testVCard, "sig", nil); err == nil {
		t.Error("VerifyCard: expected error for nil key ring")
	}
}
