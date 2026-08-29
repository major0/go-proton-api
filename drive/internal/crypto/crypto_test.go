package crypto

import (
	"testing"
	"testing/quick"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ProtonMail/gopenpgp/v2/helper"
)

// testKeyRing generates a fresh unlocked keyring for use in tests. The
// passphrase used to lock the generated key is discarded immediately after
// unlocking — the returned keyring is ready for encrypt/decrypt/sign.
func testKeyRing(t *testing.T) *crypto.KeyRing {
	t.Helper()

	passphrase := []byte("test-passphrase")

	armored, err := helper.GenerateKey("test", "test@proton.me", passphrase, "x25519", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	lockedKey, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}

	unlockedKey, err := lockedKey.Unlock(passphrase)
	if err != nil {
		t.Fatalf("unlock key: %v", err)
	}

	kr, err := crypto.NewKeyRing(unlockedKey)
	if err != nil {
		t.Fatalf("build keyring: %v", err)
	}

	return kr
}

func TestEncryptDecryptName_RoundTrip(t *testing.T) {
	parentKR := testKeyRing(t)
	addrKR := testKeyRing(t)

	names := []string{
		"hello.txt",
		"",
		"a file with spaces.pdf",
		"unicode-\u00e9\u00e8\u00ea-\u4f60\u597d.md",
		"very/long/looking/but/still/a/single/name",
	}

	for _, name := range names {
		enc, err := EncryptName(name, parentKR, addrKR)
		if err != nil {
			t.Fatalf("EncryptName(%q): %v", name, err)
		}

		got, err := DecryptName(enc, parentKR, addrKR)
		if err != nil {
			t.Fatalf("DecryptName(%q): %v", name, err)
		}

		if got != name {
			t.Errorf("round-trip mismatch: got %q, want %q", got, name)
		}
	}
}

func TestEncryptDecryptName_QuickProperty(t *testing.T) {
	parentKR := testKeyRing(t)
	addrKR := testKeyRing(t)

	// Property: for any string name, DecryptName(EncryptName(name)) == name.
	roundTrip := func(name string) bool {
		enc, err := EncryptName(name, parentKR, addrKR)
		if err != nil {
			return false
		}
		got, err := DecryptName(enc, parentKR, addrKR)
		if err != nil {
			return false
		}
		return got == name
	}

	if err := quick.Check(roundTrip, &quick.Config{MaxCount: 50}); err != nil {
		t.Errorf("name round-trip property failed: %v", err)
	}
}

func TestEncryptDecryptXAttr_RoundTrip(t *testing.T) {
	nodeKR := testKeyRing(t)
	addrKR := testKeyRing(t)

	want := &XAttr{
		Common: XAttrCommon{
			ModificationTime: "2024-01-02T03:04:05Z",
			Size:             123456,
			BlockSizes:       []int64{4096, 4096, 2048},
		},
	}

	enc, err := EncryptXAttr(want, nodeKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptXAttr: %v", err)
	}

	got, err := DecryptXAttr(enc, nodeKR, addrKR)
	if err != nil {
		t.Fatalf("DecryptXAttr: %v", err)
	}

	if got.Common.ModificationTime != want.Common.ModificationTime {
		t.Errorf("ModificationTime: got %q, want %q", got.Common.ModificationTime, want.Common.ModificationTime)
	}
	if got.Common.Size != want.Common.Size {
		t.Errorf("Size: got %d, want %d", got.Common.Size, want.Common.Size)
	}
	if len(got.Common.BlockSizes) != len(want.Common.BlockSizes) {
		t.Fatalf("BlockSizes length: got %d, want %d", len(got.Common.BlockSizes), len(want.Common.BlockSizes))
	}
	for i := range want.Common.BlockSizes {
		if got.Common.BlockSizes[i] != want.Common.BlockSizes[i] {
			t.Errorf("BlockSizes[%d]: got %d, want %d", i, got.Common.BlockSizes[i], want.Common.BlockSizes[i])
		}
	}
}

func TestDecryptName_WrongKey_Fails(t *testing.T) {
	parentKR := testKeyRing(t)
	addrKR := testKeyRing(t)
	wrongKR := testKeyRing(t)

	enc, err := EncryptName("secret.txt", parentKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptName: %v", err)
	}

	if _, err := DecryptName(enc, wrongKR, addrKR); err == nil {
		t.Error("expected error decrypting with wrong keyring, got nil")
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	kr := testKeyRing(t)
	data := []byte("the quick brown fox")

	sig, err := SignDetached(data, kr)
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}

	if err := VerifyDetached(data, sig, kr); err != nil {
		t.Errorf("VerifyDetached: %v", err)
	}
}

func TestVerify_TamperedData_Fails(t *testing.T) {
	kr := testKeyRing(t)
	data := []byte("the quick brown fox")

	sig, err := SignDetached(data, kr)
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}

	tampered := []byte("the quick brown cat")
	if err := VerifyDetached(tampered, sig, kr); err == nil {
		t.Error("expected error verifying tampered data, got nil")
	}
}

func TestVerify_WrongKey_Fails(t *testing.T) {
	signKR := testKeyRing(t)
	verifyKR := testKeyRing(t)
	data := []byte("the quick brown fox")

	sig, err := SignDetached(data, signKR)
	if err != nil {
		t.Fatalf("SignDetached: %v", err)
	}

	if err := VerifyDetached(data, sig, verifyKR); err == nil {
		t.Error("expected error verifying with wrong key, got nil")
	}
}

func TestGenerateNodeKeys_ProducesUnlockableKey(t *testing.T) {
	parentKR := testKeyRing(t)
	addrKR := testKeyRing(t)

	armoredKey, encPassphrase, passphraseSig, err := GenerateNodeKeys(parentKR, addrKR)
	if err != nil {
		t.Fatalf("GenerateNodeKeys: %v", err)
	}

	nodeKR, err := UnlockKeyRing(parentKR, addrKR, armoredKey, encPassphrase, passphraseSig)
	if err != nil {
		t.Fatalf("UnlockKeyRing: %v", err)
	}

	// The unlocked node keyring must be usable for encryption.
	enc, err := EncryptName("child.txt", nodeKR, addrKR)
	if err != nil {
		t.Fatalf("EncryptName with unlocked node keyring: %v", err)
	}
	if _, err := DecryptName(enc, nodeKR, addrKR); err != nil {
		t.Errorf("DecryptName with unlocked node keyring: %v", err)
	}
}

func TestUnlockKeyRing_BadPassphrase_Fails(t *testing.T) {
	parentKR := testKeyRing(t)
	addrKR := testKeyRing(t)
	wrongParentKR := testKeyRing(t)

	armoredKey, encPassphrase, passphraseSig, err := GenerateNodeKeys(parentKR, addrKR)
	if err != nil {
		t.Fatalf("GenerateNodeKeys: %v", err)
	}

	// Decrypting the passphrase with the wrong parent keyring must fail.
	if _, err := UnlockKeyRing(wrongParentKR, addrKR, armoredKey, encPassphrase, passphraseSig); err == nil {
		t.Error("expected error unlocking with wrong parent keyring, got nil")
	}
}
