package crypto

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// genKeyRing generates an unlocked keyring for tests.
func genKeyRing(t *testing.T, name, email string) *crypto.KeyRing {
	t.Helper()
	key, err := crypto.GenerateKey(name, email, "x25519", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kr, err := crypto.NewKeyRing(key)
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	return kr
}

// makeLockedCalendarKey generates a calendar key locked with passphrase, and
// returns the armored locked key plus the passphrase encrypted to addrKR and
// signed by addrKR.
func makeLockedCalendarKey(t *testing.T, addrKR *crypto.KeyRing, passphrase []byte) (armoredKey, encPassphrase string) {
	t.Helper()

	calKey, err := crypto.GenerateKey("cal", "cal@proton.me", "x25519", 0)
	if err != nil {
		t.Fatalf("generate calendar key: %v", err)
	}
	locked, err := calKey.Lock(passphrase)
	if err != nil {
		t.Fatalf("lock calendar key: %v", err)
	}
	armoredKey, err = locked.Armor()
	if err != nil {
		t.Fatalf("armor calendar key: %v", err)
	}

	encMsg, err := addrKR.Encrypt(crypto.NewPlainMessage(passphrase), addrKR)
	if err != nil {
		t.Fatalf("encrypt passphrase: %v", err)
	}
	encPassphrase, err = encMsg.GetArmored()
	if err != nil {
		t.Fatalf("armor passphrase: %v", err)
	}
	return armoredKey, encPassphrase
}

func TestUnlockCalendarKeyRing_RoundTrip(t *testing.T) {
	addrKR := genKeyRing(t, "addr", "addr@proton.me")
	passphrase := []byte("calendar-key-passphrase")

	armoredKey, encPassphrase := makeLockedCalendarKey(t, addrKR, passphrase)

	// No parent keyring / no signature verification: addrKR both decrypts and
	// signs the passphrase.
	calKR, err := UnlockCalendarKeyRing(nil, addrKR, armoredKey, encPassphrase, "")
	if err != nil {
		t.Fatalf("unlock calendar keyring: %v", err)
	}
	if calKR.CountEntities() == 0 {
		t.Fatal("expected non-empty calendar keyring")
	}

	// The unlocked keyring can round-trip an event field.
	enc, err := EncryptEventField("hello", calKR, addrKR)
	if err != nil {
		t.Fatalf("encrypt with unlocked keyring: %v", err)
	}
	got, err := DecryptEventField(enc, calKR, addrKR)
	if err != nil {
		t.Fatalf("decrypt with unlocked keyring: %v", err)
	}
	if got != "hello" {
		t.Fatalf("round trip mismatch: got %q want %q", got, "hello")
	}
}

func TestUnlockCalendarKeyRing_WrongAddressKey(t *testing.T) {
	addrKR := genKeyRing(t, "addr", "addr@proton.me")
	wrongKR := genKeyRing(t, "wrong", "wrong@proton.me")
	passphrase := []byte("calendar-key-passphrase")

	armoredKey, encPassphrase := makeLockedCalendarKey(t, addrKR, passphrase)

	// A different address keyring cannot decrypt the passphrase.
	if _, err := UnlockCalendarKeyRing(nil, wrongKR, armoredKey, encPassphrase, ""); err == nil {
		t.Fatal("expected error unlocking with wrong address keyring")
	}
}

func TestUnlockCalendarKeyRing_NilAddressKeyRing(t *testing.T) {
	if _, err := UnlockCalendarKeyRing(nil, nil, "", "", ""); err == nil {
		t.Fatal("expected error with nil address keyring")
	}
}
