package crypto

import (
	"testing"
)

func TestEncryptDecryptEventField_RoundTrip(t *testing.T) {
	calKR := genKeyRing(t, "cal", "cal@proton.me")
	addrKR := genKeyRing(t, "addr", "addr@proton.me")

	cases := []string{"", "Team sync", "Café ☕ meeting — room 3"}
	for _, want := range cases {
		enc, err := EncryptEventField(want, calKR, addrKR)
		if err != nil {
			t.Fatalf("encrypt %q: %v", want, err)
		}
		got, err := DecryptEventField(enc, calKR, addrKR)
		if err != nil {
			t.Fatalf("decrypt %q: %v", want, err)
		}
		if got != want {
			t.Fatalf("round trip mismatch: got %q want %q", got, want)
		}
	}
}

func TestDecryptEventField_WrongKey(t *testing.T) {
	calKR := genKeyRing(t, "cal", "cal@proton.me")
	addrKR := genKeyRing(t, "addr", "addr@proton.me")
	otherKR := genKeyRing(t, "other", "other@proton.me")

	enc, err := EncryptEventField("secret", calKR, addrKR)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// A keyring that is not the encryption target cannot decrypt.
	if _, err := DecryptEventField(enc, otherKR, addrKR); err == nil {
		t.Fatal("expected error decrypting with wrong calendar keyring")
	}
}

func TestEncryptEventField_NilKeyRing(t *testing.T) {
	if _, err := EncryptEventField("data", nil, nil); err == nil {
		t.Fatal("expected error with nil calendar keyring")
	}
}

func TestDecryptEventField_NilKeyRing(t *testing.T) {
	if _, err := DecryptEventField("data", nil, nil); err == nil {
		t.Fatal("expected error with nil calendar keyring")
	}
}

func TestDecryptEventField_Malformed(t *testing.T) {
	calKR := genKeyRing(t, "cal", "cal@proton.me")
	if _, err := DecryptEventField("not-a-pgp-message", calKR, nil); err == nil {
		t.Fatal("expected error decrypting malformed input")
	}
}
