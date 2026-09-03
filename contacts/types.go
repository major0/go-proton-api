package contacts

// CardType identifies how a contact card's vCard payload is protected on the
// wire. Proton stores each contact as one or more cards, each at a distinct
// protection level.
type CardType int

const (
	// CardCleartext is an unencrypted, unsigned vCard payload.
	CardCleartext CardType = iota
	// CardSigned is a cleartext vCard payload accompanied by a detached
	// signature that authenticates its contents.
	CardSigned
	// CardEncryptedAndSigned is a PGP-encrypted vCard payload accompanied by a
	// detached signature over the plaintext.
	CardEncryptedAndSigned
)

// Card is a single contact card. Data holds the plaintext vCard once decrypted
// (for CardCleartext and CardSigned it is already plaintext on the wire; for
// CardEncryptedAndSigned it is the decrypted result). Signature holds the
// armored detached signature for signed cards.
type Card struct {
	// Type is the protection level of this card.
	Type CardType
	// Data is the plaintext vCard payload.
	Data string
	// Signature is the armored detached signature, empty for CardCleartext.
	Signature string
}

// Contact is a decrypted Proton contact. All fields are plaintext — the client
// decrypts card payloads before populating this type.
type Contact struct {
	// ID is the upstream contact identifier.
	ID string
	// Name is the plaintext display name of the contact.
	Name string
	// Emails are the plaintext email addresses associated with the contact.
	Emails []string
	// Cards are the contact's protected vCard entries.
	Cards []Card
}

// CreateContactReq is the plaintext request to create a contact. The client
// encrypts and signs the cards before sending them to the API.
type CreateContactReq struct {
	// Name is the plaintext display name for the new contact.
	Name string
	// Emails are the plaintext email addresses for the new contact.
	Emails []string
	// Cards are the plaintext vCard entries to protect and store.
	Cards []Card
}
