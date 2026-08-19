# Encryption Model

All Proton services use end-to-end encryption. The API transports ciphertext —
the server never sees plaintext content.

## The Problem

The generated API client (oapi-codegen) produces wire types where every
encrypted field is `*string`. There's no type-level distinction between:

- Encrypted fields (Name, NodePassphrase, XAttr)
- Signed fields (ManifestSignature)
- Plaintext fields (MIMEType, SignatureAddress)
- Identifiers (LinkID, ShareID)

## Our Solution

The public API layer accepts/returns plaintext domain types. Encryption
is handled internally:

```text
Consumer passes plaintext → Public layer encrypts → Generated client sends ciphertext
Generated client receives ciphertext → Internal layer decrypts → Consumer gets plaintext
```

### Example: CreateFile

```go
// Consumer sees this:
file, _ := driveClient.CreateFile(ctx, volumeID, drive.CreateFileReq{
    ParentLinkID: parentID,
    Name:         "my-document.txt",  // plaintext
    MIMEType:     "text/plain",       // plaintext
})

// Internally:
// 1. Derive parent's NodeKey from keyring chain
// 2. Encrypt "my-document.txt" with parent NodeKey → ciphertext
// 3. Compute name hash
// 4. Call generated client with encrypted fields
// 5. Return result with plaintext ID
```

## Keyring Chains (Drive)

```text
Share Key (from share passphrase, unlocked by address key)
  └── Root Link NodeKey (encrypted by share key)
        └── Child Link NodeKey (encrypted by parent NodeKey)
              └── File Content Key (encrypted by file NodeKey)
```

Each level decrypts the next. The full chain must be walked to access content.

## Encrypted Struct Fields (XAttr example)

Some fields decrypt into structured data:

```go
// On the wire: XAttr is an encrypted base64 string
// Decrypted: it's JSON that unmarshals into:
type XAttr struct {
    Common XAttrCommon
}

type XAttrCommon struct {
    ModificationTime int64
    Size             int64
    BlockSizes       []int64
    Digests          map[string]string
}
```

## Per-Service Crypto

Each service has its own encryption patterns in `<service>/internal/crypto/`:

- Drive: keyring chains, name encryption, XAttr, block verification
- Mail: PGP message encryption, attachment encryption
- Calendar: event encryption, attendee key sharing
- Contacts: vCard field encryption

## Future: Spec Annotations

If `open-proton-api` adds `x-proton-encrypted` annotations to the spec,
generation could produce typed fields (`EncryptedName` instead of `*string`).
The internal crypto layer would shrink but the public API stays identical.
