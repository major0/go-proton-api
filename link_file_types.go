package proton

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

/* Helper function */
func getEncryptedName(name string, addrKR, nodeKR *crypto.KeyRing) (string, error) {
	clearTextName := crypto.NewPlainMessageFromString(name)

	encName, err := nodeKR.Encrypt(clearTextName, addrKR)
	if err != nil {
		return "", err
	}

	encNameString, err := encName.GetArmored()
	if err != nil {
		return "", err
	}

	return encNameString, nil
}

func GetNameHash(name string, hashKey []byte) (string, error) {
	mac := hmac.New(sha256.New, hashKey)
	_, err := mac.Write([]byte(name))
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

type CreateFileReq struct {
	ParentLinkID string

	Name     string // Encrypted File Name
	Hash     string // Encrypted content hash
	MIMEType string // MIME Type

	ContentKeyPacket          string // The block's key packet, encrypted with the node key.
	ContentKeyPacketSignature string // Unencrypted signature of the content session key, signed with the NodeKey

	NodeKey                 string // The private NodeKey, used to decrypt any file/folder content.
	NodePassphrase          string // The passphrase used to unlock the NodeKey, encrypted by the owning Link/Share keyring.
	NodePassphraseSignature string // The signature of the NodePassphrase

	SignatureAddress string // Signature email address used to sign passphrase and name
}

type CreateFileRes struct {
	ID         string // Encrypted Link ID
	RevisionID string // Encrypted Revision ID
}

type UpdateRevisionReq struct {
	BlockList         []BlockToken
	State             RevisionState
	ManifestSignature string
	SignatureAddress  string
  XAttr             string
}

type RevisionXAttrCommon struct {
	ModificationTime string
	Size             int64
	BlockSizes       []int64
	Digests          map[string]string
}

type RevisionXAttr struct {
	Common RevisionXAttrCommon
}

func (updateRevisionReq *UpdateRevisionReq) SetEncXAttrString(addrKR, nodeKR *crypto.KeyRing, xAttrCommon *RevisionXAttrCommon) error {
	// Source
	// - https://github.com/ProtonMail/WebClients/blob/099a2451b51dea38b5f0e07ec3b8fcce07a88303/packages/shared/lib/interfaces/drive/link.ts#L53
	// - https://github.com/ProtonMail/WebClients/blob/main/applications/drive/src/app/store/_links/extendedAttributes.ts#L139
	// XAttr has following JSON structure encrypted by node key:
	// {
	//    Common: {
	//        ModificationTime: "2021-09-16T07:40:54+0000",
	//        Size: 13283,
	// 		  BlockSizes: [1,2,3],
	//        Digests: "sha1 string"
	//    },
	// }

	jsonByteArr, err := json.Marshal(RevisionXAttr{
		Common: *xAttrCommon,
	})
	if err != nil {
		return err
	}

	encXattr, err := nodeKR.Encrypt(crypto.NewPlainMessage(jsonByteArr), addrKR)
	if err != nil {
		return err
	}

	encXattrString, err := encXattr.GetArmored()
	if err != nil {
		return err
	}

	updateRevisionReq.XAttr = encXattrString
	return nil
}

type BlockToken struct {
	Index int
	Token string
}
