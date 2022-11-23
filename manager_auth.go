package proton

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/ProtonMail/go-srp"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

var ErrInvalidProof = errors.New("unexpected server proof")

func (m *Manager) NewClient(uid, acc, ref string, exp time.Time) *Client {
	return newClient(m, uid).withAuth(acc, ref, exp)
}

func (m *Manager) NewClientWithRefresh(ctx context.Context, uid, ref string) (*Client, Auth, error) {
	c := newClient(m, uid)

	auth, err := m.authRefresh(ctx, uid, ref)
	if err != nil {
		return nil, Auth{}, err
	}

	return c.withAuth(auth.AccessToken, auth.RefreshToken, expiresIn(auth.ExpiresIn)), auth, nil
}

func (m *Manager) NewClientWithLogin(ctx context.Context, username string, password []byte) (*Client, Auth, error) {
	info, err := m.getAuthInfo(ctx, AuthInfoReq{Username: username})
	if err != nil {
		return nil, Auth{}, err
	}

	srpAuth, err := srp.NewAuth(info.Version, username, password, info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return nil, Auth{}, err
	}

	proofs, err := srpAuth.GenerateProofs(2048)
	if err != nil {
		return nil, Auth{}, err
	}

	auth, err := m.auth(ctx, AuthReq{
		Username:        username,
		ClientProof:     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		ClientEphemeral: base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		SRPSession:      info.SRPSession,
	})
	if err != nil {
		return nil, Auth{}, err
	}

	serverProof, err := base64.StdEncoding.DecodeString(auth.ServerProof)
	if err != nil {
		return nil, Auth{}, err
	}

	if m.verifyProofs {
		if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
			return nil, Auth{}, ErrInvalidProof
		}
	}

	return newClient(m, auth.UID).withAuth(auth.AccessToken, auth.RefreshToken, expiresIn(auth.ExpiresIn)), auth, nil
}

func (m *Manager) getAuthInfo(ctx context.Context, req AuthInfoReq) (AuthInfo, error) {
	var res struct {
		AuthInfo
	}

	if _, err := m.r(ctx).SetBody(req).SetResult(&res).Post("/core/v4/auth/info"); err != nil {
		return AuthInfo{}, err
	}

	return res.AuthInfo, nil
}

func (m *Manager) auth(ctx context.Context, req AuthReq) (Auth, error) {
	var res struct {
		Auth
	}

	if _, err := m.r(ctx).SetBody(req).SetResult(&res).Post("/core/v4/auth"); err != nil {
		return Auth{}, err
	}

	return res.Auth, nil
}

func (m *Manager) authRefresh(ctx context.Context, uid, ref string) (Auth, error) {
	state, err := crypto.RandomToken(32)
	if err != nil {
		return Auth{}, err
	}

	req := AuthRefreshReq{
		UID:          uid,
		RefreshToken: ref,
		ResponseType: "token",
		GrantType:    "refresh_token",
		RedirectURI:  "https://protonmail.ch",
		State:        string(state),
	}

	var res struct {
		Auth
	}

	if _, err := m.r(ctx).SetBody(req).SetResult(&res).Post("/core/v4/auth/refresh"); err != nil {
		return Auth{}, err
	}

	return res.Auth, nil
}

func expiresIn(seconds int) time.Time {
	return time.Now().Add(time.Duration(seconds) * time.Second)
}