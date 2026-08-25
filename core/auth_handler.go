package core

import "context"

// AuthHandler receives authentication lifecycle events from a [Session].
// Consumers implement this interface to persist token updates, react to
// session conversions, and handle irrecoverable authentication failures.
//
// All methods must be safe for concurrent invocation from multiple goroutines.
type AuthHandler interface {
	// OnTokenRefresh is called after a service session's token has been
	// successfully refreshed. The consumer should persist the new tokens
	// (e.g., to an OS keyring or encrypted file) so they survive process
	// restarts. The service parameter identifies which forked session was
	// refreshed (e.g., "drive", "mail").
	//
	// If persistence fails, the error is logged but the session continues
	// operating with the new tokens in memory.
	OnTokenRefresh(ctx context.Context, service string, data SessionData) error

	// OnSessionConverted is called after the top-level session converts from
	// Bearer to Cookie authentication. All previous Bearer forks are now
	// invalid. The consumer should clear any previously stored Bearer
	// credentials and persist the new session tree.
	OnSessionConverted(ctx context.Context, tree SessionTree) error

	// OnDeauth is called when the session is irrecoverably invalid — the
	// refresh token has expired, the account is locked, or the server has
	// rejected the refresh attempt. The consumer should clear all stored
	// credentials and prompt the user to re-authenticate.
	OnDeauth(ctx context.Context, err error)
}
