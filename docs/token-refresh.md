# Token Refresh

## Responsibility Split

### Consumer's Job (via SessionStore/AuthHandler)

- Track token expiration timers
- Proactively refresh before expiry
- Persist new tokens after refresh
- Decide refresh strategy (timer, lazy, on-demand)

### Core's Job

- Accept new tokens from consumer (hot-swap, no disruption)
- Handle reactive case (401 → attempt refresh if consumer hasn't)
- Provide thread-safe entry point for consumer to push tokens
- NEVER proactively refresh — no timers, no expiry tracking

## Consumer Pushes Tokens

```go
// Consumer refreshed proactively — push into live session
session.UpdateTokens(ctx, "drive", newSessionData)

// Update primary session
session.UpdatePrimaryTokens(ctx, newSessionData)
```

## Race Handling

If a 401 triggers Core's reactive refresh at the same moment consumer pushes:

- First write wins (mutex-protected)
- Consumer is authoritative — their push overwrites Core's refresh
- No double-refresh, no invalidation cascade

## AuthHandler

```go
type AuthHandler interface {
    OnTokenRefresh(ctx context.Context, service string, data SessionData) error
    OnSessionConverted(ctx context.Context, tree SessionTree) error
    OnDeauth(ctx context.Context, err error)
}
```

- `OnTokenRefresh` — token refreshed (by Core reactively or by consumer push)
- `OnSessionConverted` — Bearer→Cookie conversion happened
- `OnDeauth` — irrecoverable failure, consumer must re-login

## Design Principle

Core is reactive, never proactive. The consumer drives the refresh schedule.
Core gracefully accepts whatever tokens it's given. If tokens expire before
the consumer refreshes, Core handles the resulting 401 reactively.
