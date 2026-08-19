# Session Auth Model

Proton uses a tree of forked sessions. Each service operates with its own
auth context (own tokens), forked from a top-level session.

Reference implementation: `proton-utils.git`

## Session Types

| Type   | Mechanism                       | Notes                  |
| ------ | ------------------------------- | ---------------------- |
| Bearer | `Authorization: Bearer <token>` | Default after login    |
| Cookie | HTTP cookies (set by server)    | Required for Lumo/AI   |

## Session Lifecycle

```text
Login → BearerSession (top-level)
  ├── Fork → ServiceBearerSession (drive)     ← Bearer stays valid
  ├── Fork → ServiceBearerSession (mail)
  │
  └── ConvertToCookie → INVALIDATES Bearer + all Bearer forks
        ├── Fork → ServiceCookieSession (drive)
        ├── Fork → ServiceCookieSession (mail)
        └── Fork → ServiceCookieSession (lumo)  ← REQUIRES Cookie
```

## Rules

- Login always produces a Bearer session
- Services fork from the top-level (Bearer or Cookie)
- Converting Bearer → Cookie is ONE-WAY — kills Bearer and all its forks
- Lumo/AI REQUIRES Cookie auth — Bearer is rejected
- Each forked service session has its own token pair (independently refreshable)

## Consumer Paths

### Without Lumo (simpler)

```go
session, _ := core.Login(ctx, host, user, pass)
drive := session.Fork("drive")
mail := session.Fork("mail")
```

### With Lumo (requires conversion)

```go
session, _ := core.Login(ctx, host, user, pass)
session.ConvertToCookie(ctx)  // one-way, kills Bearer
drive := session.Fork("drive")
lumo := session.Fork("lumo")
```

## Per-Service Session

Each forked session:

- Has its own access/refresh token pair
- Injects its own User-Agent header per-request
- Refreshes independently (one service's 401 doesn't affect others)
- Shares TCP connections with other services (same host)

## Session Tree

What gets persisted across process restarts:

```go
type SessionTree struct {
    Primary  SessionData
    Services map[string]SessionData
}

type SessionData struct {
    Type         SessionType  // Bearer or Cookie
    UID          string
    AccessToken  string
    RefreshToken string
}
```

## Resume

```go
tree := store.Load()
session, _ := core.Resume(ctx, host, tree,
    core.WithAuthHandler(store),
)
drive := session.Service("drive")  // restored, uses stored tokens
```
