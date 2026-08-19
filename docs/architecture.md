# Architecture

## Multi-Module Layout

```text
go-proton-api/
  go.mod                     ← root module: legacy API (backward compat)
  client.go                  ← legacy Client struct (unchanged)
  link_file.go, etc.         ← legacy methods (unchanged)

  core/
    go.mod                   ← module: github.com/.../go-proton-api/core
    session.go               ← Session type, auth, transport
    internal/
      generated/             ← oapi-codegen output (NOT exported)

  drive/
    go.mod                   ← module: github.com/.../go-proton-api/drive
    client.go                ← public: encrypt → call → decrypt
    types.go                 ← public domain types (plaintext-facing)
    internal/
      generated/             ← oapi-codegen output (NOT exported)
      crypto/                ← encryption/decryption helpers (NOT exported)

  mail/
    go.mod                   ← module: github.com/.../go-proton-api/mail
    ...
  calendar/, contacts/, meet/, vpn/, lumo/, domains/
    ...
```

## Layering

```text
Consumer
  │
  ▼
Public API (plaintext types, encrypt → call → decrypt)
  │                           ▲
  ▼                           │
internal/crypto/              │  (service-specific encryption)
  │                           │
  ▼                           │
internal/generated/  ─────────┘  (oapi-codegen wire types + client)
  │
  ▼
HTTP (via Core session's shared transport)
```

### Layer Responsibilities

| Layer              | Visibility  | Responsibility                                        |
| ------------------ | ----------- | ----------------------------------------------------- |
| Public API         | Exported    | Domain types, encrypt/decrypt, consumer interface     |
| internal/crypto/   | Internal    | Keyring derivation, field encrypt/decrypt, signatures |
| internal/generated | Internal    | Raw HTTP client, wire types (all `*string`)           |
| Core transport     | Via Session | Connection pool, retry, auth headers, token refresh   |

## Dependencies

```text
core        ← no service deps (std + oapi-codegen runtime + crypto)
drive       ← depends on core
mail        ← depends on core
calendar    ← depends on core
...all services depend on core
```

Root module does NOT import sub-modules (no circular deps).

## Versioning

Independent semver per module:

- `core/v1.0.0`
- `drive/v0.1.0`
- `mail/v0.1.0`

Consumers import only what they need:

```go
import (
    "github.com/.../go-proton-api/core"
    "github.com/.../go-proton-api/drive"
)
```
