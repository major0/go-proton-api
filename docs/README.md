# go-proton-api v2 Architecture

This directory documents the architecture, design decisions, and future
direction of the go-proton-api v2 multi-module SDK.

## Documents

| Document                                   | Purpose                                              |
| ------------------------------------------ | ---------------------------------------------------- |
| [architecture.md](architecture.md)         | Multi-module layout, layering, package structure     |
| [session-auth.md](session-auth.md)         | Session types, Bearer/Cookie, forking, conversion    |
| [transport.md](transport.md)               | Connection pool, retry logic, 2xx handling           |
| [token-refresh.md](token-refresh.md)       | Refresh responsibility split, consumer-driven model  |
| [encryption.md](encryption.md)             | E2E encryption model, keyring chains, field mapping  |
| [generation.md](generation.md)             | OpenAPI code generation pipeline, Makefile, tags     |
| [branch-workflow.md](branch-workflow.md)   | Topic branch structure, dependency chain             |
| [future-direction.md](future-direction.md) | Evolution path, spec improvements, deprecation plan  |

## Goals

1. **Complete Proton platform SDK** — not just Drive, but Mail, Calendar,
   Contacts, Meet, VPN, Lumo, Domains, and Core (auth/session)
2. **Stable public API** — consumers work with plaintext domain types;
   internal layers absorb spec changes silently
3. **Independent versioning** — each service is its own Go module with
   independent semver tags
4. **Legacy compatibility** — root module maintains backward compat with
   upstream go-proton-api
5. **Proposable upstream** — each topic branch is isolated and based on
   upstream/master, suitable for independent PR submission

## Reference Implementation

The session/auth model implementation in `proton-utils.git` is the primary
Go reference for Proton's auth flows. It may be the only open-source Go
implementation of the Bearer/Cookie session forking model.
