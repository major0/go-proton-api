# Branch Workflow

## Dependency Chain

```text
upstream/master
  └── feat/pre-commit                     (.pre-commit-config.yaml)
        └── docs/proton-api-v2            (this documentation)
              └── feat/proton-core-api-v2  (core session/transport)
                    ├── feat/proton-drive-api-v2
                    ├── feat/proton-mail-api-v2
                    ├── feat/proton-calendar-api-v2
                    ├── feat/proton-contacts-api-v2
                    ├── feat/proton-meet-api-v2
                    ├── feat/proton-vpn-api-v2
                    ├── feat/proton-lumo-api-v2
                    └── feat/proton-domains-api-v2
```

## Rules

1. **Strictly sequential** — one branch at a time in the working directory.
   Never parallel sub-agents on different branches.
2. **Core first** — always update core before product branches.
3. **Each topic branch is isolated** — proposable upstream independently.
4. **Rebase, not merge** — `git pull` autorebases against upstream tracking.
5. **Conventional commits** — every commit uses conventional format.
6. **Pre-commit hooks** — formatting, linting, conventional commit validation.

## Updating All Branches

When core changes (new spec, transport fix, etc.):

1. Update core branch
2. Switch to each product branch sequentially
3. `git pull` (autorebases)
4. `make <service>` (regenerate if needed)
5. Verify build
6. Commit if changed

## Adding a New Service

1. Create branch: `feat/proton-<service>-api-v2` based on core
2. Add make target for the service
3. Create `<service>/internal/generated/` + `<service>/go.mod`
4. Generate: `make <service>`
5. Add public layer with encrypt/decrypt
6. Commit
