# Code Generation Pipeline

## Source

All generated code comes from the `open-proton-api.git` repository which
produces OpenAPI 3.1 specs from multiple Proton SDK sources.

Single input: `proton-full-api-*.json` (combined spec with all services)

## Tool

`oapi-codegen` v2.8.0 — generates typed Go clients from OpenAPI specs.

## Tag-Based Splitting

Each service is extracted from the full spec using `--include-tags`:

| Package  | Tags                                                                         |
| -------- | ---------------------------------------------------------------------------- |
| core     | account,auth,oauth,core,permissions,groups,members                           |
| drive    | shares,volumes,blocks,devices,photos,urls,unauth,...                         |
| mail     | messages,conversations,attachments,filters,eo,...                            |
| calendar | booking,events,invitations,keys,members,subscription,urls,videoconferences   |
| contacts | contacts,emails                                                              |
| meet     | meetings                                                                     |
| vpn      | business,config,logicals                                                     |
| lumo     | ai                                                                           |
| domains  | domains                                                                      |

## Makefile

```makefile
SPEC := $(lastword $(sort $(wildcard ../open-proton-api.git/output/proton-full-api-*.json)))
OAPI := github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0

generate:
    go run $(OAPI) --package $(PACKAGE)api --generate types --include-tags $(TAGS) \
        -o $(PACKAGE)/internal/generated/types.gen.go $(SPEC)
    go run $(OAPI) --package $(PACKAGE)api --generate client --include-tags $(TAGS) \
        -o $(PACKAGE)/internal/generated/client.gen.go $(SPEC)
```

Each service adds its own make target. `make all` generates everything.

## Output

Per service:

- `<service>/internal/generated/types.gen.go` — request/response structs
- `<service>/internal/generated/client.gen.go` — `ClientWithResponses` + methods

## No Post-Processing

The spec must be clean — no sed/awk fixups after generation. Field collisions
(camelCase/PascalCase duplicates) are fixed upstream in `open-proton-api.git`.

## Regeneration

When `open-proton-api.git` publishes a new spec version:

1. The Makefile glob picks up the latest version automatically
2. `make all` regenerates everything
3. If it compiles clean → commit
4. If it doesn't → fix upstream, don't post-process
