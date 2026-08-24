# Proton API client generation
#
# Each service declares its own target. Adding a new service is just
# adding a new generate-<service> target with its tags.
#
# Usage:
#   make all        # generate all packages
#   make core       # generate core package only
#   make generate PACKAGE=core TAGS="account,auth,..."  # generic

SPEC := $(lastword $(sort $(wildcard ../open-proton-api.git/output/proton-full-api-*.json)))
OAPI := github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0

.PHONY: generate all core

all: core

# Generic target: make generate PACKAGE=foo TAGS="tag1,tag2"
# Output: $(PACKAGE)/internal/generated/types.gen.go
# Output: $(PACKAGE)/internal/generated/client.gen.go
generate:
	@test -n "$(PACKAGE)" || { echo "error: PACKAGE is required" >&2; exit 1; }
	@test -n "$(TAGS)" || { echo "error: TAGS is required" >&2; exit 1; }
	@test -n "$(SPEC)" || { echo "error: no proton-full-api spec found" >&2; exit 1; }
	@mkdir -p $(PACKAGE)/internal/generated
	go run $(OAPI) --package $(PACKAGE)api --generate types --include-tags $(TAGS) -o $(PACKAGE)/internal/generated/types.gen.go $(SPEC)
	go run $(OAPI) --package $(PACKAGE)api --generate client --include-tags $(TAGS) -o $(PACKAGE)/internal/generated/client.gen.go $(SPEC)

# Core: account, auth, oauth, core platform, permissions
core:
	$(MAKE) generate PACKAGE=core TAGS="account,auth,oauth,core,permissions,groups,members"
