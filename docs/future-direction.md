# Future Direction

## Short Term

- Complete multi-module restructure (move from internal/openapi-client/ to <service>/)
- Implement Core session with full Bearer/Cookie/Fork model
- Implement Drive public layer with encryption
- Migrate proton-utils session handling to Core AuthHandler

## Medium Term

- Implement public layers for remaining services (mail, calendar, etc.)
- Absorb legacy root module interfaces into core + drive sub-modules
- Deprecate legacy root module paths
- Tag initial releases: core/v1.0.0, drive/v0.1.0, etc.

## Long Term

- Annotate open-proton-api spec with crypto metadata (`x-proton-encrypted`)
- Generate typed crypto fields instead of `*string`
- Shrink internal/crypto/ as spec captures more semantics
- Public API stays identical — consumers never notice internal improvements
- Eventually remove legacy root module entirely

## Stable Public API Principle

The public types are the stable contract:

- They define what consumers see
- They never change because the spec changed
- Internal layers absorb improvements silently
- The mapping between wire ↔ domain is where change happens

## Spec Improvement Absorption

```text
Today:        *string everywhere → hand-written crypto layer → domain types
Future:       typed crypto fields → thinner crypto layer → same domain types
Eventually:   rich generated types → minimal glue → same domain types
```

The architecture is designed so that each layer can thin out independently
without affecting the layers above it.
