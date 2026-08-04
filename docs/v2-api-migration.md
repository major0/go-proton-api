# Proton Drive API: v1 to v2 Migration Reference

Source: `open-proton-api.git/api/drive/` (protondrive-sdk-ts.json endpoint definitions)

---

## Summary

| Metric | V1 | V2 |
| ------ | -- | -- |
| Total endpoint operations | 111 | 69 (53 auth + 16 unauth/v2) |
| Share-based ops | 31 | 18 |
| Volume-based ops | 20 | 25 |
| HTTP GET | 39 | 20 |
| HTTP POST | 45 | 23 |
| HTTP PUT | 19 | 7 |
| HTTP DELETE | 8 | 3 |

The primary structural change: v1 roots file/folder CRUD under
`/drive/shares/{shareId}/`, v2 roots it under `/drive/v2/volumes/{volumeId}/`.

Photos-specific CRUD (create link, list album children, create album) is
absorbed by the generic v2 volume endpoints. Only photos domain-specific
metadata operations (tags, favorites, capture-time, albums batch ops)
remain as dedicated endpoints in v1.

---

## Endpoint Diff

### Lost: v1 endpoints with no v2 equivalent (70)

```text
DELETE /drive/photos/volumes/{volumeId}/albums/{linkId}
DELETE /drive/photos/volumes/{volumeId}/links/{linkId}/tags
DELETE /drive/shares/{shareId}
DELETE /drive/shares/{shareId}/trash
DELETE /drive/shares/{shareId}/urls/{shareUrlId}
DELETE /drive/volumes/{volumeId}/photos/share/{shareId}
GET    /drive/entitlements
GET    /drive/health/hash-check
GET    /drive/me/settings
GET    /drive/migrations/shareaccesswithnode/unmigrated
GET    /drive/organization/volumes
GET    /drive/organization/volumes/admin
GET    /drive/photos/albums/shared-with-me
GET    /drive/photos/migrate-legacy
GET    /drive/photos/volumes/{volumeId}/albums/{linkId}/children
GET    /drive/photos/volumes/{volumeId}/tags-migration
GET    /drive/sanitization/mhk
GET    /drive/shares/{shareId}
GET    /drive/shares/{shareId}/events/latest
GET    /drive/shares/{shareId}/files/{linkId}/revisions/{revisionId}/thumbnail
GET    /drive/shares/{shareId}/map
GET    /drive/shares/{shareId}/urls
GET    /drive/urls/{token}
GET    /drive/urls/{token}/files/{linkId}
GET    /drive/urls/{token}/info
GET    /drive/urls/{token}/links/{linkId}/path
GET    /drive/volumes
GET    /drive/volumes/{volumeId}
GET    /drive/volumes/{volumeId}/events/latest
GET    /drive/volumes/{volumeId}/folders/{linkId}/calculate-descendents-size
GET    /drive/volumes/{volumeId}/links/{linkId}/context
GET    /drive/volumes/{volumeId}/photos
GET    /drive/volumes/{volumeId}/urls
POST   /drive/blocks
POST   /drive/devices
POST   /drive/health/hash-check
POST   /drive/migrations/shareaccesswithnode
POST   /drive/organization/volumes
POST   /drive/photos/migrate-legacy
POST   /drive/photos/volumes
POST   /drive/photos/volumes/{volumeId}/albums
POST   /drive/photos/volumes/{volumeId}/albums/{linkId}/add-multiple
POST   /drive/photos/volumes/{volumeId}/albums/{linkId}/duplicates
POST   /drive/photos/volumes/{volumeId}/links/{linkId}/favorite
POST   /drive/photos/volumes/{volumeId}/links/{linkId}/tags
POST   /drive/photos/volumes/{volumeId}/tags-migration
POST   /drive/report/share
POST   /drive/report/url
POST   /drive/sanitization/mhk
POST   /drive/unauth/blocks
POST   /drive/unauth/report/share
POST   /drive/unauth/volumes/{volumeId}/thumbnails
POST   /drive/urls/{token}/auth
POST   /drive/urls/{token}/blocks
POST   /drive/urls/{token}/file
POST   /drive/urls/{token}/files/{linkId}/checkAvailableHashes
POST   /drive/urls/{token}/folders/{linkId}/delete_multiple
POST   /drive/urls/{token}/links/fetch_metadata
POST   /drive/volumes
POST   /drive/volumes/{volumeId}/links/fetch_metadata
POST   /drive/volumes/{volumeId}/links/{linkId}/copy
POST   /drive/volumes/{volumeId}/photos/duplicates
POST   /drive/volumes/{volumeId}/shares
POST   /drive/volumes/{volumeId}/thumbnails
PUT    /drive/devices/{deviceId}
PUT    /drive/me/settings
PUT    /drive/photos/volumes/{volumeId}/albums/{linkId}
PUT    /drive/photos/volumes/{volumeId}/links/transfer-multiple
PUT    /drive/photos/volumes/{volumeId}/links/{linkId}/capture-time
PUT    /drive/photos/volumes/{volumeId}/links/{linkId}/revisions/{revisionId}/xattr
PUT    /drive/photos/volumes/{volumeId}/recover-multiple
PUT    /drive/shares/{shareId}/editors-can-share
PUT    /drive/shares/{shareId}/urls/{shareUrlId}
PUT    /drive/volumes/{volumeId}/delete_locked
PUT    /drive/volumes/{volumeId}/links/move-multiple
PUT    /drive/volumes/{volumeId}/links/transfer-multiple
PUT    /drive/volumes/{volumeId}/restore
```

### Gained: v2 endpoints with no v1 equivalent (30)

```text
DELETE /drive/v2/shares/{shareId}/external-invitations/{invitationId}
DELETE /drive/v2/shares/{shareId}/invitations/{invitationId}
GET    /drive/v2/checklist/get-started
GET    /drive/v2/onboarding
GET    /drive/v2/onboarding/fresh-account
GET    /drive/v2/shared-bookmarks
GET    /drive/v2/sharedwithme
GET    /drive/v2/shares/external-invitations
GET    /drive/v2/shares/invitations
GET    /drive/v2/shares/invitations/{invitationId}
GET    /drive/v2/shares/my-files
GET    /drive/v2/shares/{shareId}/members
GET    /drive/v2/user-link-access
POST   /drive/v2/checklist/get-started/seen-completed-list
POST   /drive/v2/onboarding/fresh-account
POST   /drive/v2/shares/invitations/{invitationId}/accept
POST   /drive/v2/shares/invitations/{invitationId}/reject
POST   /drive/v2/shares/{shareId}/external-invitations
POST   /drive/v2/shares/{shareId}/external-invitations/{invitationId}/sendemail
POST   /drive/v2/shares/{shareId}/invitations
POST   /drive/v2/shares/{shareId}/invitations/{invitationId}/sendemail
POST   /drive/v2/urls/{token}/bookmark
POST   /drive/v2/volumes/{volumeId}/delete_multiple
POST   /drive/v2/volumes/{volumeId}/files/small
POST   /drive/v2/volumes/{volumeId}/files/{linkId}/revisions/small
POST   /drive/v2/volumes/{volumeId}/remove-mine
POST   /drive/v2/volumes/{volumeId}/trash_multiple
PUT    /drive/v2/shares/{shareId}/external-invitations/{invitationId}
PUT    /drive/v2/shares/{shareId}/invitations/{invitationId}
PUT    /drive/v2/shares/{shareId}/members/{memberId}
```

### Common: operations present in both v1 and v2 (23)

Normalized by stripping the path prefix; the suffix is identical.

| Operation suffix | V1 path(s) | V2 path(s) |
| --------------- | ----------- | ----------- |
| `DELETE files/{linkId}/revisions/{revisionId}` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET devices` | `/drive/devices` | `/drive/v2/devices` |
| `GET events/{eventId}` | `/drive/shares/{shareId}/...`, `/drive/volumes/{volumeId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET files/{linkId}/revisions` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET files/{linkId}/revisions/{revisionId}` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET folders/{linkId}/children` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET links/{linkId}/revisions/{revisionId}/verification` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET photos` | `/drive/volumes/{volumeId}/photos` | `/drive/v2/shares/photos` |
| `GET shares` | `/drive/shares` | `/drive/v2/volumes/{volumeId}/shares` |
| `GET trash` | `/drive/shares/{shareId}/...`, `/drive/volumes/{volumeId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST documents` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST files` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST files/{linkId}/revisions` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST files/{linkId}/revisions/{revisionId}/restore` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST folders` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST links` | `/drive/photos/volumes/{volumeId}/links` | `/drive/v2/volumes/{volumeId}/links` |
| `POST links/{linkId}/checkAvailableHashes` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST security` | `/drive/urls/{token}/security` | `/drive/v2/shares/{shareId}/security` |
| `POST trash/delete_multiple` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT files/{linkId}/revisions/{revisionId}` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT links/{linkId}/move` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT links/{linkId}/rename` | `/drive/shares/{shareId}/...`, `/drive/urls/{token}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT trash/restore_multiple` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |

---

## Wire Compatibility

### 100% Compatible (12 operations)

These operations have identical request/response definitions between v1
and v2. Only the path prefix changes (swap `shares/{shareId}` for
`volumes/{volumeId}` and add `/v2/`). No field renames, no structural
changes, no new query parameters.

| Operation | V1 path | V2 path |
| --------- | ------- | ------- |
| `DELETE files/{linkId}/revisions/{revisionId}` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET files/{linkId}/revisions/{revisionId}` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `GET links/{linkId}/revisions/{revisionId}/verification` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST documents` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST files` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST files/{linkId}/revisions` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST files/{linkId}/revisions/{revisionId}/restore` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST links` | `/drive/photos/volumes/{volumeId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `POST trash/delete_multiple` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT files/{linkId}/revisions/{revisionId}` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT links/{linkId}/rename` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |
| `PUT trash/restore_multiple` | `/drive/shares/{shareId}/...` | `/drive/v2/volumes/{volumeId}/...` |

For these 12 operations, migration is mechanical: replace the path
prefix and supply `volumeId` instead of `shareId`. The request body,
query parameters, and response shape are unchanged.

### Incompatible (11 operations)

These operations share a functional suffix but have breaking changes in
their request or response definitions.

| Operation | Change description |
| --------- | ------------------ |
| `GET devices` | Response `Devices` object has different structure |
| `GET events/{eventId}` | `More`/`Refresh` changed from integer (0\|1) to boolean; `Events` sub-object restructured (nested `Link{}` with `IsShared`/`IsTrashed`/`ParentLinkID`); new fields `ConvertibleExternalInvitations`, `DisableSdkQuotaChecks` |
| `GET files/{linkId}/revisions` | Response adds `Revisions` array with full revision objects (v1 returned only `Code`) |
| `GET folders/{linkId}/children` | Query params: v1 `ShowAll` replaced by v2 `AnchorID` + `FoldersOnly`; response: v1 returns inline Link objects, v2 returns `LinkIDs` + `AnchorID` + `More` (cursor pagination) |
| `GET photos` | Completely different: v1 returns paginated photo links, v2 returns Volume + Share + root Link bootstrap object |
| `GET shares` | Query params: v1 `AddressID`/`ShowAll`/`ShareType` replaced by v2 `AnchorID`; response: v2 adds `Links`, `More`, `AnchorID` (cursor pagination) |
| `GET trash` | Query params: v2 adds `Page`/`PageSize`; response field renamed `Trash` -> `TrashedLinkIDs` |
| `POST folders` | Request field renamed: `SignatureAddress` -> `SignatureEmail` |
| `POST links/{linkId}/checkAvailableHashes` | Request adds required `Hashes` field (v1 only had `ClientUID`) |
| `POST security` | Path moved from `/urls/{token}/security` to `/shares/{shareId}/security`; request adds `Hashes` field |
| `PUT links/{linkId}/move` | Request removes `NewShareID` and `SignatureAddress` (no longer needed when moves are volume-scoped; `SignatureAddress` replaced by `SignatureEmail` elsewhere) |

---

## Behavioral Changes

| Aspect | V1 | V2 |
| ------ | -- | -- |
| Pagination (children) | Offset: `Page`/`PageSize` | Cursor: `AnchorID`/`More` boolean |
| Pagination (trash) | Offset: `Page`/`PageSize` | Offset: `Page`/`PageSize` (unchanged) |
| Children response | Full Link objects inline | `LinkIDs` array (fetch details via `POST links`) |
| Events `More`/`Refresh` | Integer `0`\|`1` | Boolean `true`\|`false` |
| Events Link info | Flat: `LinkID`, `ContextShareID`, `FromContextShareID` | Nested `Link{}`: `LinkID`, `ParentLinkID`, `IsShared`, `IsTrashed` |
| Events extra fields | `CreateTime`, `UrlID`, `DeletedURLID`, `FLAG_RESTORE_*`, `FromParentLinkID` | `ConvertibleExternalInvitations`, `DisableSdkQuotaChecks` |
| Batch link fetch | `POST shares/{shareId}/links/fetch_metadata` (body: `LinkIDs` + `Thumbnails`) | `POST volumes/{volumeId}/links` (body: `LinkIDs` only) |
| Small file upload | Not available | `POST volumes/{volumeId}/files/small` with 409 conflict details |
| Unauth mirror | Minimal: blocks, thumbnails, report | Full volume CRUD under `/unauth/v2/volumes/{volumeId}/` (16 ops) |

---

## New Domains in V2

### Sharing and Collaboration (15 endpoints)

Full invitation lifecycle for internal and external (non-Proton) users:

- `POST /v2/shares/{shareId}/invitations` — invite user
- `GET /v2/shares/invitations` — list pending invitations
- `GET /v2/shares/invitations/{invitationId}` — get invitation
- `PUT /v2/shares/{shareId}/invitations/{invitationId}` — update invitation
- `DELETE /v2/shares/{shareId}/invitations/{invitationId}` — revoke invitation
- `POST /v2/shares/invitations/{invitationId}/accept` — accept
- `POST /v2/shares/invitations/{invitationId}/reject` — reject
- `POST /v2/shares/{shareId}/invitations/{invitationId}/sendemail` — resend
- External invitations: same CRUD pattern under `external-invitations/`
- `GET /v2/shares/{shareId}/members` — list members
- `PUT /v2/shares/{shareId}/members/{memberId}` — update member permissions

Permissions model uses integer enum: `4` (viewer), `6` (editor), `22` (admin).

### Discovery and Bootstrap (5 endpoints)

- `GET /v2/shares/my-files` — returns Volume + Share + root Link in one call
- `GET /v2/shares/photos` — same pattern for photos share
- `GET /v2/sharedwithme` — paginated list of shares the user has access to
- `GET /v2/shared-bookmarks` — saved/bookmarked shared links
- `GET /v2/user-link-access` — context-aware access check (invitations + shares)

### Onboarding (3 endpoints)

- `GET /v2/onboarding`
- `GET /v2/onboarding/fresh-account`
- `POST /v2/onboarding/fresh-account`

### Checklist (2 endpoints)

- `GET /v2/checklist/get-started`
- `POST /v2/checklist/get-started/seen-completed-list`

---

## Migration Path: Share-Based to Volume-Based

The key addressing change for migrating a v1 client:

```text
V1: /drive/shares/{shareId}/files/{linkId}/revisions
V2: /drive/v2/volumes/{volumeId}/files/{linkId}/revisions
```

The caller must know the `volumeId` instead of (or in addition to) the
`shareId`. The bootstrap endpoint `GET /v2/shares/my-files` provides
both `VolumeID` and `ShareID` in a single call.

For operations that previously required a `shareId` path parameter, v2
moves the addressing to `volumeId`. The server resolves the appropriate
share context internalI think this spec should likely only cover phase 1, whichly.

### Batch Operations Consolidation

V1 had folder-scoped batch operations:

```text
POST /drive/shares/{shareId}/folders/{linkId}/delete_multiple
POST /drive/shares/{shareId}/folders/{linkId}/trash_multiple
```

V2 replaces these with volume-scoped equivalents:

```text
POST /drive/v2/volumes/{volumeId}/delete_multiple
POST /drive/v2/volumes/{volumeId}/trash_multiple
```

The v2 variants accept a list of LinkIDs in the body rather than
scoping to a specific parent folder.

---

## Unauth/V2 Mirror (16 endpoints)

V2 provides a full unauthenticated mirror of core volume CRUD at
`/drive/unauth/v2/volumes/{volumeId}/...`:

```text
DELETE /drive/unauth/v2/volumes/{volumeId}/files/{linkId}/revisions/{revisionId}
GET    /drive/unauth/v2/volumes/{volumeId}/files/{linkId}/revisions/{revisionId}
GET    /drive/unauth/v2/volumes/{volumeId}/folders/{linkId}/children
GET    /drive/unauth/v2/volumes/{volumeId}/links/{linkId}/revisions/{revisionId}/verification
POST   /drive/unauth/v2/volumes/{volumeId}/delete_multiple
POST   /drive/unauth/v2/volumes/{volumeId}/documents
POST   /drive/unauth/v2/volumes/{volumeId}/files
POST   /drive/unauth/v2/volumes/{volumeId}/files/small
POST   /drive/unauth/v2/volumes/{volumeId}/files/{linkId}/revisions
POST   /drive/unauth/v2/volumes/{volumeId}/files/{linkId}/revisions/small
POST   /drive/unauth/v2/volumes/{volumeId}/folders
POST   /drive/unauth/v2/volumes/{volumeId}/links
POST   /drive/unauth/v2/volumes/{volumeId}/links/{linkId}/checkAvailableHashes
POST   /drive/unauth/v2/volumes/{volumeId}/remove-mine
PUT    /drive/unauth/v2/volumes/{volumeId}/files/{linkId}/revisions/{revisionId}
PUT    /drive/unauth/v2/volumes/{volumeId}/links/{linkId}/rename
```

These support public sharing scenarios where the caller authenticates via
a share URL token rather than a session.
