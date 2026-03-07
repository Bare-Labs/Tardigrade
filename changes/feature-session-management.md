# Feature: Session Management

**Branch:** `feat/session-management`
**Version:** 0.9.0
**Status:** done

## Scope

Implement Phase 0.2 from PLAN.md: session token issuance, in-memory session storage, device session tracking, and revocation support. Integrate into the edge gateway with REST endpoints and session-based auth fallback.

## Files Changed

- `src/http/session.zig` — **NEW** — Session store, token generation/validation, header extraction.
- `src/http.zig` — Added `session` module re-export.
- `src/edge_config.zig` — Added `session_ttl_seconds` and `session_max` fields with env var loading.
- `src/edge_gateway.zig` — Added session store to gateway state; added POST/DELETE/GET `/v1/sessions` endpoints; added session-based auth fallback on `/v1/chat`.

## Design Decisions

- **Token format:** 32 random bytes → 64-char hex string. 256 bits of entropy is sufficient for session tokens.
- **Storage:** In-memory `StringHashMap`. Acceptable for single-node gateway; can be swapped for Redis/DB later.
- **TTL:** Idle-based (last_active_ns). Sessions extend on each validated use.
- **Revocation:** Marks session as revoked (soft delete). Cleanup removes expired/revoked entries on next `create()`.
- **Auth fallback:** `/v1/chat` checks bearer token first, then falls back to session token. Identity is propagated either way.

## Tests Added

In `src/http/session.zig`:
- `SessionStore create and validate`
- `SessionStore create with device_id`
- `SessionStore revoke`
- `SessionStore revokeByIdentity`
- `SessionStore max_sessions limit`
- `SessionStore validate returns null for unknown token`
- `SessionStore listByIdentity`
- `isValidToken validates format`
- `fromHeaders extracts valid token`
- `fromHeaders returns null when missing`
- `fromHeaders returns null for invalid token`

## Acceptance Criteria

- [x] Session tokens are cryptographically random (std.crypto.random)
- [x] Sessions track identity, client IP, device ID, timestamps
- [x] Sessions expire after configurable idle TTL
- [x] Max session limit enforced
- [x] Single session and per-identity bulk revocation
- [x] Gateway endpoints for create/revoke/list
- [x] Session auth accepted as bearer token alternative on /v1/chat
- [x] All tests pass (`zig build test`)
