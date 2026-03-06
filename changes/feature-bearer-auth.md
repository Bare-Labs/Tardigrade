# Feature: Bearer Token Authentication

## Overview

Implement Phase 0.1 bearer token authentication primitives and token validation hooks for the gateway foundation.

## Scope

- Add `src/http/auth.zig` with:
  - bearer token extraction from `Authorization` headers
  - RFC6750-style bearer token shape validation
  - `authorize` helper returning structured auth errors
  - optional validation hook callback for caller-owned token trust decisions
- Export auth helpers via `src/http.zig`.
- Update roadmap and changelog entries for this shipped scope.

## Files changed

- `src/http/auth.zig` (new)
- `src/http.zig`
- `PLAN.md`
- `CHANGELOG.md`

## Tests added/changed

- Added unit tests in `src/http/auth.zig`:
  - parse bearer token with mixed-case scheme
  - reject malformed or non-bearer authorization values
  - validate token charset/length and hook behavior
  - verify `authorize` error cases and success path

## Verification

- `zig fmt --check src/http/auth.zig src/http.zig src/main.zig`
- `zig build test --global-cache-dir .zig-cache/global --cache-dir .zig-cache`

## Status

Done.
