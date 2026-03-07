# Feature: IP Access Control

**Branch:** `feat/ip-access-control`
**Version:** 0.11.0
**Status:** done

## Scope

Implement Phase 6.1 from PLAN.md: IP-based allow/deny directives with CIDR notation support.

## Files Changed

- `src/http/access_control.zig` — **NEW** — IP parsing, CIDR matching, AccessControl rule engine.
- `src/http.zig` — Added `access_control` module re-export.
- `src/edge_config.zig` — Added `access_control_rules` field with `TARDIGRADE_ACCESS_CONTROL` env var.
- `src/edge_gateway.zig` — Added ACL to GatewayState, IP access check before rate limiting.

## Design Decisions

- **Rule format:** `"allow <CIDR>, deny <CIDR>, ..."` — simple comma-separated string, parsed at startup.
- **Evaluation:** First match wins, with configurable default action (defaults to allow when rules are set).
- **IP parsing:** Custom IPv4 and IPv6 parsers to avoid std.net dependency. Supports `::` shorthand for IPv6.
- **Placement:** ACL check runs before rate limiting — blocked IPs don't consume rate limit tokens.
- **Empty config:** When `TARDIGRADE_ACCESS_CONTROL` is empty, access control is disabled (all traffic allowed).

## Tests Added

In `src/http/access_control.zig`:
- `parseIp valid IPv4`
- `parseIp valid IPv6 full`
- `parseIp valid IPv6 shorthand`
- `parseIp invalid`
- `parseCidr IPv4 with prefix`
- `parseCidr plain IPv4 gets /32`
- `parseCidr invalid prefix`
- `CidrBlock contains matching IP` (multiple subnet tests)
- `CidrBlock /24 subnet`
- `CidrBlock /32 exact match`
- `CidrBlock /0 matches all`
- `CidrBlock IPv4 does not match IPv6`
- `AccessControl allow by default`
- `AccessControl deny by default`
- `AccessControl fromConfig allow then deny`
- `AccessControl fromConfig deny specific`
- `AccessControl first match wins`
- `AccessControl handles unparseable IP`

## Acceptance Criteria

- [x] IPv4 and IPv6 address parsing
- [x] CIDR block matching with bit-level prefix comparison
- [x] Allow/deny rule parsing from config string
- [x] First-match-wins evaluation
- [x] Gateway integration before rate limiting
- [x] 403 Forbidden for denied IPs
- [x] All tests pass (`zig build test`)
