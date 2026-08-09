# Certificate-status policy: revocation, OCSP, CRLs, and stapling

Tardigrade's pure-Zig PKI path validates certification paths per RFC 5280 and
RFC 9618. This document covers the layer above that: deciding whether a
certificate has been *revoked*, and what the gateway does when it cannot tell.

The implementation is `src/pki/revocation.zig`, wired into
`src/pki/path_validator.zig`. Online fetching of OCSP responses and CRLs is not
implemented yet; the policy, the data model, and the reporting are, so nothing
in the stack has to guess what an acceptance means.

## The one rule

**A path acceptance never implies revocation was checked.** Every accepted path
carries a `revocation.Report` naming, per certificate, exactly what evidence was
consulted and what was not. The default policy checks nothing, and says so.

```zig
var result = pki.path_validator.validateCandidates(allocator, candidates, policy, provider);
switch (result) {
    .accepted => |path| {
        // .disabled, and every entry `not_checked_policy_disabled`
        std.debug.print("status mode: {s}\n", .{@tagName(path.revocation.mode)});
        if (!path.revocation.allChecked()) {
            // No certificate in this path has a completed status check.
        }
    },
    .rejected => |failure| { /* `failure.reason` names the revocation verdict */ },
}
```

## Modes

`revocation.Configuration.mode` selects one of four behaviors. All of them
consult only evidence the caller supplies; none reaches the network.

| Mode | Consults | Missing status | Present-but-unusable status | Revoked |
| --- | --- | --- | --- | --- |
| `disabled` (default) | nothing | accept, recorded | n/a | n/a |
| `stapled_only` | stapled OCSP | accept, recorded | **reject** | reject |
| `soft_fail` | all sources | accept, recorded | accept, recorded | reject |
| `strict` | all sources | **reject** | **reject** | reject |

"Present-but-unusable" means stale, malformed, or unauthenticated evidence —
the peer or provider offered an answer and the answer cannot be trusted.
`stapled_only` draws the line there deliberately: a peer that staples nothing
never promised anything, but a peer that staples a broken response did.

`strict` additionally rejects a certificate that publishes no revocation
mechanism at all (no OCSP responder in Authority Information Access, no CRL
distribution point), because no future provider could ever satisfy the policy
for it. That verdict is `status_source_unsupported`, distinct from "we looked
and found nothing".

## Must-staple (RFC 7633)

A certificate carrying the TLS Feature extension with `status_request` (5)
asserts that its server always delivers a stapled status response. Tardigrade
parses the extension (`x509.Certificate.mustStaple`) and enforces it in every
mode that consults status: the leaf must have a *stapled*, good, usable status,
or the path is rejected with `must_staple_not_satisfied`. A cached or CRL answer
does not substitute — the point of the assertion is the in-band delivery.

RFC 7633 §4.2.3 lets an issuing CA assert the feature on behalf of the
certificates below it, so a must-staple assertion anywhere in the path binds the
leaf.

In `disabled` mode there is no evidence channel, so the assertion cannot be
honored. Rather than silently ignore it, acceptance sets
`Report.must_staple_unenforced`. Operators who deploy must-staple certificates
behind Tardigrade should run at least `stapled_only`.

## Evidence and the trust boundary

Evidence reaches validation as `revocation.StatusAssertion` values in
`ValidationPolicy.revocation_evidence` — status, source, timestamps, an optional
`Defect` when the encoded response could not be interpreted, and
`signature_verified`.

`signature_verified` is asserted by whoever produced the evidence. This module
does not verify OCSP responder signatures (that needs its own delegated-responder
path validation) or CRL signatures (that needs the CRL issuer's key). With
`require_signature_verified` — the default — unverified evidence never counts as
a completed check, so a peer cannot manufacture a "good" status by stapling
bytes nobody authenticated. Turning it off is a deliberate downgrade.

A *revoked* assertion is honored even when unverified or stale. The only party
who can supply attacker-chosen stapled bytes is the peer being authenticated,
and a peer revoking itself is not a threat; ignoring a stale revocation would be.

### Freshness

`revocation.Freshness` bounds how old evidence may be:

- `clock_skew_seconds` (default 300) — tolerance on both sides of every
  comparison, so a modest clock offset does not fail handshakes.
- `maximum_age_seconds` (default 7 days) — maximum age of `thisUpdate`.
  Evidence with no `thisUpdate` cannot be aged and is unusable while this is set.
- `require_next_update` (default true) — RFC 6960 §2.4 permits an absent
  `nextUpdate`, but evidence with no stated expiry can never be aged out of a
  cache, so it is unusable by default.

Evidence dated in the future beyond the skew allowance, or whose `nextUpdate`
precedes its `thisUpdate`, is incoherent and unusable.

### Source precedence

When several sources answer for the same certificate, a usable `revoked` from
*any* source decides — a second source cannot launder a revocation away.
Otherwise the highest-precedence source wins: stapled, then cached, then CRL
set; within one source, a definite answer beats `unknown`. When nothing is
usable, the highest-precedence blocked assertion is reported, so the operator
learns *why* rather than just "unavailable".

## No ambient I/O

No code in `src/pki/` opens a socket, reads a file, or reads a clock during
validation. Validation time is injected (`ValidationPolicy.validation_time`) and
status evidence is supplied by the caller. A future fetch-and-cache provider
implements `revocation.Provider` and runs *before* validation:

```zig
var evidence = try provider.collect(allocator, .{
    .path = candidate_path,
    .validation_time = now,
    .stapled = stapled_from_handshake,
});
policy.revocation_evidence = evidence;
```

That is the whole seam. Adding OCSP fetching, a response cache, or a CRL-set
distribution channel changes no signature in the TLS handshake or in
`path_validator`, and cannot introduce blocking I/O into path validation,
because path validation has no way to call out.

## Operational tradeoffs

**Privacy.** Online OCSP tells the CA which site each visitor is reaching, from
which IP, and when — a per-connection disclosure to a third party. Stapling
removes it: the server fetches its own status and delivers it in-band, so the
responder learns about servers, not visitors. This is why `stapled_only` is the
recommended first step rather than a fetching mode, and why any future fetch
provider must be opt-in.

**Availability.** Hard-failing on unreachable revocation infrastructure converts
a responder outage into a gateway outage, which is why most deployed TLS stacks
soft-fail — and why soft-fail revocation gives an on-path attacker who can block
the responder exactly the outcome they want. Tardigrade does not resolve that
dilemma by picking a comfortable default and hiding it; it names the modes and
records the result. `strict` is honest but demands a status pipeline that is at
least as available as the gateway.

**Operations.** CRL sets are cheap at handshake time and stale by construction;
OCSP is fresher and adds latency and a dependency. Stapling shifts both cost and
dependency to the server operator, where they are visible and controllable. The
`Report` is the observability hook: it distinguishes "checked and good" from
"nothing was checked" so a deployment can measure its actual coverage before
tightening the mode.

## Failure reasons

`path_validator.FailureReason` gains:

| Reason | Meaning |
| --- | --- |
| `certificate_revoked` | usable evidence says revoked |
| `revocation_status_unavailable` | the mode requires an answer; none was usable |
| `revocation_status_stale` | evidence outside the freshness window |
| `revocation_status_malformed` | evidence the provider could not interpret |
| `revocation_status_unauthenticated` | nobody verified the responder or CRL signature |
| `revocation_must_staple_not_satisfied` | RFC 7633 assertion unmet |
| `revocation_source_unsupported` | certificate publishes no revocation mechanism |
| `revocation_evidence_invalid` | evidence filed against a certificate not in the path |
| `revocation_resource_limit_exceeded` | evidence exceeded the configured bounds |

Failure values carry only enums and indices — never borrowed certificate bytes.

## Not implemented yet

- Fetching OCSP responses or CRLs, and any cache behind that.
- Decoding OCSP responses and CRLs into `StatusAssertion` values, including
  responder-signature verification and delegated-responder path validation
  (`id-pkix-ocsp-nocheck` is defined in `oid.zig` for that work).
- Wiring stapled responses from the TLS handshake into `Evidence`.

Each is additive against the seam described here.
