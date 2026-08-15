# Troubleshooting

This is the canonical operator runbook for diagnosing Tardigrade failures. It
assumes you have a symptom (a bad response, a process that won't start, a
metric that looks wrong) and walks you from that symptom to a concrete check,
a likely cause, a fix, and a way to verify the fix worked.

It is deliberately not a second copy of the reference docs. Where a fix
requires a full directive/environment-variable listing, this guide links to
[Configuration](CONFIGURATION.md), [Deployment](DEPLOYMENT.md),
[Reload, drain, and shutdown](RELOAD_SHUTDOWN.md), or
[Observability](OBSERVABILITY.md) instead of restating them.

All examples use the canonical packaged config path,
`/etc/tardigrade/tardigrade.conf`, and the canonical binary name, `tardi`
(`tardigrade` also works as a compatibility alias installed by the release
script — see [README.md#install](../README.md#install)). Substitute your own
config path throughout; **always pass it explicitly** (`-c <path>` or a
positional argument) rather than relying on defaults — `tardi check` and
`tardi config validate` fall back to `./tardigrade.toml` when no path is
given, which is almost never what you want against an nginx-style
`tardigrade.conf` deployment.

## Contents

1. [Five-minute triage](#1-five-minute-triage)
2. [Config does not parse or validate](#2-config-does-not-parse-or-validate)
3. [Listener fails to bind / service is unreachable](#3-listener-fails-to-bind--service-is-unreachable)
4. [Route does not match](#4-route-does-not-match)
5. [Static files return 404 or 403](#5-static-files-return-404-or-403)
6. [Upstream returns 502 / 504 / 503](#6-upstream-returns-502--504--503)
7. [TLS certificate/key errors](#7-tls-certificatekey-errors)
8. [Health checks mark an upstream down](#8-health-checks-mark-an-upstream-down)
9. [Metrics endpoint unavailable](#9-metrics-endpoint-unavailable)
10. [Logs are missing / going somewhere unexpected](#10-logs-are-missing--going-somewhere-unexpected)
11. [Reload did not apply expected changes](#11-reload-did-not-apply-expected-changes)
12. [Performance appears worse than expected](#12-performance-appears-worse-than-expected)
13. [Still stuck?](#13-still-stuck)

---

## 1. Five-minute triage

Run this pass before anything more specific. It separates "config problem",
"process problem", and "network/routing problem" in a handful of commands.

```bash
tardi version

tardi check /etc/tardigrade/tardigrade.conf

tardi print-config -c /etc/tardigrade/tardigrade.conf

tardi routes -c /etc/tardigrade/tardigrade.conf

tardi upstreams -c /etc/tardigrade/tardigrade.conf
```

For a packaged/systemd deployment, add the process-level checks:

```bash
tardi status --pid-file /run/tardigrade/tardigrade.pid
sudo systemctl status tardigrade
sudo journalctl -u tardigrade -n 100 --no-pager
```

Then probe the listener you're actually diagnosing. Only do this if the
config you're checking actually defines a `/health` route — it isn't a
built-in path, it's a convention used throughout `examples/` (a
`location = /health { return 200 ok; }` block); `tardi routes` above tells
you whether yours has one.

```bash
curl -v -H 'Host: localhost' http://127.0.0.1:8069/health
```

For TLS:

```bash
curl -vk -H 'Host: localhost' https://127.0.0.1:8443/health
```

> The starter config and every example match on a specific `server_name`
> (`localhost` by default). A bare `curl` against a raw IP without a matching
> `Host` header returns `404`, not `200` — that's expected virtual-host
> behavior, not a bug. Match your config's `server_name` with `-H 'Host:
> ...'`, or configure an unnamed/default `server {}` block (a block with no
> `server_name` names) if you need one to catch non-matching hosts — see
> [CONFIGURATION.md's Server Blocks section](CONFIGURATION.md#server-blocks).

### Critical inspection-command warning

**`print-config`, `routes`, and `upstreams` inspect the config file loaded by
that CLI invocation. They do not talk to a running Tardigrade process, and
they do not prove that a previous `tardi reload`/`SIGHUP` was applied
successfully.** Running any of the three against an edited config file only
tells you the *file* parses and would produce the routes/upstreams you
expect — not that the live process is actually serving them. For live reload
state, use the runtime status/log/metric surfaces in
[§11](#11-reload-did-not-apply-expected-changes), primarily
`GET /tardigrade/reload/status`.

Effective-value precedence (process environment, then config file, then
decrypted secrets, then built-in defaults) is fully documented in
[CONFIGURATION.md](CONFIGURATION.md#configuration-reference) — check there
before assuming a config-file edit is what's actually in effect; a
`TARDIGRADE_*` environment variable set on the process always wins.

## 2. Config does not parse or validate

### Symptoms

`tardi check` (or `tardi run`, `sudo systemctl start tardigrade`) exits
non-zero with an `error: configuration parse failed …` or
`error: configuration validation failed …` message instead of
`configuration valid`.

### First checks

```bash
tardi check /etc/tardigrade/tardigrade.conf
echo "exit code: $?"
```

Exit code `2` means the config itself is invalid (syntax or semantic
validation rejected it); exit code `1` means something else went wrong
(unexpected filesystem/internal error) — don't spend time re-reading the
config file for a `1`.

For package deployments, also check as the service user, since file
permissions differ between your shell and the service account:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
```

**This check does not see `/etc/tardigrade/tardigrade.env`.** A value that
only exists there (a secret bootstrap reference, a port override, a TLS path
override) can make the standalone check pass while the actual service still
fails to start — see [DEPLOYMENT.md's
`ExecStartPre` note](DEPLOYMENT.md#commands) for why the unit's own
`ExecStartPre` (not this ad hoc invocation) is the real pre-flight gate.

### Likely causes

Syntax-level (the parser rejects the file before semantic validation runs):

- missing `;` at the end of a directive
- mismatched `{`/`}` — the parser requires the block opener on a line ending
  in `{` and a closing line containing only `}`
- malformed `server {}` / `location {}` block
- an `include` path or glob that doesn't resolve
- a `${VAR}` interpolation that references an unset environment variable

Semantic/resource-level (the file parses, but a value is invalid):

- an out-of-range port, invalid enum value, or malformed URL
- a `tls_cert_path` set without a matching `tls_key_path` (or vice versa) —
  Tardigrade requires both or neither, at both the top level and per
  `server {}` block
- a malformed `proxy_pass`/`upstream_base_url`
- contradictory settings (e.g. both HTTP/1.1 and HTTP/2 disabled)
- pointing at the wrong config file entirely — double-check
  `-c`/`--config`, `TARDIGRADE_CONFIG_PATH`, and the runtime discovery order
  in [CONFIGURATION.md](CONFIGURATION.md#configuration-reference)
- a process-environment `TARDIGRADE_*` variable silently overriding a
  file value you just edited (env wins — see the precedence note above)

`tardi check`/`tardi run` also print non-fatal `config warning: …` lines for
risky-but-valid settings (upstream TLS verification disabled, rate limiting
disabled, HSTS off with TLS configured, 0-RTT enabled, etc.) — read these
even when the check otherwise passes.

### Concrete fixes

Fix the specific line the diagnostic names, then re-run `tardi check`. For
syntax errors, work from the top of the file down — one missing `;` can
cascade into misleading downstream parse errors. For "config file not
found", pass the exact path you intend with `-c`/`--config` rather than
relying on discovery order.

### Verify the fix

```bash
tardi check /etc/tardigrade/tardigrade.conf
```

should print `configuration valid` followed by the config summary, with exit
code `0`. Then confirm the specific fields you changed:

```bash
tardi print-config -c /etc/tardigrade/tardigrade.conf
```

### Related documentation

- [Configuration reference](CONFIGURATION.md) — full directive/env-var
  listing, syntax rules, and precedence.
- [examples/](../examples/README.md) — copy/paste-runnable configs, CI-checked
  with `tardi check` on every change.

## 3. Listener fails to bind / service is unreachable

### A. Tardigrade never binds

#### Symptoms

The process exits immediately (`tardi run` prints `error: tardigrade exited:
…` and exits non-zero) or `systemctl start tardigrade` / `docker compose up`
never reaches a healthy state. No `Tardigrade edge listening on …` line
appears in the logs.

#### First checks

```bash
tardi check /etc/tardigrade/tardigrade.conf
tardi print-config -c /etc/tardigrade/tardigrade.conf
sudo ss -ltnp
```

**`tardi check` never binds a socket** — it's a dry parse/validate only, so
a passing check does not rule out a bind failure. `ss -ltnp` (or
`sudo journalctl -u tardigrade -n 50 --no-pager` for the actual startup
error) is what tells you whether the port is already taken.

#### Likely causes

- the port is already in use — by a previous Tardigrade instance that
  didn't fully stop, or by an unrelated process; `ss -ltnp` names the owning
  PID
- an invalid or non-local `TARDIGRADE_LISTEN_HOST`/`listen` address (a host
  that doesn't resolve to a local interface)
- attempting to bind `80`/`443` directly without the capability to do so
  (see below)
- systemd sandboxing (`ProtectSystem=full`, `ProtectHome=true`, etc.)
  blocking a path your config references outside the allowed directories

#### Concrete fixes

Kill or reassign the conflicting process, or change `listen`/
`TARDIGRADE_LISTEN_PORT`. **For privileged ports (`80`/`443`), do not run
Tardigrade as root.** Follow [DEPLOYMENT.md's ports and privilege
model](DEPLOYMENT.md#ports-and-privilege-model): put a frontend load
balancer or NAT in front and expose `80`/`443` there, or grant the systemd
unit `AmbientCapabilities=CAP_NET_BIND_SERVICE` (plus
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`) so the unprivileged
`tardigrade` service account can bind the port directly. Tardigrade can also
be configured to refuse to start under UID 0 at all
(`TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true`) — if you see a startup
rejection referencing this, that guard is working as intended; fix the
deployment, don't disable the guard.

If a systemd hardening directive is blocking a path your deployment
legitimately needs, extend that directive's allowlist for the specific path
rather than loosening `ProtectSystem`/`ProtectHome` globally — see
[DEPLOYMENT.md's filesystem layout section](DEPLOYMENT.md#host-filesystem-layout).

#### Verify the fix

```bash
sudo systemctl restart tardigrade
sudo journalctl -u tardigrade -n 20 --no-pager
```

Look for `Tardigrade edge listening on <host>:<port>`, then confirm with
`ss -ltnp` and a local `curl`.

### B. Listener exists but remote clients cannot connect

#### Symptoms

`ss -ltnp` shows Tardigrade bound and listening, `curl` succeeds from
`127.0.0.1` on the host itself, but remote clients time out or get
connection-refused.

#### First checks

Prove local connectivity first (it isolates "Tardigrade problem" from
"network path problem"):

```bash
curl -v -H 'Host: <your-server-name>' http://127.0.0.1:<port>/health
```

Then check what address it's actually bound to:

```bash
sudo ss -ltnp | grep tardi
```

#### Likely causes

- bound to `127.0.0.1` (loopback-only) instead of `0.0.0.0` or a specific
  reachable interface
- a host or cloud-provider firewall/security-group blocking the port
- a load balancer or NAT pointing at the wrong backend target/port
- under Docker, the container port was never published (missing/incorrect
  `ports:` mapping in `compose.yaml`)
- the client is using the wrong scheme (`http://` against a TLS-only
  listener, or `https://` against a plaintext one)

#### Concrete fixes

Set `TARDIGRADE_LISTEN_HOST`/`listen` to a reachable address, open the
firewall/security-group rule for the port, fix the load balancer's backend
target, or add/correct the Docker `ports:` mapping (see
[DEPLOYMENT.md's Docker section](DEPLOYMENT.md#docker)).

#### Verify the fix

Repeat the remote client's request (or `curl` from an external host) and
confirm you get the expected response rather than a timeout/connection
refused.

### Related documentation

- [DEPLOYMENT.md](DEPLOYMENT.md) — filesystem layout, permissions, systemd
  unit contract, Docker port publication.
- [CONFIGURATION.md](CONFIGURATION.md#listener-and-protocol) — listener and
  protocol fields.

## 4. Route does not match

### Symptoms

A request that should hit a specific `location`/`proxy_pass`/`return`
instead gets routed somewhere else, returns `404`, or hits the wrong
upstream.

### First checks

```bash
tardi routes -c /etc/tardigrade/tardigrade.conf
```

Then reproduce the exact request, including the `Host` header if your config
uses `server_name`/multiple `server {}` blocks:

```bash
curl -v -H 'Host: api.example.com' \
  http://127.0.0.1:8069/api/users
```

### Likely causes

- **wrong `Host` / virtual host**: when any `server {}` block exists, host
  selection is based on server blocks only — the first matching named block
  wins, then an unnamed/default block, then the first block as a last-resort
  fallback. A selected named fallback that doesn't actually match the
  request `Host` is rejected outright (`404`), not silently served. See
  [CONFIGURATION.md's Server Blocks section](CONFIGURATION.md#server-blocks).
- **a different server block was selected than you expect** because of the
  fallback order above
- **exact vs. prefix mismatch**: `location = /path` only matches that exact
  path, not `/path/` or `/path/sub`
- **priority-prefix shadowing**: `location ^~ /path/` wins over any regex or
  plain-prefix location for requests under that prefix, even a regex that
  would otherwise match more specifically
- **an earlier regex matched first**: `location ~`/`~*` blocks are evaluated
  in declaration order, and the first match wins — not the most specific one
- **the request is hitting a different listener, process, or config
  entirely** — a second Tardigrade instance, a stale process still bound
  from before a restart, or the wrong `-c`/`TARDIGRADE_CONFIG_PATH`
- **an edited config was never successfully reloaded** — see
  [§11](#11-reload-did-not-apply-expected-changes); `tardi routes` against
  the file on disk proves nothing about what the running process is
  actually serving

Query strings and fragments are stripped before location matching — a
`?query=string` never affects which `location` block wins. Only `if
($request_uri …)`/`if ($args …)` conditional rules can see the query string;
ordinary `location` matching never does.

### Concrete fixes

Reorder or tighten `location` blocks to get the precedence you want (exact
`=` for a single path, `^~` to force priority over regex, and remember
regex order matters). Fix the `server_name`/`Host` mismatch, or add a
default/catch-all `server {}` block if you need one. If the config on disk
is right but the live process disagrees, reload it (§11) instead of editing
further.

### Verify the fix

```bash
tardi routes -c /etc/tardigrade/tardigrade.conf
curl -v -H 'Host: api.example.com' http://127.0.0.1:8069/api/users
```

Confirm both the static route table and the live response match what you
expect.

### Related documentation

- [CONFIGURATION.md — Location Blocks](CONFIGURATION.md#location-blocks) and
  [Server Blocks](CONFIGURATION.md#server-blocks) — full precedence rules.
- [examples/virtual-hosts](../examples/virtual-hosts/README.md).

## 5. Static files return 404 or 403

Treat these as two different failure classes — a `403` here is a deliberate
security rejection, not a permissions bug to work around by loosening
anything.

### 404 — file not found

#### Symptoms

A static request returns `404` where you expected a file to be served.

#### First checks

```bash
tardi routes -c /etc/tardigrade/tardigrade.conf
sudo -u tardigrade test -r /var/lib/tardigrade/public/index.html
```

The `test -r` run as the service account catches "the file exists but
Tardigrade's user can't read it" — which surfaces as `404`, not a permission
error, from the client's perspective.

#### Likely causes

- the file genuinely doesn't exist at the resolved path
- wrong `root`/`alias` for the matched location
- a relative `root` resolved from an unexpected working directory (prefer
  absolute paths in production configs)
- the request matched a different `location`/`server` block than you
  expected — see [§4](#4-route-does-not-match)
- `try_files` candidates don't include a fallback that resolves
- directory-index behavior: for a directory-style request, Tardigrade tries
  `try_files` first, then `index` (which defaults to `index.html` and is
  resolved *relative to the requested directory*, not the root — `GET
  /docs/` checks `docs/index.html`), then `autoindex` if enabled. A
  nonexistent directory still 404s even with `try_files`/`index`
  configured. See [PROXY_SECURITY.md §12a](PROXY_SECURITY.md#12a-root--index--try_files-interaction-437)
  for the exact resolution order.

#### Concrete fixes

Correct `root`/`alias`/`try_files` for the matching location, fix file
ownership/permissions for the service account (readable, not necessarily
writable), or set an explicit `index "";` if you deliberately don't want the
default `index.html` fallback.

#### Verify the fix

```bash
curl -v -H 'Host: <server_name>' http://127.0.0.1:8069/<path>
```

Confirm `200` with the expected body.

### 403 — security-driven rejection

#### Symptoms

A static request returns `403` instead of `404`, often for a request that
"looks like" it should resolve, or contains `..`/encoded traversal
sequences.

#### Likely causes

This is intentional: Tardigrade resolves the canonical (`realpath`) absolute
path of both the configured document root and the requested file, and
rejects any resolved path that doesn't have the root as a prefix — with
`403`, not `404`. This blocks `..` segments, percent-encoded and
double-percent-encoded traversal, backslash traversal, and symlinks that
point outside the document root. See
[PROXY_SECURITY.md §12](PROXY_SECURITY.md#12-directory-traversal--static-file-serving)
for the full list of blocked sequences.

#### Concrete fixes

**Do not "fix" a `403` here by loosening filesystem permissions or moving
files to make traversal succeed** — that defeats the boundary the `403` is
protecting. If the rejection is a false positive (a legitimate file that
happens to be reached through a symlink), either move the real file inside
the document root or point `root`/`alias` at the actual containing
directory so the request never needs to leave it.

#### Verify the fix

```bash
curl -v -H 'Host: <server_name>' http://127.0.0.1:8069/<legitimate-path>
```

Confirm you get `200` for the legitimate path while a traversal attempt
(`curl http://127.0.0.1:8069/../../etc/passwd`) still correctly returns
`403`.

### Related documentation

- [PROXY_SECURITY.md](PROXY_SECURITY.md) — full traversal/symlink threat
  model and static-serving security guarantees.
- [CONFIGURATION.md — Location Blocks](CONFIGURATION.md#location-blocks).
- [examples/static-file-server](../examples/static-file-server/README.md).

## 6. Upstream returns 502 / 504 / 503

These three statuses map to three distinct failure classes in Tardigrade's
proxy path — don't treat them interchangeably.

### First checks

Inspect the configured upstream policy first — remember this is
configuration, not a live probe:

```bash
tardi upstreams -c /etc/tardigrade/tardigrade.conf
```

Then contact the origin from the **same host/container/network namespace**
Tardigrade uses — a check from your laptop proves nothing if Tardigrade
reaches the origin over a different network path:

```bash
curl -v http://127.0.0.1:3000/health
```

For an HTTPS origin:

```bash
curl -v https://backend.example.com/health
```

### 502 — Bad Gateway

#### Symptoms

`502` with `error_category: upstream_error` (or `internal_error` for a
`5xx` status Tardigrade itself returns) in the access log.

#### Likely causes

Non-timeout gateway/protocol failures:

- connection refused (nothing listening at the configured target)
- wrong target host/port/scheme in `proxy_pass`/`upstream_base_url`
- the upstream closed the connection before sending a complete response
  head, or sent a malformed/truncated status line
- upstream TLS verification or handshake failure when proxying to `https://`
- a protocol mismatch (e.g. `TARDIGRADE_UPSTREAM_PROTOCOL` set to something
  the origin doesn't actually speak)

#### Concrete fixes

Fix the target URL/scheme, start or repair the origin process, or correct
the upstream TLS configuration. **Do not "fix" an upstream TLS handshake
failure by disabling `TARDIGRADE_UPSTREAM_TLS_VERIFY`** — that removes
certificate validation for every request to that origin. Instead fix the
origin's certificate, supply the correct CA bundle via
`TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE`, or correct
`TARDIGRADE_UPSTREAM_TLS_SERVER_NAME` if SNI doesn't match what the origin
presents.

#### Verify the fix

```bash
curl -v http://127.0.0.1:8069/<proxied-path>
```

Confirm the proxied response now matches what the origin returns directly.

### 504 — Gateway Timeout

#### Symptoms

`502` and `504` look similar to the client but classify differently in
Tardigrade's own logs/metrics (`error_category: upstream_timeout`) —
`504` specifically means Tardigrade gave up waiting, not that it couldn't
reach the origin at all.

#### Likely causes

- connect timeout: the origin never accepted the TCP connection in time
  (`TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS`)
- response timeout: the origin accepted the connection but never finished
  responding in time (`TARDIGRADE_UPSTREAM_TIMEOUT_MS`,
  `TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS`)
- an overloaded or hung upstream process
- genuine network latency or packet loss between Tardigrade and the origin
- retry policy (`TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS`) extending the total
  observed latency before the final timeout is returned

#### Concrete fixes

Fix the slow/hung origin, or tune the timeout values in
[CONFIGURATION.md's Proxy And Upstreams section](CONFIGURATION.md#proxy-and-upstreams)
to match realistic origin latency — raising a timeout papers over a slow
origin rather than fixing it, so treat that as a stopgap, not a resolution.

#### Verify the fix

Time the direct-to-origin request and the proxied request and confirm both
complete well inside the configured timeout:

```bash
time curl -v http://127.0.0.1:3000/health
time curl -v http://127.0.0.1:8069/<proxied-path>
```

### 503 — Service Unavailable

#### Symptoms

`503`, often with `Retry-After` and `Connection: close`, and
`error_category: upstream_unavailable` (proxy-capacity path) or no
upstream contact at all.

#### Likely causes

`503` here is a capacity/availability signal, not a gateway or timeout
failure — don't fold it into the 502/504 explanations above:

- the per-origin connection-pool limit
  (`TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST`) is exhausted, failing the
  checkout fast instead of queuing without bound
- every backend for the route is currently marked unhealthy by passive
  failure tracking (`TARDIGRADE_UPSTREAM_MAX_FAILS`/
  `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS`) or active probing — see
  [§8](#8-health-checks-mark-an-upstream-down)
- an open circuit breaker fast-failing a backend after repeated failures —
  see the [circuit-breaker row of OBSERVABILITY.md's overload
  troubleshooting table](OBSERVABILITY.md#operator-troubleshooting) for the
  exact recovery condition
- Tardigrade's own accept-time capacity limits were hit — this is **not**
  an upstream problem at all; see the [overload-response table in
  OBSERVABILITY.md](OBSERVABILITY.md#configured-limits) for the connection/
  queue/memory caps that produce the same deterministic `503`

#### Concrete fixes

Point 503s at capacity/health metrics rather than guessing:

```bash
curl -s http://127.0.0.1:8069/status/metrics | grep -E \
  'tardigrade_upstream_unhealthy_backends|tardigrade_connection_rejections_total|tardigrade_queue_rejections_total'
```

Scale or repair the unhealthy backend(s), or raise the relevant capacity
limit only after confirming Tardigrade has headroom (CPU/memory/fds) to
honor it. If a circuit breaker is involved, let it recover on its own
schedule rather than editing config to force it closed — it will re-trip on
the next real failure anyway.

#### Verify the fix

```bash
curl -s http://127.0.0.1:8069/status/metrics | grep tardigrade_upstream_unhealthy_backends
curl -v http://127.0.0.1:8069/<proxied-path>
```

Confirm the unhealthy-backend count drops and the proxied request succeeds.

### Related documentation

- [OBSERVABILITY.md — Resource Limits and Overload Behavior](OBSERVABILITY.md#resource-limits-and-overload-behavior)
  — the full overload-cause-to-signal mapping, including the local-capacity
  `503` path that isn't an upstream problem at all.
- [CONFIGURATION.md — Proxy And Upstreams](CONFIGURATION.md#proxy-and-upstreams)
  and [Health Checks And Circuit Breaking](CONFIGURATION.md#health-checks-and-circuit-breaking).
- [UPSTREAM_POOLING.md](UPSTREAM_POOLING.md) — connection pool contract.

## 7. TLS certificate/key errors

Separate startup credential validation (Tardigrade won't start at all) from
client-facing handshake failures (Tardigrade is running, but a given client
can't complete a TLS handshake).

### Startup validation failures

#### Symptoms

`tardi check`/`tardi run`/`systemctl start tardigrade` fails with a
certificate/key-related validation error instead of `configuration valid`.

#### First checks

```bash
tardi check /etc/tardigrade/tardigrade.conf
tardi print-config -c /etc/tardigrade/tardigrade.conf
sudo -u tardigrade test -r /etc/tardigrade/tls/fullchain.pem
sudo -u tardigrade test -r /etc/tardigrade/tls/privkey.pem
```

Certificate metadata:

```bash
openssl x509 \
  -in /etc/tardigrade/tls/fullchain.pem \
  -noout -subject -issuer -dates
```

#### Likely causes

- only `tls_cert_path` or only `tls_key_path` configured — Tardigrade
  requires both or neither, and rejects a cert-only/key-only configuration
  at validation time rather than silently falling back to plaintext
- the service account can't read the private key (see permissions fix
  below)
- malformed PEM, or an ambiguous/ill-formed certificate chain
- the certificate and key don't match
- an expired or not-yet-valid certificate (`openssl x509 … -dates` above)
- for the appliance TLS profile specifically: more than one certificate
  identity configured (server-block TLS material or `TARDIGRADE_TLS_SNI_CERTS`)
  — the appliance profile supports exactly one identity; see
  [BARE_APPLIANCE_TLS.md](BARE_APPLIANCE_TLS.md)

#### Concrete fixes

Provision the missing half of the cert/key pair, fix the PEM encoding, or
replace an expired certificate. For a permissions fix:

**Never make the private key world-readable.** Keep it `root:tardigrade
0640` (or narrower), owned by a group the service account belongs to. If
you're running under Docker with a bind-mounted key, the failure is usually
a **numeric GID mismatch**, not a mode problem: a host file owned
`root:tardigrade 0640` is only readable inside the container if the
container's `tardigrade` group numerically matches the host group that owns
the file (group *names* don't cross the container boundary, only numeric
IDs do) — `chmod`-ing the bind-mounted file to fix this changes the mode on
the host file too, making the key world-readable there. Instead add the
container to the correct numeric group with Compose's `group_add:`. Full
walkthrough: [DEPLOYMENT.md's permissions
section](DEPLOYMENT.md#permissions-and-ownership).

#### Verify the fix

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
```

Should print `configuration valid` with `tls: enabled` in the summary.

### Runtime handshake failures

#### Symptoms

Tardigrade is running and `tardi check` passes, but a specific client (or
all clients) can't complete a TLS handshake against it.

#### First checks

```bash
openssl s_client \
  -connect 127.0.0.1:8443 \
  -servername api.example.com
```

Read the handshake output for the actual failure: certificate rejected,
protocol version mismatch, no shared cipher, or the connection closing
during `ClientHello`.

#### Likely causes

- SNI/hostname mismatch — the client's `-servername` (or its equivalent)
  doesn't match any configured cert's names, and the wrong cert (or none)
  is presented
- a TLS-version or cipher-suite mismatch between client and
  `TARDIGRADE_TLS_MIN_VERSION`/`TARDIGRADE_TLS_MAX_VERSION`/
  `TARDIGRADE_TLS_CIPHER_LIST`/`TARDIGRADE_TLS_CIPHER_SUITES`
- a plaintext HTTP request sent to a TLS listener (or vice versa) — the
  symptom looks like a "hang" or protocol error, not a clean TLS alert
- client certificate verification enabled
  (`TARDIGRADE_TLS_CLIENT_VERIFY=true`) but the client didn't present one,
  or its chain doesn't validate against `TARDIGRADE_TLS_CLIENT_CA_PATH`

#### Concrete fixes

Correct the SNI name or add the missing name to `TARDIGRADE_TLS_SNI_CERTS`,
widen `TARDIGRADE_TLS_MIN_VERSION`/`_MAX_VERSION` only if you understand the
compatibility tradeoff, or fix the client's scheme. **Do not weaken
TLS verification (client or upstream) as a generic fix** — diagnose the
actual mismatch instead.

#### Verify the fix

```bash
openssl s_client -connect 127.0.0.1:8443 -servername api.example.com </dev/null
curl -vk -H 'Host: api.example.com' https://127.0.0.1:8443/health
```

Confirm the handshake completes and the response comes back as expected.

### Related documentation

- [CONFIGURATION.md — TLS Termination](CONFIGURATION.md#tls-termination) —
  full TLS field reference.
- [BARE_APPLIANCE_TLS.md](BARE_APPLIANCE_TLS.md) — appliance TLS profile
  constraints.
- [PKI_REVOCATION.md](PKI_REVOCATION.md) — OCSP/CRL policy, if you're
  chasing a revocation-related failure.
- [examples/tls-termination](../examples/tls-termination/README.md).

## 8. Health checks mark an upstream down

### Symptoms

Requests to a route fail or fail over unexpectedly, and you suspect
Tardigrade's active/passive health checking has marked a backend unhealthy.

### First checks

```bash
tardi upstreams -c /etc/tardigrade/tardigrade.conf
```

This shows the **configured** active-probe path/interval/timeout/thresholds
and passive failure policy for the file you point it at — **it is not a
live backend-health dashboard.** It cannot tell you whether a backend is
currently marked unhealthy by the running process.

For live aggregate health, use metrics:

```bash
curl -s http://127.0.0.1:8069/status/metrics | \
  grep tardigrade_upstream_unhealthy_backends
```

Then probe the actual health-check endpoint from Tardigrade's own network
context (same host/container/namespace), using the configured probe path:

```bash
curl -v http://<upstream-host>:<upstream-port><probe-path>
```

### Likely causes

- the configured probe path or expected success-status range doesn't match
  what the origin actually returns
  (`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH`/`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS`)
- the probe timeout is too small for the origin's real response time
  (`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS`)
- fail/recovery thresholds are too aggressive for a flaky-but-usable origin
  (`TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD`/`_SUCCESS_THRESHOLD`)
- passive failures from real request traffic tripping
  `TARDIGRADE_UPSTREAM_MAX_FAILS` before the active probe would have caught it
- a namespace/address mismatch — the probe reaches a different network path
  than real proxied traffic does (common in containerized deployments)
- an HTTPS probe target failing TLS/SNI verification, distinct from a
  plain reachability failure
- the origin is genuinely unhealthy

Note the active-probe env-var naming split documented in
[CONFIGURATION.md](CONFIGURATION.md#health-checks-and-circuit-breaking):
config-file/secret overrides must use the `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_*`
names, not the process-environment-only `TARDIGRADE_UPSTREAM_PROBE_*`
aliases — setting the wrong family in a config file silently does nothing.

### Concrete fixes

Align the probe path/status range with what the origin actually serves,
raise the probe timeout to match real origin latency, or loosen fail/success
thresholds if a healthy-but-occasionally-slow origin is being marked down
too aggressively. Fix the underlying origin if it's genuinely failing.

### Verify the fix

```bash
curl -s http://127.0.0.1:8069/status/metrics | grep tardigrade_upstream_unhealthy_backends
```

Confirm the count returns to `0` (or the expected number) after the next
probe interval elapses, then confirm proxied requests succeed.

### Related documentation

- [CONFIGURATION.md — Health Checks And Circuit Breaking](CONFIGURATION.md#health-checks-and-circuit-breaking).
- [examples/health-checks](../examples/health-checks/README.md).

## 9. Metrics endpoint unavailable

### Symptoms

`curl` (or your Prometheus scraper) against the metrics path fails or
returns something other than metrics text.

### First checks

```bash
curl -v http://127.0.0.1:8069/status/metrics
```

### Likely causes and how to tell them apart

| Symptom | Meaning |
| --- | --- |
| `404 Not Found` | Wrong path, metrics disabled (`TARDIGRADE_METRICS_PATH=""`), or you're hitting the wrong listener/server block. Check `tardi print-config -c <path>` for the `metrics:` line. |
| `401 Unauthorized` | `TARDIGRADE_METRICS_REQUIRE_AUTH=true` and the request isn't authenticated. This is expected hardening, not a bug — see [DEPLOYMENT.md's hardening checklist](DEPLOYMENT.md#production-hardening-checklist). |
| Connection refused | The listener itself is down or unreachable — this is [§3](#3-listener-fails-to-bind--service-is-unreachable), not a metrics-specific problem. |
| TLS handshake failure | Wrong scheme (`http://` vs `https://`) or a certificate problem — see [§7](#7-tls-certificatekey-errors). |
| Curl from the host succeeds, Prometheus scrape fails | The failure is on the scraper's side of the network path — a firewall rule, wrong scrape target, wrong scheme/TLS config in the scrape job, or `TARDIGRADE_METRICS_REQUIRE_AUTH` without a bearer token configured in the scrape job. Not a Tardigrade-side problem once local `curl` works. |

### Concrete fixes

Correct `TARDIGRADE_METRICS_PATH`/re-enable metrics, supply the auth
credential your scraper needs if `TARDIGRADE_METRICS_REQUIRE_AUTH=true`, or
fix the scraper's target/scheme/network path. Don't disable
`TARDIGRADE_METRICS_REQUIRE_AUTH` in production just to unblock a scrape —
fix the scrape job's auth instead.

### Verify the fix

```bash
curl -v http://127.0.0.1:8069/status/metrics | head -5
```

Confirm you get Prometheus text output (lines starting `# HELP`/`# TYPE`),
then confirm the scraper's own target status shows the endpoint as up.

### Related documentation

- [OBSERVABILITY.md — Metrics](OBSERVABILITY.md#metrics) — full metric
  catalog.
- [examples/prometheus-metrics](../examples/prometheus-metrics/README.md).

## 10. Logs are missing / going somewhere unexpected

### Symptoms

You expect log output (runtime or access logs) and don't see it where you're
looking, or a specific request/status isn't showing up.

### First checks

For systemd deployments, journald is the default surface:

```bash
sudo journalctl -u tardigrade -n 100 --no-pager
sudo journalctl -u tardigrade -f
```

For Docker:

```bash
docker compose logs -f tardigrade
```

If you configured `error_log`/`TARDIGRADE_ERROR_LOG_PATH`, check that file
instead:

```bash
tardi print-config -c /etc/tardigrade/tardigrade.conf   # confirm the path in effect
sudo tail -f /var/log/tardigrade/error.log
```

### Likely causes

- **expecting a file while output is actually going to
  journald/stdout/stderr**: without `error_log`/`TARDIGRADE_ERROR_LOG_PATH`
  configured, runtime and access logs go to stdout, which is what
  `journalctl`/`docker compose logs` capture
- **`error_log` is configured but the target directory/file isn't writable
  by the service account** — check ownership of `/var/log/tardigrade/`
- **log level filtering**: `error_log … warn;` (or
  `TARDIGRADE_LOG_LEVEL=warn`) suppresses `info`/`debug` runtime lines you
  might be expecting
- **access-log minimum status**: `TARDIGRADE_ACCESS_LOG_MIN_STATUS` set
  above `0` hides successful requests from the access log by design
- **buffering delay**: `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE` set above `0`
  batches access-log writes until the buffer threshold — a request you just
  made may not appear until the buffer flushes
- **a misconfigured syslog target** (`TARDIGRADE_ACCESS_LOG_SYSLOG_UDP`)
  silently drops entries the sink refuses (access logging is best-effort and
  never blocks the request path — see
  [OBSERVABILITY.md's log/metrics sink note](OBSERVABILITY.md#configured-limits))
- **looking at access logs for a startup failure** — a config or bind
  failure happens before any request is ever handled, so it will never
  appear in the access log; check runtime logs (journald/`error_log`)
  instead
- **under Docker with a freshly bind-mounted log directory**: `error_log`
  fails with `EACCES` because the bind mount replaced the image's
  pre-owned `10001:10001` directory with a root-owned host path — see
  [DEPLOYMENT.md's Logs section](DEPLOYMENT.md#logs) for the
  `install -d -o 10001 -g 10001` fix

Do not expect a second log-rotation mechanism: the packaged DEB/RPM
logrotate policy sends `SIGUSR1` after rotation, and Tardigrade's own
`SIGUSR1` handler reopens the log file cleanly on that cadence — that's the
one supported rotation path.

### Concrete fixes

Point your monitoring at the actual active surface (journald vs. file),
raise the log level or lower `TARDIGRADE_ACCESS_LOG_MIN_STATUS` if you're
missing entries, fix `/var/log/tardigrade/` ownership, or wait out
(or disable) the access-log buffer if you need near-real-time entries.

### Verify the fix

```bash
curl -v http://127.0.0.1:8069/health
sudo journalctl -u tardigrade -n 5 --no-pager   # or: tail -5 /var/log/tardigrade/access.log
```

Confirm the request you just made shows up where you expect it.

### Related documentation

- [OBSERVABILITY.md — Structured Logs](OBSERVABILITY.md#structured-logs) —
  full field reference for both log types.
- [DEPLOYMENT.md — Logs](DEPLOYMENT.md#logs) — journald vs. file logs,
  logrotate/`SIGUSR1` contract, Docker persistence caveats.
- [examples/access-logs](../examples/access-logs/README.md).

## 11. Reload did not apply expected changes

### Symptoms

You edited `tardigrade.conf`, reloaded, and the running process still
behaves like the old config — or reload appears to have "worked" (no error
printed) but nothing changed.

### First checks

Validate the file first — a failed reload silently keeps the old config
active, so if the new file is invalid you'd otherwise have no idea:

```bash
sudo -u tardigrade tardi check /etc/tardigrade/tardigrade.conf
```

Reload:

```bash
sudo systemctl reload tardigrade
# or, without systemd:
tardi reload --pid-file /run/tardigrade/tardigrade.pid
```

**Then check the live result, not the file.** `tardi print-config`/`routes`/
`upstreams` against the config file on disk only prove the *file* is what
you intend — they say nothing about whether the running process actually
published it. Use the runtime reload-status endpoint instead:

```bash
curl -s http://127.0.0.1:8069/tardigrade/reload/status
```

This returns `{"ok":<bool|null>,"at_ms":<timestamp>,"error":<string|null>}` —
`ok: false` with a non-null `error` means the reload was rejected and the
**previous** config is still active. Cross-check with logs and metrics:

```bash
sudo journalctl -u tardigrade -n 50 --no-pager | grep -i reload
curl -s http://127.0.0.1:8069/status/metrics | grep tardigrade_reload
```

Expect one of `configuration hot-reload starting` /
`configuration hot-reload applied` (success) or `config reload failed during
load: …` / `config reload rejected by validation: …` / `config reload
rejected: … restart the process …` (failure) in the runtime log around the
time you reloaded.

### Likely causes

- **the reload was rejected** — the `reload/status` endpoint and logs above
  will say so explicitly; the previously published config stays active
- **the field you changed is not reload-eligible.** Tardigrade classifies
  every setting into one of three buckets — see the [full matrix in
  CONFIGURATION.md](CONFIGURATION.md#reload-behavior):
  1. reloadable in place (routing, TLS credentials, rate limits, buffer
     limits, log level, etc.) — takes effect immediately on the next
     request after publication;
  2. **reload rejected outright**, restart required (listener-shard
     topology, HTTP/3 listener-owned settings, native early-data
     replay/ticket-key mode, appliance TLS credential identity) — `SIGHUP`
     refuses these and keeps the old config running rather than applying a
     partial change;
  3. **the reload "succeeds" and publishes the new config, but the specific
     live runtime state doesn't change until restart** (bound socket
     host/port, worker thread/queue counts, PID file, upstream-pool policy,
     session/approval/transcript store paths, general TLS context inputs,
     and more) — this is the easiest case to mistake for "reload is
     broken", because there's no rejection to see.
- **you edited `tardigrade.env`, not `tardigrade.conf`** — `SIGHUP` reloads
  the *config*; it cannot change the *process environment* of an
  already-running process. `tardigrade.env` (and any
  `EnvironmentFile=`/Compose `env_file:` source) only takes effect on the
  next full restart. This includes systemd `EnvironmentFile=` changes —
  editing the file never touches a process that's already running.
- **`master_process true;`**: PID-file/`SIGHUP` reload does not yet provide
  coherent control across all workers in master/worker mode — use
  `systemctl restart tardigrade` instead of reload when running with a
  master process. See [DEPLOYMENT.md's master/worker
  section](DEPLOYMENT.md#commands).
- **an in-flight request observed the old config** — in-flight requests
  keep their request-scoped config lease across a reload by design; only
  new requests after publication acquire the new version. This is expected
  behavior, not a bug, and resolves itself as soon as the in-flight request
  completes.

### Concrete fixes

For a rejected reload: fix whatever `reload/status`/the logs say is wrong,
then reload again. For a restart-required field: `sudo systemctl restart
tardigrade` (or recreate the Docker container) instead of reload — reload
will never apply it. For a `tardigrade.env` edit: restart, not reload.

### Verify the fix

```bash
curl -s http://127.0.0.1:8069/tardigrade/reload/status
curl -s http://127.0.0.1:8069/status/metrics | grep -E 'tardigrade_reload_(success|failure)_total'
```

`ok: true` and a fresh `at_ms`, with `reload_success_total` incremented and
`reload_failure_total` unchanged since your attempt, confirms the reload
actually installed. Then re-check the specific behavior you changed against
a live request — not just `tardi print-config` against the file.

### Related documentation

- [RELOAD_SHUTDOWN.md](RELOAD_SHUTDOWN.md) — full hot-reload/drain/shutdown
  contract.
- [CONFIGURATION.md — Reload Behavior](CONFIGURATION.md#reload-behavior) —
  the complete reloadable/restart-required/publish-but-inactive matrix.
- [examples/graceful-reload](../examples/graceful-reload/README.md).

## 12. Performance appears worse than expected

### Symptoms

Latency or throughput looks worse than published benchmark numbers, or
worse than you expect for the workload.

### First checks

Confirm you're actually running a release build — a debug build is
substantially slower and is not what published benchmarks measure:

```bash
zig build -Doptimize=ReleaseFast
./zig-out/bin/tardi version
```

Then rule out the most common false alarms before assuming a Tardigrade
regression:

- Are you hitting the intended route/server/protocol? A request that falls
  through to an unexpected `location` or upstream will not perform like the
  one you meant to measure — check with [§4](#4-route-does-not-match).
- Is the client reusing connections? Per-request TCP/TLS handshake
  overhead dominates small-request latency; compare with keep-alive.
- Is the slowness on Tardigrade's side or the upstream's? Time the origin
  directly (as in [§6](#6-upstream-returns-502--504--503)) before assuming
  Tardigrade is the bottleneck.

### Likely causes

- debug build instead of `ReleaseFast`
- rate limiting (`TARDIGRADE_RATE_LIMIT_RPS`) becoming the effective
  bottleneck and returning `429`s — a common benchmark-methodology mistake,
  not a real capacity problem; check
  [benchmarks/README.md's path-and-host-overrides
  note](../benchmarks/README.md#path-and-host-overrides)
- worker-pool queue saturation — check `tardigrade_worker_queued_jobs` vs.
  `tardigrade_worker_queue_capacity` and `tardigrade_worker_active_jobs` in
  `/status/metrics`; see the [overload troubleshooting table in
  OBSERVABILITY.md](OBSERVABILITY.md#operator-troubleshooting)
- upstream latency/saturation rather than local queueing — check
  `tardigrade_proxy_ttfb_ms` and the upstream directly
- excessive debug/synchronous logging (`error_log … debug;` in production)
- streaming vs. buffered proxy mode mismatch for large transfers — compare
  `tardigrade_proxy_streaming_requests_total` against
  `tardigrade_proxy_buffered_requests_total` for the route in question; see
  [PROXY_STREAMING.md](PROXY_STREAMING.md)
- **comparing an ad hoc laptop/debug run against published benchmark
  numbers.** Published Tardigrade benchmark numbers are captured on a
  dedicated, idle, deployment-class target, not a shared laptop — a laptop
  can measure 2-3x faster or slower than a real deployment target purely
  from CPU/scheduling differences. Treat any local run as a smoke test, not
  a regression signal, unless it's run with matched hardware, concurrency,
  and protocol against the baseline you're comparing to.

### Concrete fixes

Rebuild in `ReleaseFast`, fix the false-alarm cause you found above, or tune
the specific limit/timeout the metrics point at (see
[OBSERVABILITY.md's tuning principle](OBSERVABILITY.md#configured-limits):
raise a limit only after confirming headroom exists to honor it).

### Verify the fix

Reproduce your benchmark with the same tool, path, concurrency, and
protocol you used for the original comparison:

```bash
./benchmarks/run.sh \
  --host 127.0.0.1 \
  --pid-file /run/tardigrade/tardigrade.pid \
  --scenarios static-http1,proxy-http1,keepalive
```

Compare `p50`/`p95`/`p99` and `req/s` against your actual baseline, not
against the README's headline numbers unless your hardware and workload
genuinely match theirs.

### Related documentation

- [benchmarks/README.md](../benchmarks/README.md) — full benchmark
  methodology, measurement-reliability pitfalls, and scenario list.
- [OBSERVABILITY.md — Resource Limits and Overload Behavior](OBSERVABILITY.md#resource-limits-and-overload-behavior).
- [PROXY_STREAMING.md](PROXY_STREAMING.md) — streaming vs. buffered proxy
  behavior.

## 13. Still stuck?

Before filing an issue, check whether the surface you're troubleshooting is
listed as `stable` in the [Core v1 support matrix](SUPPORT_MATRIX.md).
Experimental surfaces (HTTP/2, HTTP/3/QUIC, WebSocket/SSE, ACME, auth/session
extensions, DNS-driven upstream discovery, and more) carry weaker
operational guarantees than the stable HTTP/1.1 core, and a rough edge there
may be expected rather than a bug.

If you're still stuck, open a [GitHub
issue](https://github.com/Bare-Systems/Tardigrade/issues) with this filled
in:

```text
Tardigrade version:
Installation method:
OS/distribution:
Deployment: shell / systemd / Docker
Affected protocol: HTTP/1.1 / HTTP/2 / HTTP/3
Support-matrix maturity:
Exact command:
Config path:
Relevant config section (secrets removed):
Expected result:
Actual result:
HTTP status/error:
Relevant log lines:
Output of tardi print-config:
Output of tardi routes, if routing-related:
Output of tardi upstreams, if proxy-related:
Relevant metrics:
```

Get the version with `tardi version`.

**Redact before pasting**: TLS private key contents, bearer/API tokens,
secret-store keys and values, credentials embedded in URLs
(`https://user:pass@host/`), session tokens, and any TLS keylog/qlog
material (`TARDIGRADE_HTTP3_KEYLOG_PATH` output decrypts traffic). Don't
over-redact past that — listener addresses, route patterns, upstream
hostnames, and HTTP status codes are exactly what a maintainer needs and
are not secrets by default.

For suspected security vulnerabilities specifically, use
[SECURITY.md](../SECURITY.md) instead of a public issue.

### Related documentation

- [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) — stable vs. experimental surface.
- [SECURITY.md](../SECURITY.md) — vulnerability reporting.
