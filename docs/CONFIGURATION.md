# Configuration Reference

This reference documents the public Tardigrade configuration surface loaded by
`EdgeConfig` and the nginx-style config-file adapter.

Configuration precedence is:

1. Built-in defaults.
2. `TARDIGRADE_CONFIG_PATH`, when set, parsed as an nginx-style config file.
3. `TARDIGRADE_SECRETS_PATH` and `TARDIGRADE_SECRET_KEYS`, when set.
4. Environment variables, which override file-config values.

Validate before startup:

```bash
./zig-out/bin/tardi check ./tardigrade.conf
./zig-out/bin/tardi config validate ./tardigrade.conf
```

For copy/paste-runnable configs, see [examples/](../examples/README.md):
[static files](../examples/static-file-server/README.md),
[reverse proxy](../examples/reverse-proxy/README.md),
[TLS termination](../examples/tls-termination/README.md),
[virtual hosts](../examples/virtual-hosts/README.md),
[health checks](../examples/health-checks/README.md),
[rate limiting](../examples/rate-limiting/README.md),
[access logs](../examples/access-logs/README.md),
[Prometheus metrics](../examples/prometheus-metrics/README.md),
[graceful reload](../examples/graceful-reload/README.md), and
[production baseline](../examples/production-baseline/README.md).

## Config File Syntax

Config files are nginx-inspired. Directives end in `;`; `server {}` and
`location {}` blocks are supported; `#` starts a comment. `include` accepts a
path or a single `*` glob suffix, and relative includes resolve from the current
file. `set $name value;` defines variables referenced as `${name}`. Environment
variables can also be interpolated with `${NAME}`.

Unknown top-level directives are normalized to environment keys by uppercasing,
replacing `-` with `_`, and prefixing `TARDIGRADE_`. For example,
`upstream_timeout_ms 5000;` maps to `TARDIGRADE_UPSTREAM_TIMEOUT_MS=5000`.

## Core Directives

| Directive | Env key | Type | Default | Notes |
| --- | --- | --- | --- | --- |
| `include` | n/a | path/glob | n/a | Parses another config file. A single `*` suffix is supported. |
| `set` | n/a | variable | n/a | Defines a config variable without the leading `$`. |
| `listen` | `TARDIGRADE_LISTEN_HOST`, `TARDIGRADE_LISTEN_PORT`, `TARDIGRADE_HTTP2_ENABLED` | host/port | `0.0.0.0:8069` | Accepts `host:port`, `port`, or `host`; `http2` flag enables HTTP/2. Ports must be 1-65535. |
| `worker_processes` | `TARDIGRADE_WORKER_PROCESSES` | u32 | `1` | `auto` maps to `0`; used with master-process mode. |
| `worker_connections` | `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | u32 | `0` | `0` means unlimited active client connections. |
| `pid` | `TARDIGRADE_PID_FILE` | path | `""` | Empty disables pid-file writing. |
| `user` | `TARDIGRADE_RUN_USER`, `TARDIGRADE_RUN_GROUP` | names | `""` | First token is user; optional second token is group. |
| `error_log` | `TARDIGRADE_ERROR_LOG_PATH`, `TARDIGRADE_LOG_LEVEL` | path + enum | `""`, `info` | Levels: `debug`, `info`, `warn`, `error`. |
| `secrets_file` | `TARDIGRADE_SECRETS_PATH` | path | `""` | Loads secret overrides from a separate file. |
| `secret_key` | `TARDIGRADE_SECRET_KEYS` | string/list | `""` | Inline secret override source. Prefer files in production. |

## Server Blocks

Top-level `server_name`, `root`, and `try_files` configure the default virtual
host. `server {}` blocks add per-host overrides. See the
[virtual-hosts example](../examples/virtual-hosts/README.md).

| Directive | Type | Default | Notes |
| --- | --- | --- | --- |
| `server_name` | list | `[]` | Hostnames for this block. A block with no names is the default block. |
| `root` | path | `""` | Per-server static root. |
| `try_files` | string/list | `""` | Per-server static fallback. |
| `tls_cert_path` | path | `""` | Per-server TLS cert. With `tls_key_path`, also adds SNI certs for block names. |
| `tls_key_path` | path | `""` | Per-server TLS key. Must be paired with cert path. |
| `upstream_base_url` | URL | `""` | Per-server default reverse-proxy upstream. |
| `proxy_pass_chat` | URL | `""` | BearClaw/chat route upstream. |
| `proxy_pass_commands_prefix` | URL/path | `""` | BearClaw commands prefix upstream. |
| nested `location` | block | `[]` | Locations scoped to this server block. |

## Location Blocks

Location matching follows nginx-style precedence: exact matches, then `^~`
priority prefixes, then regexes in declaration order, then the longest plain
prefix. Each location must choose one action family: proxy, FastCGI/SCGI/uWSGI,
return, rewrite, or static.

| Directive | Type | Default | Notes |
| --- | --- | --- | --- |
| `location = /path` | matcher | n/a | Exact match. |
| `location ^~ /path/` | matcher | n/a | Prefix priority. |
| `location ~ pattern` | matcher | n/a | Case-sensitive regex. |
| `location ~* pattern` | matcher | n/a | Case-insensitive regex. |
| `location /path/` | matcher | n/a | Plain prefix. |
| `proxy_pass` | URL/path | n/a | Proxies matching requests. |
| `fastcgi_pass` | endpoint | n/a | FastCGI upstream. |
| `scgi_pass` | endpoint | n/a | SCGI upstream. |
| `uwsgi_pass` | endpoint | n/a | uWSGI upstream. |
| `root` | path | n/a | Serves files under root. |
| `alias` | path | n/a | Serves files from alias path. |
| `index` | filename | `index.html` | Directory index fallback. Set `""` to opt out. |
| `autoindex` | bool | `off` | `on`, `off`, `true`, `false`. |
| `try_files` | string/list | `""` | Location-level candidate list. |
| `return` | status/body | n/a | Status u16 and optional response body. |
| `rewrite` | pattern/replacement/flag | n/a | Default flag is `last`. |
| `error_page` | statuses/target | `[]` | Status codes followed by path or HTTP(S) URL target. |
| `auth` | enum | `off` | `off`, `required`. |
| `proxy_streaming` / `proxy_streaming_mode` | enum | `inherit` | `inherit`, `off`/`buffered`, `response`, `full`/`request-response`. |
| `early_data` | enum | `off` | `off`, `replay_safe`/`replay-safe`. |
| `proxy_early_data` | enum | `off` | `off`, `rfc8470`/`rfc-8470`; valid only with `proxy_pass`. |

## Field Reference

All fields are optional unless noted. Empty string defaults generally disable
the feature or let runtime code choose a fallback. Boolean parsing accepts
`true`/`1` as true for permissive bool fields.

### Listener And Protocol

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_LISTEN_HOST` | string | `0.0.0.0` | Bind address. |
| `TARDIGRADE_LISTEN_PORT` | u16 | `8069` | 1-65535. |
| `TARDIGRADE_HTTP1_ENABLED` | bool | `true` | Enables HTTP/1.1. |
| `TARDIGRADE_HTTP2_ENABLED` | bool | `true` | Enables HTTP/2 where supported. |
| `TARDIGRADE_TLS_HTTP1_NO_ALPN_FALLBACK` | bool | `false` | Allows HTTP/1.1 on TLS clients that omit ALPN. |
| `TARDIGRADE_PROXY_PROTOCOL` | enum | `off` | `off`, `auto`, `v1`, `v2`. |
| `TARDIGRADE_PROXY_STREAMING_MODE` | enum | `off` | `off`/`buffered`, `response`, `full`/`request-response`. |
| `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` | bytes | `16384` | 1-1048576; must fit proxy buffer hard limit. |
| `TARDIGRADE_PROXY_STREAM_ALL_STATUSES` | bool | `false` | Stream all upstream statuses instead of mapping non-200 responses. |

### Routing And Static Serving

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_SERVER_NAMES` | list | `[]` | Comma or whitespace separated host patterns. Empty matches any host. |
| `TARDIGRADE_DOC_ROOT` | path | `""` | Enables static fallback when set. |
| `TARDIGRADE_TRY_FILES` | string/list | `""` | Candidate list; supports `$uri`. |
| `TARDIGRADE_SERVER_BLOCKS` | encoded list | `""` | Internal representation generated by `server {}` blocks. Prefer config-file blocks. |
| `TARDIGRADE_LOCATION_BLOCKS` | encoded list | `""` | Internal representation generated by `location {}` blocks. Prefer config-file blocks. |
| `TARDIGRADE_LOCATION_ERROR_PAGES` | encoded list | `""` | Internal error-page representation. Prefer `error_page` in locations. |
| `TARDIGRADE_INTERNAL_REDIRECT_RULES` | encoded list | `""` | `method|pattern|target;...`; target can be a path or named location. |
| `TARDIGRADE_NAMED_LOCATIONS` | encoded list | `""` | `name|path;...`. |
| `TARDIGRADE_MIRROR_RULES` | encoded list | `""` | `method|pattern|target_url;...`; best-effort async copies. |
| `TARDIGRADE_REWRITE_RULES` | encoded list | `""` | `method|pattern|replacement|flag;...`; config-file `rewrite` is preferred. |
| `TARDIGRADE_RETURN_RULES` | encoded list | `""` | `method|pattern|status|body;...`; config-file `return` is preferred. |
| `TARDIGRADE_CONDITIONAL_RULES` | encoded list | `""` | Encoded inline `if (...) return|rewrite` rules. |

### Proxy And Upstreams

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_BASE_URL` | URL | `http://127.0.0.1:8080` | Default upstream. |
| `TARDIGRADE_UPSTREAM_BASE_URLS` | CSV URLs | `[]` | Primary upstream pool. |
| `TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS` | CSV u32 | `[]` | Nonzero weights; count must match `UPSTREAM_BASE_URLS`. |
| `TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS` | CSV URLs | `[]` | Backup upstreams. |
| `TARDIGRADE_UPSTREAM_CHAT_BASE_URLS` | CSV URLs | `[]` | Chat-specific upstream pool. |
| `TARDIGRADE_UPSTREAM_CHAT_BASE_URL_WEIGHTS` | CSV u32 | `[]` | Nonzero weights; count must match chat URLs. |
| `TARDIGRADE_UPSTREAM_CHAT_BACKUP_BASE_URLS` | CSV URLs | `[]` | Chat backup upstreams. |
| `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS` | CSV URLs | `[]` | Commands-specific upstream pool. |
| `TARDIGRADE_UPSTREAM_COMMANDS_BASE_URL_WEIGHTS` | CSV u32 | `[]` | Nonzero weights; count must match command URLs. |
| `TARDIGRADE_UPSTREAM_COMMANDS_BACKUP_BASE_URLS` | CSV URLs | `[]` | Commands backup upstreams. |
| `TARDIGRADE_UPSTREAM_LB_ALGORITHM` | enum | `round_robin` | `round_robin`, `least_connections`, `ip_hash`, `generic_hash`, `random_two_choices`; hyphen variants accepted. |
| `TARDIGRADE_UPSTREAM_PROTOCOL` | enum | `http1` | `http1`/`http/1.1`/`h1`, `h2`/`http2`, `auto`, `h2c`. |
| `TARDIGRADE_UPSTREAM_TIMEOUT_MS` | u32 ms | `10000` | Per-attempt upstream timeout. |
| `TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS` | u32 ms | `5000` | Upstream TCP connect timeout; `0` disables. |
| `TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS` | u32 ms | `0` | Wait for upstream response start; `0` falls back to upstream timeout. |
| `TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS` | u64 ms | `0` | Total budget across attempts; `0` disables. |
| `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` | u32 | `1` | Minimum effective value is `1`. |
| `TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY` | bool | `true` | Restricts retries to idempotent methods. |
| `TARDIGRADE_UPSTREAM_POOL_ENABLED` | bool | `true` | Reuse plain-HTTP upstream connections. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST` | usize | `32` | Idle pooled connections per origin. |
| `TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS` | u64 ms | `90000` | Idle pool eviction age. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS` | u64 ms | `0` | Hard pooled-connection lifetime; `0` disables. |
| `TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST` | usize | `0` | Concurrent checked-out upstream connections per origin; `0` unlimited. |
| `TARDIGRADE_UPSTREAM_POOL_LOCK_METRICS` | bool | `false` | Benchmark-only lock wait counters. |
| `TARDIGRADE_UPSTREAM_GUNZIP_ENABLED` | bool | `true` | Request gzip from upstream and gunzip in gateway. |
| `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` | bytes | `262144` | Must be at least 1. |
| `TARDIGRADE_PROXY_PASS_CHAT` | URL | `""` | BearClaw/chat route upstream. |
| `TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX` | URL/path | `""` | BearClaw commands route prefix/upstream. |

### Upstream TLS

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_TLS_VERIFY` | bool | `true` | Verify HTTPS upstream certificates. False logs a warning. |
| `TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE` | path | `""` | PEM CA bundle. Empty uses system defaults. |
| `TARDIGRADE_UPSTREAM_TLS_SERVER_NAME` | hostname | `""` | Overrides upstream SNI. Empty uses URL hostname. |
| `TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT` | path | `""` | PEM client certificate for upstream mTLS. |
| `TARDIGRADE_UPSTREAM_TLS_CLIENT_KEY` | path | `""` | PEM client private key for upstream mTLS. |

### Health Checks And Circuit Breaking

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_CB_THRESHOLD` | u32 | `0` | Circuit breaker failure threshold; `0` disables. |
| `TARDIGRADE_CB_TIMEOUT_MS` | u64 ms | `30000` | Open timeout before half-open probe. |
| `TARDIGRADE_UPSTREAM_MAX_FAILS` | u32 | `0` | Passive health failure threshold; `0` disables. |
| `TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS` | u64 ms | `10000` | Passive failure retry timeout. |
| `TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS` | u64 ms | `0` | Primary active-probe interval; `0` disables. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS` | u64 ms | `0` | Fallback alias for probe interval. |
| `TARDIGRADE_UPSTREAM_PROBE_PATH` | path | `/` | Primary active-probe path. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH` | path | `/` | Fallback alias for probe path. |
| `TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS` | u32 ms | `2000` | Primary active-probe timeout. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS` | u32 ms | `2000` | Fallback alias for probe timeout. |
| `TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD` | u32 | `1` | Primary active-probe failure threshold; minimum effective value is 1. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD` | u32 | `1` | Fallback alias for fail threshold. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD` | u32 | `1` | Consecutive successes before clearing unhealthy; minimum effective value is 1. |
| `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS` | status/range | `200-299` | Single u16 status or inclusive `min-max`. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS` | status/range | `200-299` | Fallback alias for success range. |
| `TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS_OVERRIDES` | encoded list | `""` | `upstream_url|status-or-range;...`. |
| `TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS_OVERRIDES` | encoded list | `""` | Fallback alias for success overrides. |
| `TARDIGRADE_UPSTREAM_SLOW_START_MS` | u64 ms | `0` | Slow-start window for recovered upstreams; `0` disables. |

### TLS Termination

General release binaries use the OpenSSL-backed TLS profile. The
appliance/native profile has a stricter TLS 1.3-only subset.

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_TLS_CERT_PATH` | path | `""` | Required for TLS; must be paired with key path. |
| `TARDIGRADE_TLS_KEY_PATH` | path | `""` | Required for TLS; must be paired with cert path. |
| `TARDIGRADE_TLS_MIN_VERSION` | string | `1.2` general, `1.3` appliance | Appliance profile requires `1.3`. |
| `TARDIGRADE_TLS_MAX_VERSION` | string | `1.3` | Appliance profile requires `1.3`. |
| `TARDIGRADE_TLS_CIPHER_LIST` | string | `""` | OpenSSL TLS <=1.2 cipher list. Appliance profile requires empty. |
| `TARDIGRADE_TLS_CIPHER_SUITES` | string | `""` | TLS 1.3 cipher suites. Appliance profile requires empty. |
| `TARDIGRADE_TLS_SERVER_NAME` | DNS name | `""` | Appliance profile requires a single non-wildcard DNS host name when TLS is enabled. |
| `TARDIGRADE_TLS_SNI_CERTS` | encoded list | `""` | Additional SNI certs as `name|cert|key;...`. Appliance profile requires empty. |
| `TARDIGRADE_TLS_SESSION_CACHE` | bool | `true` general, `false` appliance | OpenSSL session cache. Appliance profile rejects true. |
| `TARDIGRADE_TLS_SESSION_CACHE_SIZE` | u32 | `20480` | OpenSSL session cache size. |
| `TARDIGRADE_TLS_SESSION_TIMEOUT_SECONDS` | u32 | `300` | OpenSSL session timeout. |
| `TARDIGRADE_TLS_SESSION_TICKETS` | bool | `true` general, `false` appliance | OpenSSL ticket support. Appliance profile rejects true. |
| `TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS` | u32 ms | `5000` | TLS handshake read timeout. `0` falls back to keep-alive timeout. |
| `TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS` | u64 ms | `5000` general, `0` appliance | OpenSSL cert/key watcher interval. Appliance profile requires `0`. |
| `TARDIGRADE_TLS_CLIENT_CA_PATH` | path | `""` | Required when `TARDIGRADE_TLS_CLIENT_VERIFY=true`. |
| `TARDIGRADE_TLS_CLIENT_VERIFY` | bool | `false` | Downstream client cert verification. Appliance profile rejects true. |
| `TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH` | u32 | `3` | Client certificate chain depth. |
| `TARDIGRADE_TLS_CRL_PATH` | path | `""` | CRL file. |
| `TARDIGRADE_TLS_CRL_CHECK` | bool | `false` | Enable CRL checking. Appliance profile rejects true. |
| `TARDIGRADE_TLS_OCSP_STAPLING` | bool | `false` | Enable OCSP stapling. Appliance profile rejects true. |
| `TARDIGRADE_TLS_OCSP_RESPONSE_PATH` | path | `""` | DER OCSP response path. |
| `TARDIGRADE_TLS_OCSP_AUTO_REFRESH` | bool | `false` | Refresh OCSP response automatically. Appliance profile rejects true. |
| `TARDIGRADE_TLS_OCSP_REFRESH_INTERVAL_MS` | u64 ms | `3600000` | OCSP refresh interval. |
| `TARDIGRADE_TLS_OCSP_REFRESH_TIMEOUT_MS` | u32 ms | `10000` | OCSP refresh timeout. |

### Native TLS Resumption And Replay

These settings affect native pure-Zig TLS-over-TCP and QUIC/H3 engines, not
OpenSSL `TARDIGRADE_TLS_SESSION_*` behavior.

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_TLS_NATIVE_RESUMPTION_MODE` | enum | `disabled` | `disabled`, `stateful`, `stateless`, `hybrid`. |
| `TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_LIFETIME_SECONDS` | u32 seconds | `86400` | Must be nonzero and within native session policy when enabled. |
| `TARDIGRADE_TLS_NATIVE_RESUMPTION_TICKET_USAGE` | enum | `reusable` | `reusable`, `single_use`. |
| `TARDIGRADE_TLS_NATIVE_TICKET_KEYS_PATH` | path | `""` | Requires `stateless` or `hybrid`. Reload mode changes may require restart. |
| `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE` | enum | `disabled` | `disabled`, `process_local`. Replay-store topology changes require restart. |
| `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES` | usize | `65536` | Strictly parsed. Must be 1-1048576. |

### TLS Buffer Limits

Each TLS buffer scope has three byte fields:
`<PREFIX>_LOW_WATERMARK_BYTES`, `<PREFIX>_HIGH_WATERMARK_BYTES`, and
`<PREFIX>_HARD_LIMIT_BYTES`. Prefixes are
`TARDIGRADE_TLS_INBOUND_CIPHERTEXT`, `TARDIGRADE_TLS_INBOUND_PLAINTEXT`,
`TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT`, and `TARDIGRADE_TLS_HANDSHAKE`.

Values must be positive with `low < high <= hard`; hard limits must fit native
TLS stream capacity. Defaults are derived from native stream queue capacities:
low is about one quarter of capacity, high about three quarters, and hard is
capacity.

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES` | bytes | derived | Positive; less than corresponding high watermark. |
| `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES` | bytes | derived | Positive; greater than low and `<=` hard. |
| `TARDIGRADE_TLS_INBOUND_CIPHERTEXT_HARD_LIMIT_BYTES` | bytes | derived | Positive; native inbound ciphertext queue hard limit. |
| `TARDIGRADE_TLS_INBOUND_PLAINTEXT_LOW_WATERMARK_BYTES` | bytes | derived | Positive; less than corresponding high watermark. |
| `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HIGH_WATERMARK_BYTES` | bytes | derived | Positive; greater than low and `<=` hard. |
| `TARDIGRADE_TLS_INBOUND_PLAINTEXT_HARD_LIMIT_BYTES` | bytes | derived | Positive; native inbound plaintext queue hard limit. |
| `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_LOW_WATERMARK_BYTES` | bytes | derived | Positive; less than corresponding high watermark. |
| `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HIGH_WATERMARK_BYTES` | bytes | derived | Positive; greater than low and `<=` hard. |
| `TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT_HARD_LIMIT_BYTES` | bytes | derived | Positive; native outbound ciphertext queue hard limit. |
| `TARDIGRADE_TLS_HANDSHAKE_LOW_WATERMARK_BYTES` | bytes | derived | Positive; less than corresponding high watermark. |
| `TARDIGRADE_TLS_HANDSHAKE_HIGH_WATERMARK_BYTES` | bytes | derived | Positive; greater than low and `<=` hard. |
| `TARDIGRADE_TLS_HANDSHAKE_HARD_LIMIT_BYTES` | bytes | derived | Positive; native handshake queue hard limit. |

### ACME

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_TLS_ACME_ENABLED` | bool | `false` | Enable ACME. Appliance profile rejects true. |
| `TARDIGRADE_TLS_ACME_CERT_DIR` | path | `""` | Certificate storage directory. |
| `TARDIGRADE_TLS_ACME_DIRECTORY_URL` | URL | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL. |
| `TARDIGRADE_TLS_ACME_DOMAINS` | CSV DNS names | `[]` | Domains to obtain/renew. Empty logs a warning when ACME is enabled. |
| `TARDIGRADE_TLS_ACME_EMAIL` | email | `""` | ACME account email. |
| `TARDIGRADE_TLS_ACME_ACCOUNT_KEY_PATH` | path | `""` | PEM ECDSA P-256 account key path; created on first run. |
| `TARDIGRADE_TLS_ACME_RENEW_DAYS_BEFORE_EXPIRY` | u32 days | `30` | Renewal trigger window. |

### HTTP/3 And QUIC

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_HTTP3_ENABLED` | bool | `false` | Enables native QUIC/H3. Requires TLS identity in native paths. |
| `TARDIGRADE_QUIC_PORT` | u16 | `443` | UDP QUIC listener port, 1-65535. |
| `TARDIGRADE_HTTP3_ALT_SVC` | enum | `off` | `off`, `auto`. |
| `TARDIGRADE_HTTP3_ALT_SVC_MAX_AGE_SECONDS` | u32 | `300` | `Alt-Svc` `ma` value. |
| `TARDIGRADE_HTTP3_ENABLE_0RTT` | bool | `false` | Enables 0-RTT. Logs replay warning; appliance profile rejects true. |
| `TARDIGRADE_HTTP3_CONNECTION_MIGRATION` | bool | `false` | QUIC connection migration; appliance profile rejects true. |
| `TARDIGRADE_HTTP3_RETRY_POLICY` | enum | `off` | `off`, `address_validation`/`address-validation`; appliance profile rejects non-off. |
| `TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE` | bytes | QUIC max | Bounds discovered send size; transport clamps to valid range. |
| `TARDIGRADE_HTTP3_UDP_RECV_BUFFER_BYTES` | bytes | `0` | Advisory socket receive buffer target. `0` leaves kernel sizing. |
| `TARDIGRADE_HTTP3_UDP_SEND_BUFFER_BYTES` | bytes | `0` | Advisory socket send buffer target. `0` leaves kernel sizing. |
| `TARDIGRADE_HTTP3_ECN` | bool | `true` | Enables QUIC ECN where supported. |

### Security, Auth, And Policy

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_AUTH_REQUEST_URL` | URL | `""` | External auth request endpoint. Empty disables. |
| `TARDIGRADE_JWT_SECRET` | secret | `""` | JWT secret. Redacted in config-conflict logs. |
| `TARDIGRADE_JWT_ISSUER` | string | `""` | Expected JWT issuer. |
| `TARDIGRADE_JWT_AUDIENCE` | string | `""` | Expected JWT audience. |
| `TARDIGRADE_BASIC_AUTH_HASHES` | CSV SHA-256 hex | `[]` | 64-char SHA-256 hashes of `user:password`. |
| `TARDIGRADE_AUTH_TOKEN_HASHES` | CSV SHA-256 hex | `[]` | 64-char SHA-256 hashes of bearer tokens. |
| `TARDIGRADE_SESSION_TTL_SECONDS` | u32 seconds | `3600` | Session TTL. |
| `TARDIGRADE_SESSION_MAX` | u32 | `128` | Max sessions retained. |
| `TARDIGRADE_SESSION_STORE_PATH` | path | `""` | File-backed session store. Path changes on reload require restart. |
| `TARDIGRADE_DEVICE_REGISTRY_PATH` | path | `""` | Device registry used by device-signature auth. |
| `TARDIGRADE_POLICY_RULES` | encoded string | `""` | Raw policy rules. |
| `TARDIGRADE_POLICY_USER_SCOPES` | encoded string | `""` | Raw user scope mapping. |
| `TARDIGRADE_POLICY_APPROVAL_ROUTES` | encoded string | `""` | Raw approval-route mapping. |
| `TARDIGRADE_APPROVAL_STORE_PATH` | path | `""` | Approval store. Path changes on reload require restart. |
| `TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK` | URL | `""` | Approval escalation webhook. Changes on reload require restart. |
| `TARDIGRADE_APPROVAL_TTL_MS` | i64 ms | `300000` | Approval token TTL. |
| `TARDIGRADE_APPROVAL_MAX_PENDING_PER_IDENTITY` | u32 | `0` | Pending approvals per identity; `0` disables this cap. |
| `TARDIGRADE_TRANSCRIPT_STORE_PATH` | path | `""` | Transcript store. Path changes on reload require restart. |
| `TARDIGRADE_TRUST_GATEWAY_ID` | string | `tardigrade-edge` | Gateway identity for signed upstream trust headers. |
| `TARDIGRADE_TRUST_SHARED_SECRET` | secret | `""` | Shared secret for upstream trust headers. Empty disables signing/verification. |
| `TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES` | CSV strings | `[]` | Accepted upstream identities when verification is enabled. |
| `TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY` | bool | `false` | Require signed upstream identity headers on responses. |
| `TARDIGRADE_SECURITY_HEADERS` | bool | `true` | Adds default security headers. |
| `TARDIGRADE_HSTS_ENABLED` | bool | `false` | Emits HSTS on HTTPS responses. |
| `TARDIGRADE_HSTS_MAX_AGE` | u32 seconds | `31536000` | HSTS max-age. |
| `TARDIGRADE_HSTS_INCLUDE_SUBDOMAINS` | bool | `true` | Adds `includeSubDomains`. |
| `TARDIGRADE_HSTS_PRELOAD` | bool | `false` | Adds `preload`. |
| `TARDIGRADE_GEO_BLOCKED_COUNTRIES` | CSV country codes | `[]` | Alphabetic ISO-style country codes from external country header. |
| `TARDIGRADE_GEO_COUNTRY_HEADER` | header name | `CF-IPCountry` | Header supplying country code. |
| `TARDIGRADE_ACCESS_CONTROL` | string | `""` | IP access control rules, e.g. `allow 10.0.0.0/8, deny 0.0.0.0/0`. |
| `TARDIGRADE_ADD_HEADERS` | encoded list | `""` | `Name: value|Name2: value2`; appended response headers. |

### Rate Limits And Request Limits

| Env key | Type | Config default | Effective behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_RATE_LIMIT_RPS` | f64 | `10` | Requests per second per client IP. `0` disables and logs a warning. |
| `TARDIGRADE_RATE_LIMIT_BURST` | u32 | `20` | Burst capacity. |
| `TARDIGRADE_MAX_BODY_SIZE` | bytes | `0` | `0` uses parser default `1048576`. |
| `TARDIGRADE_MAX_URI_LENGTH` | bytes | `0` | `0` uses parser default `8192`. |
| `TARDIGRADE_MAX_HEADER_COUNT` | usize | `0` | `0` uses parser default `100`. |
| `TARDIGRADE_MAX_HEADER_SIZE` | bytes | `0` | `0` uses parser default `8192`. |
| `TARDIGRADE_MAX_HEADERS_TOTAL_SIZE` | bytes | `0` | `0` uses parser default `32768`; over-limit requests return 431. |
| `TARDIGRADE_BODY_TIMEOUT_MS` | u32 ms | `0` | `0` uses parser default `30000`. |
| `TARDIGRADE_HEADER_TIMEOUT_MS` | u32 ms | `10000` | `0` uses parser default `10000`. |
| `TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS` | u32 ms | `0` | Overall request deadline; `0` disables. |
| `TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS` | u32 ms | `5000` | Idle keep-alive timeout; `0` disables. |
| `TARDIGRADE_DOWNSTREAM_WRITE_TIMEOUT_MS` | u32 ms | `30000` | Downstream write timeout; `0` disables explicit deadline. |
| `TARDIGRADE_MAX_REQUESTS_PER_CONNECTION` | u32 | `100` | `0` means unlimited. |
| `TARDIGRADE_MAX_CONNECTIONS_PER_IP` | u32 | `0` | `0` unlimited. Overridden by `TARDIGRADE_LIMIT_CONN_PER_IP` when that alias is non-empty. |
| `TARDIGRADE_LIMIT_CONN_PER_IP` | u32 alias | `""` | Compatibility alias for max connections per IP. |
| `TARDIGRADE_MAX_ACTIVE_CONNECTIONS` | u32 | `0` | Total active client connections; `0` unlimited. |
| `TARDIGRADE_MAX_IN_FLIGHT_REQUESTS` | u32 | `0` | Concurrent in-flight HTTP requests; `0` unlimited; returns 503 when exceeded. |

### Logging, Metrics, And Tracing

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_LOG_LEVEL` | enum | `info` | `debug`, `info`, `warn`, `error`. |
| `TARDIGRADE_ERROR_LOG_PATH` | path | `""` | Optional error-log destination; empty keeps stderr behavior. |
| `TARDIGRADE_ACCESS_LOG_FORMAT` | enum | `json` | `json`, `plain`, `custom`. |
| `TARDIGRADE_ACCESS_LOG_TEMPLATE` | string | `""` | Used when format is `custom`. |
| `TARDIGRADE_ACCESS_LOG_MIN_STATUS` | u16 | `0` | Minimum status logged; `0` logs all. |
| `TARDIGRADE_ACCESS_LOG_BUFFER_SIZE` | bytes | `0` | In-memory buffer before flush; `0` disables buffering. |
| `TARDIGRADE_ACCESS_LOG_SYSLOG_UDP` | host:port | `""` | Optional syslog UDP endpoint. |
| `TARDIGRADE_REDACT_HEADERS` | CSV header names | built-in list | Empty uses built-in redaction list. |
| `TARDIGRADE_METRICS_PATH` | path | `/status/metrics` | Empty disables Prometheus endpoint. |
| `TARDIGRADE_METRICS_REQUIRE_AUTH` | bool | `false` | Requires request auth before serving metrics. |
| `TARDIGRADE_OTEL_ENABLED` | bool | `false` | Enables W3C Trace Context propagation and OTLP export. |
| `TARDIGRADE_OTEL_ENDPOINT` | URL | `""` | OTLP/HTTP endpoint. |
| `TARDIGRADE_OTEL_SAMPLE_RATE` | u32 percent | `100` | Must be 0-100. |

`TARDIGRADE_LOG_ROTATE_MAX_BYTES` and `TARDIGRADE_LOG_ROTATE_MAX_FILES` are
consumed by the CLI log-rotation path, not `EdgeConfig`. Defaults are `0`
(rotation disabled) and `5`.

### Compression And Cache

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_COMPRESSION_ENABLED` | bool | `true` | Enables response compression. |
| `TARDIGRADE_COMPRESSION_MIN_SIZE` | bytes | `256` | Minimum body size to compress. |
| `TARDIGRADE_COMPRESSION_BROTLI_ENABLED` | bool | `true` | Enables Brotli compression. |
| `TARDIGRADE_COMPRESSION_BROTLI_QUALITY` | u32 | `5` | Must be 0-11. |
| `TARDIGRADE_IDEMPOTENCY_TTL` | u32 seconds | `300` | Idempotency cache TTL; `0` disables. |
| `TARDIGRADE_PROXY_CACHE_TTL_SECONDS` | u32 seconds | `0` | Proxy response cache TTL; `0` disables. |
| `TARDIGRADE_PROXY_CACHE_PATH` | path | `""` | Disk-backed/tiered cache path. |
| `TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE` | string | `method:path:payload_sha256` | Colon-separated tokens: `method`, `path`, `payload_sha256`, `identity`, `api_version`. |
| `TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS` | u32 seconds | `0` | Serve stale while revalidating after TTL expiry. |
| `TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS` | u32 ms | `250` | Wait for another request populating same cache key. |
| `TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS` | u64 ms | `30000` | Cache manager maintenance interval. |

### Runtime, Reload, And Workers

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_CONFIG_PATH` | path | unset | Config file to load when commands do not pass `-c/--config`. |
| `TARDIGRADE_PID_FILE` | path | `""` | Empty disables pid-file writing. |
| `TARDIGRADE_RUN_USER` | string | `""` | User for post-bind privilege drop. |
| `TARDIGRADE_RUN_GROUP` | string | `""` | Group for post-bind privilege drop. |
| `TARDIGRADE_CHROOT_DIR` | path | `""` | Chroot after bind. |
| `TARDIGRADE_REQUIRE_UNPRIVILEGED_USER` | bool | `false` | Require runtime to be unprivileged after startup. |
| `TARDIGRADE_WORKER_THREADS` | u32 | `0` | Connection-handling worker threads; `0` means auto CPU count. |
| `TARDIGRADE_LISTENER_SHARDS` | u16 | `0` | `0`/`1` single listener; `>1` starts parallel accept loops where supported. Topology changes require restart. |
| `TARDIGRADE_ACCEPT_BATCH_LIMIT` | u32 | `64` | Minimum effective value is 1. |
| `TARDIGRADE_ACCEPT_FAIRNESS_YIELD_EVERY` | u32 | `0` | Yield after this many accepts; `0` disables. |
| `TARDIGRADE_EVENT_LOOP_BACKEND` | enum | `default` | `default`, `epoll`, `kqueue`, `io_uring`; explicit unavailable backends fail startup. |
| `TARDIGRADE_EVENT_LOOP_IO_URING_ENTRIES` | u16 | `256` | 64-4096. Ignored by epoll/kqueue. |
| `TARDIGRADE_MASTER_PROCESS` | bool | `false` | Enables master process supervision mode. |
| `TARDIGRADE_WORKER_PROCESSES` | u32 | `1` | Worker processes in master mode. |
| `TARDIGRADE_BINARY_UPGRADE` | bool | `true` | Enables SIGUSR2 binary upgrade path. |
| `TARDIGRADE_WORKER_RECYCLE_SECONDS` | u32 seconds | `0` | Worker recycle interval; `0` disables. |
| `TARDIGRADE_WORKER_CPU_AFFINITY` | string | `""` | CPU list for worker role pinning. |
| `TARDIGRADE_WORKER_QUEUE_SIZE` | usize | `1024` | Max queued accepted connections waiting for workers. |
| `TARDIGRADE_WORKER_MAX_QUEUE_DEPTH` | usize | `0` | Per-worker queue depth; `0` no per-worker limit. |
| `TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS` | u64 ms | `30000` | Graceful drain timeout. `0` force-closes immediately. |
| `TARDIGRADE_FD_SOFT_LIMIT` | u64 | `0` | Desired `RLIMIT_NOFILE` soft limit; `0` leaves OS default. |
| `TARDIGRADE_CONNECTION_POOL_SIZE` | usize | `256` | Maximum idle connection sessions cached for reuse. |
| `TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES` | bytes | `2097152` | Max retained bytes per active connection; `0` unlimited. |
| `TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES` | bytes | `0` | Estimated total connection memory cap; `0` unlimited. |

`TARDIGRADE_VALIDATE_CONFIG_ONLY` is consumed by the CLI as a compatibility
validation switch. It is not part of `EdgeConfig`.

### Proxy Buffer Limits

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES` | bytes | `262144` | Must be positive and less than high watermark. |
| `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES` | bytes | `786432` | Must be `<=` hard limit and no larger than HTTP/2 max receive window. |
| `TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES` | bytes | `1048576` | Must be at least high watermark and at least effective streaming relay allocation. |
| `TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES` | bytes | `0` | `0` disables. Nonzero must be at least per-stream hard limit. |
| `TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES` | bytes | `0` | `0` disables. Nonzero must be at least per-stream hard limit. |

### Protocol Adapters

These surfaces are in-tree and configurable, but not all are part of the stable
Core v1 support contract. Check [support matrix](SUPPORT_MATRIX.md) before
depending on them in production.

| Env key / directive | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `fastcgi_pass` / `TARDIGRADE_FASTCGI_UPSTREAM` | endpoint | `""` | Top-level or location FastCGI upstream. |
| `fastcgi_index` / `TARDIGRADE_FASTCGI_INDEX` | filename | `index.php` | Default FastCGI directory index. |
| `fastcgi_param` / `TARDIGRADE_FASTCGI_PARAMS` | key/value list | `[]` | Directive appends `NAME value`; env format is `NAME=value|NAME2=value2`. |
| `scgi_pass` / `TARDIGRADE_SCGI_UPSTREAM` | endpoint | `""` | SCGI upstream. |
| `uwsgi_pass` / `TARDIGRADE_UWSGI_UPSTREAM` | endpoint | `""` | uWSGI upstream. |
| `smtp_pass` / `TARDIGRADE_SMTP_UPSTREAM` | endpoint | `""` | SMTP upstream. |
| `imap_pass` / `TARDIGRADE_IMAP_UPSTREAM` | endpoint | `""` | IMAP upstream. |
| `pop3_pass` / `TARDIGRADE_POP3_UPSTREAM` | endpoint | `""` | POP3 upstream. |
| `TARDIGRADE_GRPC_UPSTREAM` | URL | `""` | gRPC upstream base URL. |
| `TARDIGRADE_MEMCACHED_UPSTREAM` | endpoint | `""` | Memcached endpoint. |
| `TARDIGRADE_TCP_PROXY_UPSTREAM` | endpoint | `""` | Generic TCP proxy upstream. |
| `TARDIGRADE_UDP_PROXY_UPSTREAM` | endpoint | `""` | Generic UDP proxy upstream. |
| `TARDIGRADE_STREAM_SSL_TERMINATION` | bool | `false` | Enable stream-module SSL termination mode. |

### WebSocket And SSE

These are configurable in-tree surfaces outside the stable Core v1 baseline.

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_WEBSOCKET_ENABLED` | bool | `false` | Enables WebSocket handling. |
| `TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS` | u32 ms | `30000` | WebSocket idle timeout. |
| `TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE` | bytes | `65536` | Maximum WebSocket frame size. |
| `TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS` | u32 ms | `15000` | Ping interval. |
| `TARDIGRADE_SSE_ENABLED` | bool | `false` | Enables SSE handling. |
| `TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC` | usize | `128` | Retained events per topic. |
| `TARDIGRADE_SSE_POLL_INTERVAL_MS` | u32 ms | `250` | SSE poll interval. |
| `TARDIGRADE_SSE_MAX_BACKLOG` | u32 | `128` | Maximum SSE backlog. |
| `TARDIGRADE_SSE_IDLE_TIMEOUT_MS` | u32 ms | `30000` | SSE idle timeout. |

### DNS Discovery

| Env key | Type | Default | Valid values / behavior |
| --- | --- | --- | --- |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST` | hostname | `""` | When non-empty, periodically resolves A/AAAA addresses and merges them into upstream pool. |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT` | u16 | `80` | Port assigned to DNS-discovered addresses. |
| `TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS` | bool | `false` | Use HTTPS for DNS-discovered upstreams. |
| `TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS` | u64 ms | `30000` | Re-resolution interval. |

## Full Annotated Example

```nginx
worker_processes auto;
worker_connections 4096;
pid /run/tardigrade.pid;
error_log /var/log/tardigrade/error.log info;

listen 0.0.0.0:8443 http2;
tls_cert_path /etc/tardigrade/tls/fullchain.pem;
tls_key_path /etc/tardigrade/tls/privkey.pem;
tls_server_name edge.example.com;

server_name example.com www.example.com;
root /srv/www/example;
try_files $uri /index.html;

location = /health {
    return 200 ok;
}

location ^~ /assets/ {
    root /srv/www/example;
    index "";
    autoindex off;
}

location /api/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_streaming response;
}

server {
    server_name api.example.com;
    tls_cert_path /etc/tardigrade/tls/api.crt;
    tls_key_path /etc/tardigrade/tls/api.key;
    upstream_base_url http://127.0.0.1:9000;

    location = /health {
        return 200 api-ok;
    }

    location / {
        proxy_pass http://127.0.0.1:9000;
    }
}
```

Common production environment overrides:

```bash
export TARDIGRADE_CONFIG_PATH=/etc/tardigrade/tardigrade.conf
export TARDIGRADE_RATE_LIMIT_RPS=100
export TARDIGRADE_RATE_LIMIT_BURST=200
export TARDIGRADE_METRICS_PATH=/status/metrics
export TARDIGRADE_METRICS_REQUIRE_AUTH=true
export TARDIGRADE_ACCESS_LOG_FORMAT=json
export TARDIGRADE_REDACT_HEADERS=authorization,cookie,set-cookie
export TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS=3
export TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY=true
export TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS=5000
export TARDIGRADE_UPSTREAM_PROBE_PATH=/health
export TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS=30000
```

## Validation Notes

- `TARDIGRADE_TLS_CERT_PATH` and `TARDIGRADE_TLS_KEY_PATH` must be both set or
  both empty.
- `TARDIGRADE_TLS_CLIENT_VERIFY=true` requires `TARDIGRADE_TLS_CLIENT_CA_PATH`.
- `TARDIGRADE_COMPRESSION_BROTLI_QUALITY` must be 0-11.
- `TARDIGRADE_OTEL_SAMPLE_RATE` must be 0-100.
- `TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS` must be at least 1.
- `TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES` must be at least 1.
- `TARDIGRADE_PROXY_STREAM_BUFFER_SIZE` must be 1-1048576 bytes.
- Many integer fields use permissive parsing and fall back to defaults on
  malformed values. Replay and TLS buffer fields fail validation instead.
