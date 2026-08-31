<h1 align="center">Tardigrade</h1>

<p align="center">
  <strong>A small Zig edge server for static file serving, reverse proxying, TLS termination, and operator-friendly reloads.</strong>
</p>

<p align="center">
  <a href="https://github.com/Bare-Systems/Tardigrade/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Bare-Systems/Tardigrade/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/Bare-Systems/Tardigrade/actions/workflows/scorecard.yml"><img alt="OSSF Scorecard" src="https://github.com/Bare-Systems/Tardigrade/actions/workflows/scorecard.yml/badge.svg"></a>
  <a href="https://github.com/Bare-Systems/Tardigrade/releases"><img alt="GitHub release" src="https://img.shields.io/github/v/release/Bare-Systems/Tardigrade?include_prereleases"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Bare-Systems/Tardigrade"></a>
</p>

---

Tardigrade is a lightweight Zig edge server and reverse proxy for deployments
that want a small native binary, stable HTTP/1.1, HTTP/2, and HTTP/3/QUIC
downstream serving, config-driven routing, observable runtime behavior, and
predictable reloads.

## Install

```bash
brew tap bare-systems/tap
brew install tardigrade
```

Then confirm the command is available:

```bash
tardi version
```

## Start with the simplest setup

```bash
mkdir -p public
printf '%s\n' '<h1>Hello from Tardigrade</h1>' > public/index.html

tardi init static > tardigrade.conf
tardi check
tardi run
```

Open:

- http://localhost:8080/
- http://localhost:8080/health

This serves the static site and includes a health endpoint.

## Common ways to run Tardigrade

### 1. Static site

```bash
tardi init static > tardigrade.conf
tardi run
```

Use this for serving local assets or a simple website.

### 2. Reverse proxy

```bash
tardi init proxy > tardigrade.conf
tardi run
```

This creates a basic upstream proxy config. The default local setup points at a local upstream service.

### 3. Use a specific config file

```bash
tardi check ./my-site.conf
tardi run -c ./my-site.conf
```

This is useful when you want to keep multiple config files for different environments.

### 4. TLS termination example

```bash
tardi init tls > tardigrade.conf
```

Set the certificate/key paths and your upstream in `tardigrade.conf`, then:

```bash
tardi check
tardi run
```

See the [TLS termination example](examples/tls-termination/README.md) for a complete setup.

## Useful commands

```bash
tardi --help
tardi check ./tardigrade.conf
tardi run -c ./tardigrade.conf
tardi version
```

## Features

- Static file serving with normalized paths, range requests, cache validation, and
  symlink escape protection.
- Reverse proxying with config-driven routing, upstream health checks, retries
  for safe connection drops, and bounded streaming for larger transfers.
- TLS termination for stable HTTP/1.1 and HTTP/2 over TCP, plus native
  HTTP/3/QUIC over UDP.
- Hot reloads and graceful drain behavior for operator-managed deployments.
- Structured access logs, request IDs, W3C `traceparent` forwarding, and
  Prometheus metrics at `/status/metrics` by default.
- Request limits, rate limiting, security headers, and release-gated security
  regression tests.
- Native packaging with release archives, DEB/RPM packages, service files,
  checksums, SBOMs, and provenance attestation.

The stable Core v1 contract covers the documented HTTP/1.1, HTTP/2, and
HTTP/3/QUIC edge paths. WebSocket/SSE, ACME, FastCGI, uWSGI, SCGI, memcached,
and BearClaw-specific flows exist in-tree, but they are not all stable Core v1
surfaces. Check the [support matrix](docs/SUPPORT_MATRIX.md) before depending
on a specific feature.

## More info

For full configuration details and advanced deployment options, see:

<p align="center">
  <a href="docs/QUICKSTART.md"><strong>Quickstart</strong></a> |
  <a href="https://github.com/Bare-Systems/Tardigrade/releases">Releases</a> |
  <a href="docs/SUPPORT_MATRIX.md">Support Matrix</a> |
  <a href="docs/CONFIGURATION.md">Configuration</a> |
  <a href="docs/OBSERVABILITY.md">Observability</a> |
  <a href="docs/DEPLOYMENT.md">Deployment</a> |
  <a href="docs/TROUBLESHOOTING.md">Troubleshooting</a> |
  <a href="SECURITY.md">Security</a> |
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

Performance methodology, reproducible harnesses, and the latest committed benchmark report are in [benchmarks/README.md](benchmarks/README.md).

This project is licensed under the Apache License 2.0.
