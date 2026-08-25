# Tardigrade Quickstart

Run a local static site or reverse proxy with Tardigrade in a few minutes.

Tardigrade is the project/package name. The installed command is `tardi`.
Some installation formats may also provide `tardigrade` as a compatibility
alias, but examples on this page use `tardi`.

## Install

The official install script works for this guide:

```bash
curl -fsSL https://github.com/Bare-Systems/Tardigrade/releases/latest/download/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
tardi version
```

This installs `tardi` (with a `tardigrade` compatibility alias) into
`$HOME/.local/bin`; the `export` above puts that directory on `PATH` for
the current shell. The published release uses the native Zig shipping
profile — no OpenSSL runtime required for Tardigrade — and provides Linux
x86_64/aarch64 plus Intel and Apple Silicon macOS archives. See
[packaging/README.md](../packaging/README.md) for other install paths
(Homebrew, DEB/RPM, Docker) and exact current platform/release status.

To build from source instead:

```bash
git clone https://github.com/Bare-Systems/Tardigrade.git
cd Tardigrade
zig build -Doptimize=ReleaseFast
export PATH="$PWD/zig-out/bin:$PATH"
tardi version
```

The build above requires [Zig](https://ziglang.org/) 0.16.0 and does not
require OpenSSL to compile or run Tardigrade — the default `general` TLS
profile is pure-Zig native.

## Static-site happy path

From a clean directory:

```bash
mkdir -p public
printf '%s\n' '<h1>Hello from Tardigrade</h1>' > public/index.html

tardi init static > tardigrade.conf
tardi check
tardi run
```

`tardi init static` writes a starter config to stdout only, so the
redirect above produces a clean `tardigrade.conf` with no extra output mixed
in. With no path given, `tardi check` validates `./tardigrade.conf` directly,
and `tardi run` discovers that same local file too -- assuming, as in this
walkthrough, that `TARDIGRADE_CONFIG_PATH` isn't set in your shell, since
that env var takes precedence over the local file for `run` but not for
`check`. Validation performs a dry parse and never starts a listener.

`tardi run` starts listening on `http://localhost:8080`. From another
terminal:

```bash
curl -fsS http://localhost:8080/
curl -fsS http://localhost:8080/health
```

You should see:

- the index request returns `<h1>Hello from Tardigrade</h1>`;
- `/health` returns `ok`.

Press `Ctrl-C` in the terminal running `tardi run` to stop it; it drains
in-flight connections and exits cleanly.

## Reverse-proxy happy path

This walkthrough creates its own local upstream so it is fully runnable
without any application of your own.

Start a throwaway upstream in one terminal:

```bash
mkdir -p upstream
printf '%s\n' 'hello from upstream' > upstream/index.html
python3 -m http.server 3000 --bind 127.0.0.1 --directory upstream
```

In your Tardigrade working directory (a second terminal):

```bash
tardi init proxy > tardigrade.conf
tardi check
tardi run
```

The generated `proxy` profile points at `http://127.0.0.1:3000`, so no
extra config is needed beyond what `check` already validated -- `check`
validates the config's shape and does not require the upstream to be
reachable. From a third terminal:

```bash
curl -fsS http://localhost:8080/
curl -fsS http://localhost:8080/health
```

You should see:

- the index request returns `hello from upstream`, proxied through
  Tardigrade to the local Python server;
- `/health` still returns `ok` directly from the edge, with no upstream
  hop.

`Ctrl-C` stops `tardi run` cleanly; stop the Python upstream with `Ctrl-C`
in its own terminal.

## Explicit config path

The walkthroughs above rely on `tardi check` and `tardi run` finding
`./tardigrade.conf` with no arguments. To point either command at a
specific file instead:

```bash
tardi check ./my-site.conf
tardi run -c ./my-site.conf
```

Both commands consume `./my-site.conf`: `check` accepts it as the positional
form shown above, while `run` requires `-c`/`--config`.

## Next steps

- [Configuration reference](CONFIGURATION.md) -- every directive, type,
  default, and environment variable.
- [Examples](../examples/README.md) -- curated, copy/paste-runnable configs
  for TLS termination, virtual hosts, rate limiting, metrics, and more.
- [Production deployment](DEPLOYMENT.md) -- running Tardigrade under
  systemd or Docker.
- [Reload, drain, and shutdown](RELOAD_SHUTDOWN.md) -- the full hot-reload
  and graceful-shutdown contract.
- [Core v1 support matrix](SUPPORT_MATRIX.md) -- what's stable versus
  experimental.
- [Troubleshooting](TROUBLESHOOTING.md) -- symptom-to-diagnosis runbook for
  when something doesn't work as expected.
- [packaging/README.md](../packaging/README.md) -- install/build options
  and current platform coverage in detail.
