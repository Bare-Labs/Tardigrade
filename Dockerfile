# Local build support only: this image is not published to a registry.
# See docs/DEPLOYMENT.md for the full Docker deployment workflow and
# packaging/README.md for current packaging/distribution status.

# debian:bookworm-slim, pinned by digest for reproducible builds.
FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS build

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

# Pin to the same Zig version CI builds/tests against (.github/workflows/ci.yml).
RUN sh ./scripts/install-zig.sh 0.16.0 /opt/zig \
    && ln -s "$(find /opt/zig -maxdepth 3 -type f -name zig)" /usr/local/bin/zig

# Default "general" TLS profile: links the approved OpenSSL adapter (see
# docs/TLS_DEPENDENCY_POLICY.md). Requires libssl-dev above.
RUN zig build -Doptimize=ReleaseFast

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241 AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin tardigrade

COPY --from=build /src/zig-out/bin/tardi /usr/local/bin/tardi

RUN mkdir -p /etc/tardigrade /var/lib/tardigrade /run/tardigrade \
    && chown -R tardigrade:tardigrade /var/lib/tardigrade /run/tardigrade

USER tardigrade
WORKDIR /var/lib/tardigrade

ENV TARDIGRADE_PID_FILE=/run/tardigrade/tardigrade.pid

EXPOSE 8069/tcp

# Exec form so `tardi` runs as PID 1 and receives SIGTERM/SIGHUP directly from
# `docker stop` / `docker kill -s HUP`, rather than a shell intermediary.
ENTRYPOINT ["/usr/local/bin/tardi"]
CMD ["run", "-c", "/etc/tardigrade/tardigrade.conf"]
