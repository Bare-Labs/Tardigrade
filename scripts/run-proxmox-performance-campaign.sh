#!/usr/bin/env bash
# Ephemeral Proxmox LXC performance campaign for #593.
#
# Creates a fresh Debian container on a Proxmox host, installs benchmark tools,
# builds the current checkout, runs selected performance suites, pulls artifacts
# back to the local workspace, and destroys the container unless --keep-container
# is set.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"

PROXMOX_SSH_TARGET="${PROXMOX_SSH_TARGET:-root@10.250.250.2}"
PROXMOX_SSH_BIND="${PROXMOX_SSH_BIND:-10.250.250.1}"
PROXMOX_TEMPLATE_STORAGE="${PROXMOX_TEMPLATE_STORAGE:-}"
PROXMOX_ROOTFS_STORAGE="${PROXMOX_ROOTFS_STORAGE:-}"
PROXMOX_TEMPLATE="${PROXMOX_TEMPLATE:-}"
PROXMOX_BRIDGE="${PROXMOX_BRIDGE:-vmbr0}"
PROXMOX_CT_ID="${PROXMOX_CT_ID:-}"
PROXMOX_CT_NAME="${PROXMOX_CT_NAME:-tardigrade-perf-${timestamp}}"
PROXMOX_CT_CORES="${PROXMOX_CT_CORES:-4}"
PROXMOX_CT_MEMORY_MB="${PROXMOX_CT_MEMORY_MB:-4096}"
PROXMOX_CT_DISK_GB="${PROXMOX_CT_DISK_GB:-12}"
PROXMOX_CT_IP="${PROXMOX_CT_IP:-dhcp}"
PROXMOX_KEEP_CONTAINER=false

ZIG_VERSION="${ZIG_VERSION:-0.16.0}"
K6_VERSION="${K6_VERSION:-latest}"
SERVERS="${SERVERS:-tardigrade,nginx,haproxy,caddy}"
DURATION="${DURATION:-15}"
CONNECTIONS="${CONNECTIONS:-32}"
THREADS="${THREADS:-4}"
SHARDS="${SHARDS:-4}"
ALLOW_MISSING=false
RUN_COMPETITIVE=true
RUN_LISTENER_SHARDING=false

LOCAL_OUT_DIR="${LOCAL_OUT_DIR:-$repo/benchmarks/results/$(date -u '+%Y-%m-%d')/proxmox-lxc-campaign-${timestamp}}"
REMOTE_STAGE="${REMOTE_STAGE:-/tmp/tardigrade-proxmox-perf-${timestamp}}"

usage() {
  cat <<'EOF'
Usage: scripts/run-proxmox-performance-campaign.sh [OPTIONS]

Creates a disposable Proxmox LXC, builds the current Tardigrade checkout inside
it, runs benchmark suites, pulls artifacts locally, and tears the CT down.

Defaults target the direct Mac<->Proxmox link:
  PROXMOX_SSH_TARGET=root@10.250.250.2
  PROXMOX_SSH_BIND=10.250.250.1

Options:
  --target SSH_TARGET       Proxmox SSH target (default: env/default above)
  --bind ADDRESS            Local SSH source address; use "" to disable -b
  --ct-id ID                Container VMID (default: pvesh /cluster/nextid)
  --name NAME               Container hostname
  --template STORAGE:PATH   Existing CT template ref, or template filename
  --template-storage NAME   Storage for template download/discovery
  --rootfs-storage NAME     Storage for container rootfs
  --bridge NAME             Proxmox bridge for CT eth0 (default: vmbr0)
  --ip CIDR|dhcp            CT eth0 IP config (default: dhcp)
  --cores N                 CT vCPUs (default: 4)
  --memory MB               CT memory (default: 4096)
  --disk GB                 CT rootfs size (default: 12)
  --duration SECONDS        Benchmark duration per workload (default: 15)
  --connections N           Benchmark connections (default: 32)
  --threads N               Benchmark load threads (default: 4)
  --servers LIST            Competitive servers (default: all four)
  --suite NAME              Suite to run: competitive, listener-sharding.
                            May be passed more than once. Default: competitive.
  --shards N                Listener-sharding profile count (default: 4)
  --k6-version VERSION      k6 release tag/version, or latest (default: latest)
  --allow-missing           Pass --allow-missing to competitive run
  --out-dir DIR             Local artifact directory
  --keep-container          Leave the CT running for inspection
  --help                    Show this help

Environment variables with the same uppercase names may also be used.
EOF
}

suite_seen=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target) PROXMOX_SSH_TARGET="$2"; shift 2 ;;
    --bind) PROXMOX_SSH_BIND="$2"; shift 2 ;;
    --ct-id) PROXMOX_CT_ID="$2"; shift 2 ;;
    --name) PROXMOX_CT_NAME="$2"; shift 2 ;;
    --template) PROXMOX_TEMPLATE="$2"; shift 2 ;;
    --template-storage) PROXMOX_TEMPLATE_STORAGE="$2"; shift 2 ;;
    --rootfs-storage) PROXMOX_ROOTFS_STORAGE="$2"; shift 2 ;;
    --bridge) PROXMOX_BRIDGE="$2"; shift 2 ;;
    --ip) PROXMOX_CT_IP="$2"; shift 2 ;;
    --cores) PROXMOX_CT_CORES="$2"; shift 2 ;;
    --memory) PROXMOX_CT_MEMORY_MB="$2"; shift 2 ;;
    --disk) PROXMOX_CT_DISK_GB="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --connections) CONNECTIONS="$2"; shift 2 ;;
    --threads) THREADS="$2"; shift 2 ;;
    --servers) SERVERS="$2"; shift 2 ;;
    --shards) SHARDS="$2"; shift 2 ;;
    --k6-version) K6_VERSION="$2"; shift 2 ;;
    --suite)
      if ! $suite_seen; then
        RUN_COMPETITIVE=false
        RUN_LISTENER_SHARDING=false
        suite_seen=true
      fi
      case "$2" in
        competitive) RUN_COMPETITIVE=true ;;
        listener-sharding) RUN_LISTENER_SHARDING=true ;;
        *) echo "unknown suite: $2" >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --allow-missing) ALLOW_MISSING=true; shift ;;
    --out-dir) LOCAL_OUT_DIR="$2"; shift 2 ;;
    --keep-container) PROXMOX_KEEP_CONTAINER=true; shift ;;
    --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$DURATION $CONNECTIONS $THREADS $PROXMOX_CT_CORES $PROXMOX_CT_MEMORY_MB $PROXMOX_CT_DISK_GB $SHARDS" in
  *[!0-9\ ]*) echo "numeric options must be positive integers" >&2; exit 2 ;;
esac

mkdir -p "$LOCAL_OUT_DIR"
src_tgz="$LOCAL_OUT_DIR/source.tgz"
zig_tgz="$LOCAL_OUT_DIR/zig-${ZIG_VERSION}-x86_64-linux.tgz"

say() { printf '%s\n' "$*"; }

ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)
scp_opts=(-o BatchMode=yes -o ConnectTimeout=10)
if [[ -n "$PROXMOX_SSH_BIND" ]]; then
  ssh_opts+=(-b "$PROXMOX_SSH_BIND")
  scp_opts+=(-o "BindAddress=${PROXMOX_SSH_BIND}")
fi

ssh_pve() {
  # shellcheck disable=SC2029 # helper intentionally sends the caller's command to the configured Proxmox SSH target
  ssh "${ssh_opts[@]}" "$PROXMOX_SSH_TARGET" "$@"
}

scp_to_pve() {
  scp "${scp_opts[@]}" "$1" "${PROXMOX_SSH_TARGET}:$2"
}

scp_from_pve() {
  scp "${scp_opts[@]}" "${PROXMOX_SSH_TARGET}:$1" "$2"
}

GIT_SHA="$(git rev-parse HEAD)"
say "==> packaging source from $repo (${GIT_SHA:0:8})"
COPYFILE_DISABLE=1 tar --format ustar -C "$repo" -czf "$src_tgz" \
  --exclude=.git \
  --exclude=.DS_Store \
  --exclude=.blink \
  --exclude=.claude \
  --exclude=.codex \
  --exclude=.zig \
  --exclude=.zig-cache \
  --exclude=.zig-toolchain \
  --exclude=dist \
  --exclude=zig-out \
  --exclude=benchmarks/results \
  .

linux_zig_dir="$repo/.zig/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}"
if [[ -x "$linux_zig_dir/zig" ]]; then
  say "==> packaging local Linux Zig ${ZIG_VERSION} toolchain"
  COPYFILE_DISABLE=1 tar --format ustar -C "$repo/.zig/${ZIG_VERSION}" -czf "$zig_tgz" "zig-x86_64-linux-${ZIG_VERSION}"
else
  rm -f "$zig_tgz"
fi

say "==> staging campaign inputs on $PROXMOX_SSH_TARGET"
ssh_pve "rm -rf '$REMOTE_STAGE' && mkdir -p '$REMOTE_STAGE'"
scp_to_pve "$src_tgz" "$REMOTE_STAGE/source.tgz"
if [[ -f "$zig_tgz" ]]; then
  scp_to_pve "$zig_tgz" "$REMOTE_STAGE/zig.tgz"
fi

remote_status=0
set +e
ssh "${ssh_opts[@]}" "$PROXMOX_SSH_TARGET" \
  PROXMOX_CT_ID="$PROXMOX_CT_ID" \
  PROXMOX_CT_NAME="$PROXMOX_CT_NAME" \
  PROXMOX_TEMPLATE="$PROXMOX_TEMPLATE" \
  PROXMOX_TEMPLATE_STORAGE="$PROXMOX_TEMPLATE_STORAGE" \
  PROXMOX_ROOTFS_STORAGE="$PROXMOX_ROOTFS_STORAGE" \
  PROXMOX_BRIDGE="$PROXMOX_BRIDGE" \
  PROXMOX_CT_IP="$PROXMOX_CT_IP" \
  PROXMOX_CT_CORES="$PROXMOX_CT_CORES" \
  PROXMOX_CT_MEMORY_MB="$PROXMOX_CT_MEMORY_MB" \
  PROXMOX_CT_DISK_GB="$PROXMOX_CT_DISK_GB" \
  PROXMOX_KEEP_CONTAINER="$PROXMOX_KEEP_CONTAINER" \
  ZIG_VERSION="$ZIG_VERSION" \
  K6_VERSION="$K6_VERSION" \
  GIT_SHA="$GIT_SHA" \
  SERVERS="$SERVERS" \
  DURATION="$DURATION" \
  CONNECTIONS="$CONNECTIONS" \
  THREADS="$THREADS" \
  SHARDS="$SHARDS" \
  ALLOW_MISSING="$ALLOW_MISSING" \
  RUN_COMPETITIVE="$RUN_COMPETITIVE" \
  RUN_LISTENER_SHARDING="$RUN_LISTENER_SHARDING" \
  REMOTE_STAGE="$REMOTE_STAGE" \
  bash -s <<'REMOTE'
set -euo pipefail

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

command -v pct >/dev/null 2>&1 || die "pct not found; run this on a Proxmox host"
command -v pveam >/dev/null 2>&1 || die "pveam not found; run this on a Proxmox host"

ctid="$PROXMOX_CT_ID"
if [[ -z "$ctid" ]]; then
  if command -v pvesh >/dev/null 2>&1; then
    ctid="$(pvesh get /cluster/nextid)"
  else
    ctid="$(awk 'BEGIN{srand(); print 9000 + int(rand() * 900)}')"
  fi
fi

[[ "$ctid" =~ ^[0-9]+$ ]] || die "invalid CT id: $ctid"
if pct status "$ctid" >/dev/null 2>&1; then
  die "CT $ctid already exists; pass --ct-id with an unused VMID"
fi

template_storage="$PROXMOX_TEMPLATE_STORAGE"
if [[ -z "$template_storage" ]]; then
  template_storage="$(pvesm status -content vztmpl 2>/dev/null | awk 'NR > 1 && $3 == "active" { print $1; exit }')"
fi
[[ -n "$template_storage" ]] || die "no active Proxmox storage with vztmpl content found"

rootfs_storage="$PROXMOX_ROOTFS_STORAGE"
if [[ -z "$rootfs_storage" ]]; then
  rootfs_storage="$(pvesm status -content rootdir 2>/dev/null | awk 'NR > 1 && $3 == "active" { print $1; exit }')"
fi
[[ -n "$rootfs_storage" ]] || die "no active Proxmox storage with rootdir content found"

template="$PROXMOX_TEMPLATE"
if [[ -z "$template" ]]; then
  template="$(pveam list "$template_storage" 2>/dev/null | awk '/debian-13.*standard.*amd64/ { print $1 }' | tail -1)"
fi
if [[ -z "$template" ]]; then
  available="$(pveam available --section system | awk '$2 ~ /debian-13.*standard.*amd64/ { print $2 }' | tail -1)"
  [[ -n "$available" ]] || die "could not find a Debian 13 standard amd64 template"
  say "==> downloading template $available to $template_storage"
  pveam download "$template_storage" "$available"
  template="${template_storage}:vztmpl/${available}"
elif [[ "$template" != *:* ]]; then
  template="${template_storage}:vztmpl/${template}"
fi

artifact_tgz="${REMOTE_STAGE}/artifacts.tgz"
container_created=false

cleanup() {
  status=$?
  if pct status "$ctid" >/dev/null 2>&1; then
    pct exec "$ctid" -- bash -lc '
      set -e
      if [ -d /work/Tardigrade/benchmarks/results ]; then
        tar -C /work/Tardigrade -czf /root/tardigrade-performance-artifacts.tgz benchmarks/results .zig-cache/proxmox-performance-campaign 2>/dev/null || \
          tar -C /work/Tardigrade -czf /root/tardigrade-performance-artifacts.tgz benchmarks/results
      fi
    ' >/dev/null 2>&1 || true
    pct pull "$ctid" /root/tardigrade-performance-artifacts.tgz "$artifact_tgz" >/dev/null 2>&1 || true
  fi
  if [[ "$PROXMOX_KEEP_CONTAINER" != "true" && "$container_created" == "true" ]]; then
    say "==> destroying CT $ctid"
    pct stop "$ctid" >/dev/null 2>&1 || true
    pct destroy "$ctid" --purge >/dev/null 2>&1 || true
  elif [[ "$container_created" == "true" ]]; then
    say "==> kept CT $ctid for inspection"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

say "==> creating CT $ctid ($PROXMOX_CT_NAME)"
pct create "$ctid" "$template" \
  --hostname "$PROXMOX_CT_NAME" \
  --cores "$PROXMOX_CT_CORES" \
  --memory "$PROXMOX_CT_MEMORY_MB" \
  --swap 0 \
  --rootfs "${rootfs_storage}:${PROXMOX_CT_DISK_GB}" \
  --net0 "name=eth0,bridge=${PROXMOX_BRIDGE},ip=${PROXMOX_CT_IP}" \
  --unprivileged 1 \
  --features nesting=1 \
  --start 1
container_created=true

say "==> waiting for CT network and apt"
for _ in $(seq 1 90); do
  if pct exec "$ctid" -- bash -lc 'test -r /etc/os-release && getent hosts deb.debian.org >/dev/null 2>&1'; then
    break
  fi
  sleep 1
done
pct exec "$ctid" -- bash -lc 'getent hosts deb.debian.org >/dev/null 2>&1' || die "CT has no working DNS/network"

say "==> installing benchmark dependencies in CT"
pct exec "$ctid" -- bash -lc '
  set -euo pipefail
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates curl xz-utils tar jq wrk nginx haproxy caddy nghttp2-client openssl python3 procps iproute2 psmisc coreutils findutils gawk
  if ! command -v k6 >/dev/null 2>&1; then
    if apt-cache show k6 >/dev/null 2>&1; then
      apt-get install -y k6
    else
      tag="$K6_VERSION"
      if [[ "$tag" == "latest" ]]; then
        tag="$(curl -fsSL https://api.github.com/repos/grafana/k6/releases/latest | jq -r .tag_name)"
      fi
      case "$tag" in
        v*) version="${tag#v}" ;;
        *) version="$tag"; tag="v$tag" ;;
      esac
      case "$(uname -m)" in
        x86_64|amd64) k6_arch="amd64" ;;
        aarch64|arm64) k6_arch="arm64" ;;
        *) echo "unsupported k6 architecture: $(uname -m)" >&2; exit 1 ;;
      esac
      url="https://github.com/grafana/k6/releases/download/${tag}/k6-v${version}-linux-${k6_arch}.tar.gz"
      tmp="$(mktemp -d)"
      trap "rm -rf \"\$tmp\"" EXIT
      curl -fsSL "$url" -o "$tmp/k6.tgz"
      tar -xzf "$tmp/k6.tgz" -C "$tmp"
      install -m 0755 "$tmp/k6-v${version}-linux-${k6_arch}/k6" /usr/local/bin/k6
      rm -rf "$tmp"
      trap - EXIT
    fi
  fi
'

say "==> loading source into CT"
pct exec "$ctid" -- mkdir -p /work/Tardigrade /work/Tardigrade/.zig-cache/proxmox-performance-campaign
pct push "$ctid" "${REMOTE_STAGE}/source.tgz" /root/tardigrade-source.tgz
pct exec "$ctid" -- tar -xzf /root/tardigrade-source.tgz -C /work/Tardigrade

if [[ -f "${REMOTE_STAGE}/zig.tgz" ]]; then
  say "==> installing staged Zig $ZIG_VERSION in CT"
  pct push "$ctid" "${REMOTE_STAGE}/zig.tgz" /root/zig.tgz
  pct exec "$ctid" -- bash -lc "
    set -e
    mkdir -p /opt/zig-versions/${ZIG_VERSION}
    tar -xzf /root/zig.tgz -C /opt/zig-versions/${ZIG_VERSION}
    ln -sf /opt/zig-versions/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}/zig /usr/local/bin/zig
  "
else
  say "==> downloading Zig $ZIG_VERSION in CT"
  pct exec "$ctid" -- bash -lc "cd /work/Tardigrade && ./scripts/install-zig.sh '$ZIG_VERSION' /opt/zig-versions >/tmp/zig-path && ln -sf \"\$(cat /tmp/zig-path)/zig\" /usr/local/bin/zig"
fi

say "==> running campaign inside CT"
pct exec "$ctid" -- bash -lc "
  set -euo pipefail
  cd /work/Tardigrade
  out=\"benchmarks/results/\$(date -u +%Y-%m-%d)/proxmox-lxc-campaign-\$(date -u +%Y%m%dT%H%M%SZ)\"
  mkdir -p \"\$out\" .zig-cache/proxmox-performance-campaign
  {
    printf 'date_utc=%s\n' \"\$(date -u '+%Y-%m-%dT%H:%M:%SZ')\"
    printf 'proxmox_host=%s\n' \"\$(hostname)\"
    printf 'ct_id=%s\n' '$ctid'
    printf 'ct_name=%s\n' '$PROXMOX_CT_NAME'
    printf 'git_sha=%s\n' '$GIT_SHA'
    printf 'zig=%s\n' \"\$(zig version)\"
    printf 'kernel=%s\n' \"\$(uname -a)\"
    printf 'lscpu<<EOF\n'; lscpu; printf 'EOF\n'
    printf 'memory<<EOF\n'; free -h; printf 'EOF\n'
    printf 'ulimit<<EOF\n'; ulimit -a; printf 'EOF\n'
    printf 'ip_addr<<EOF\n'; ip -br addr; printf 'EOF\n'
    printf 'versions<<EOF\n'
    wrk --version 2>&1 | head -2 || true
    nginx -v 2>&1 || true
    haproxy -v 2>&1 | head -1 || true
    caddy version 2>&1 || true
    h2load --version 2>&1 | head -1 || true
    k6 version 2>&1 | head -1 || true
    printf 'EOF\n'
  } > \"\$out/environment.txt\"
  cp \"\$out/environment.txt\" .zig-cache/proxmox-performance-campaign/environment.txt
  zig build -Doptimize=ReleaseFast -Dversion='$GIT_SHA'
  if [[ '$RUN_COMPETITIVE' == true ]]; then
    args=(./benchmarks/competitive/run.sh --binary ./zig-out/bin/tardi --servers '$SERVERS' --duration '$DURATION' --connections '$CONNECTIONS' --threads '$THREADS' --out-dir \"\$out/competitive\")
    if [[ '$ALLOW_MISSING' == true ]]; then args+=(--allow-missing); fi
    printf '%q ' \"\${args[@]}\" > \"\$out/competitive-command.txt\"
    printf '\n' >> \"\$out/competitive-command.txt\"
    \"\${args[@]}\"
  fi
  if [[ '$RUN_LISTENER_SHARDING' == true ]]; then
    listener_conf=\"\$out/listener-sharding.conf\"
    cat >\"\$listener_conf\" <<EOF
pid \$out/listener-sharding.pid;
listen 19090;
location = /health {
    return 200 ok;
}
location = /proxy/health {
    proxy_pass http://127.0.0.1:19091/health;
}
EOF
    python3 benchmarks/fixtures/upstream_server.py --port 19091 >\"\$out/listener-upstream.log\" 2>&1 &
    upstream_pid=\$!
    trap 'kill \"\$upstream_pid\" >/dev/null 2>&1 || true' EXIT
    ./benchmarks/listener-sharding.sh \
      --start-command './zig-out/bin/tardi run -c '\"\$listener_conf\" \
      --port 19090 \
      --duration '$DURATION' \
      --connections '$CONNECTIONS' \
      --threads '$THREADS' \
      --shards '$SHARDS' \
      --save-dir \"\$out/listener-sharding\"
    kill \"\$upstream_pid\" >/dev/null 2>&1 || true
    trap - EXIT
  fi
  printf '%s\n' \"\$out\" > .zig-cache/proxmox-performance-campaign/result-dir.txt
"

say "==> campaign completed in CT $ctid"
REMOTE
remote_status=$?
set -e

say "==> collecting artifacts"
if scp_from_pve "$REMOTE_STAGE/artifacts.tgz" "$LOCAL_OUT_DIR/artifacts.tgz"; then
  tar -xzf "$LOCAL_OUT_DIR/artifacts.tgz" -C "$LOCAL_OUT_DIR"
  say "artifacts: $LOCAL_OUT_DIR"
else
  say "warning: no artifact archive was available on the Proxmox host" >&2
fi

ssh_pve "rm -rf '$REMOTE_STAGE'" >/dev/null 2>&1 || true
exit "$remote_status"
