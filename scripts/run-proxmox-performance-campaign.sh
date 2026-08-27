#!/usr/bin/env bash
# Ephemeral Proxmox performance campaign for #593.
#
# Canonical mode provisions a disposable KVM VM. LXC remains available only as
# an explicit smoke mode for cheap orchestration checks.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

timestamp="$(date -u '+%Y%m%dT%H%M%SZ')"

PROXMOX_SSH_TARGET="${PROXMOX_SSH_TARGET:-root@10.250.250.2}"
PROXMOX_SSH_BIND="${PROXMOX_SSH_BIND:-10.250.250.1}"
PROXMOX_MODE="${PROXMOX_MODE:-kvm}"
PROXMOX_TEMPLATE_STORAGE="${PROXMOX_TEMPLATE_STORAGE:-}"
PROXMOX_ROOTFS_STORAGE="${PROXMOX_ROOTFS_STORAGE:-}"
PROXMOX_TEMPLATE="${PROXMOX_TEMPLATE:-}"
PROXMOX_BRIDGE="${PROXMOX_BRIDGE:-vmbr0}"
PROXMOX_GUEST_ID="${PROXMOX_GUEST_ID:-}"
PROXMOX_GUEST_NAME="${PROXMOX_GUEST_NAME:-tardigrade-perf-${timestamp}}"
PROXMOX_GUEST_CORES="${PROXMOX_GUEST_CORES:-4}"
PROXMOX_GUEST_MEMORY_MB="${PROXMOX_GUEST_MEMORY_MB:-4096}"
PROXMOX_GUEST_DISK_GB="${PROXMOX_GUEST_DISK_GB:-16}"
PROXMOX_GUEST_IP="${PROXMOX_GUEST_IP:-dhcp}"
PROXMOX_VM_IMAGE="${PROXMOX_VM_IMAGE:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
PROXMOX_VM_GATEWAY="${PROXMOX_VM_GATEWAY:-}"
PROXMOX_KEEP_GUEST=false
PROXMOX_NONCANONICAL=false

TARDIGRADE_REF="${TARDIGRADE_REF:-v0.6.4}"
ZIG_VERSION="${ZIG_VERSION:-0.16.0}"
K6_VERSION="${K6_VERSION:-latest}"
H2LOAD_PATH="${H2LOAD_PATH:-}"
SERVERS="${SERVERS:-tardigrade,nginx,haproxy,caddy}"
DURATION="${DURATION:-15}"
CONNECTIONS="${CONNECTIONS:-32}"
THREADS="${THREADS:-4}"
SHARDS="${SHARDS:-4}"
ALLOW_MISSING=false
TUNE_COMPARISON=true
RUN_COMPETITIVE=true
RUN_LISTENER_SHARDING=false
RUN_BACKEND_COMPARISON=false

LOCAL_OUT_DIR="${LOCAL_OUT_DIR:-$repo/benchmarks/results/$(date -u '+%Y-%m-%d')/proxmox-${PROXMOX_MODE}-campaign-${timestamp}}"
REMOTE_STAGE="${REMOTE_STAGE:-/tmp/tardigrade-proxmox-perf-${timestamp}}"

usage() {
  cat <<'EOF'
Usage: scripts/run-proxmox-performance-campaign.sh [OPTIONS]

Creates a disposable Proxmox guest, installs benchmark tools, builds an
immutable Tardigrade ref, runs selected benchmark suites, pulls artifacts
locally, and tears the guest down unless --keep-guest is set.

Defaults target the direct Mac<->Proxmox link:
  PROXMOX_SSH_TARGET=root@10.250.250.2
  PROXMOX_SSH_BIND=10.250.250.1

Options:
  --mode kvm|lxc-smoke      Guest mode (default: kvm). LXC is non-canonical.
  --target SSH_TARGET       Proxmox SSH target (default: env/default above)
  --bind ADDRESS            Local SSH source address; use "" to disable -b
  --guest-id ID             VMID/CTID (default: pvesh /cluster/nextid)
  --ct-id ID                Alias for --guest-id
  --vm-id ID                Alias for --guest-id
  --name NAME               Guest name/hostname
  --tardigrade-ref REF      Git ref to archive and benchmark (default: v0.6.4)
  --vm-image PATH|URL       Debian cloud image for KVM mode
  --vm-gateway IP           Static gateway for --ip CIDR in KVM mode
  --h2load-path PATH        QUIC-capable h2load path inside the guest
  --template STORAGE:PATH   Existing CT template ref, or template filename
  --template-storage NAME   Storage for CT template download/discovery
  --rootfs-storage NAME     Storage for VM disk or CT rootfs
  --bridge NAME             Proxmox bridge for guest net0 (default: vmbr0)
  --ip CIDR|dhcp            Guest IP config (default: dhcp)
  --cores N                 Guest vCPUs (default: 4)
  --memory MB               Guest memory (default: 4096)
  --disk GB                 Guest root disk size (default: 16)
  --duration SECONDS        Benchmark duration per workload (default: 15)
  --connections N           Benchmark connections (default: 32)
  --threads N               Benchmark load threads (default: 4)
  --servers LIST            Competitive servers (default: all four)
  --suite NAME              competitive, listener-sharding, backend-comparison.
                            May be passed more than once. Default: competitive.
  --shards N                Listener-sharding profile count (default: 4)
  --k6-version VERSION      k6 release tag/version, or latest (default: latest)
  --allow-missing           Pass --allow-missing to competitive run
  --no-tune-comparison      Disable H3 UDP buffer tuning rows
  --noncanonical            Allow KVM run despite host-idleness warnings
  --out-dir DIR             Local artifact directory
  --keep-guest              Leave the guest running for inspection
  --keep-container          Alias for --keep-guest
  --help                    Show this help

Canonical #593 evidence must use --mode kvm and pass all preflights. Use
--mode lxc-smoke only for fast create/run/destroy orchestration checks.
EOF
}

suite_seen=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) PROXMOX_MODE="$2"; shift 2 ;;
    --target) PROXMOX_SSH_TARGET="$2"; shift 2 ;;
    --bind) PROXMOX_SSH_BIND="$2"; shift 2 ;;
    --guest-id|--ct-id|--vm-id) PROXMOX_GUEST_ID="$2"; shift 2 ;;
    --name) PROXMOX_GUEST_NAME="$2"; shift 2 ;;
    --tardigrade-ref) TARDIGRADE_REF="$2"; shift 2 ;;
    --vm-image) PROXMOX_VM_IMAGE="$2"; shift 2 ;;
    --vm-gateway) PROXMOX_VM_GATEWAY="$2"; shift 2 ;;
    --h2load-path) H2LOAD_PATH="$2"; shift 2 ;;
    --template) PROXMOX_TEMPLATE="$2"; shift 2 ;;
    --template-storage) PROXMOX_TEMPLATE_STORAGE="$2"; shift 2 ;;
    --rootfs-storage) PROXMOX_ROOTFS_STORAGE="$2"; shift 2 ;;
    --bridge) PROXMOX_BRIDGE="$2"; shift 2 ;;
    --ip) PROXMOX_GUEST_IP="$2"; shift 2 ;;
    --cores) PROXMOX_GUEST_CORES="$2"; shift 2 ;;
    --memory) PROXMOX_GUEST_MEMORY_MB="$2"; shift 2 ;;
    --disk) PROXMOX_GUEST_DISK_GB="$2"; shift 2 ;;
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
        RUN_BACKEND_COMPARISON=false
        suite_seen=true
      fi
      case "$2" in
        competitive) RUN_COMPETITIVE=true ;;
        listener-sharding) RUN_LISTENER_SHARDING=true ;;
        backend-comparison) RUN_BACKEND_COMPARISON=true ;;
        *) echo "unknown suite: $2" >&2; exit 2 ;;
      esac
      shift 2
      ;;
    --allow-missing) ALLOW_MISSING=true; shift ;;
    --no-tune-comparison) TUNE_COMPARISON=false; shift ;;
    --noncanonical) PROXMOX_NONCANONICAL=true; shift ;;
    --out-dir) LOCAL_OUT_DIR="$2"; shift 2 ;;
    --keep-guest|--keep-container) PROXMOX_KEEP_GUEST=true; shift ;;
    --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

case "$PROXMOX_MODE" in
  kvm) ;;
  lxc-smoke) PROXMOX_NONCANONICAL=true; TUNE_COMPARISON=false ;;
  *) die "--mode must be kvm or lxc-smoke" ;;
esac

case "$DURATION $CONNECTIONS $THREADS $PROXMOX_GUEST_CORES $PROXMOX_GUEST_MEMORY_MB $PROXMOX_GUEST_DISK_GB $SHARDS" in
  *[!0-9\ ]*) die "numeric options must be positive integers" ;;
esac
for n in "$DURATION" "$CONNECTIONS" "$THREADS" "$PROXMOX_GUEST_CORES" "$PROXMOX_GUEST_MEMORY_MB" "$PROXMOX_GUEST_DISK_GB" "$SHARDS"; do
  [[ "$n" -gt 0 ]] || die "numeric options must be positive integers"
done

case "$REMOTE_STAGE" in
  /tmp/tardigrade-proxmox-perf-*) ;;
  *) die "REMOTE_STAGE must stay under /tmp/tardigrade-proxmox-perf-*" ;;
esac
[[ "$REMOTE_STAGE" =~ ^/tmp/[A-Za-z0-9._/@+-]+$ ]] || die "REMOTE_STAGE contains unsafe characters"

mkdir -p "$LOCAL_OUT_DIR"
src_tgz="$LOCAL_OUT_DIR/source.tgz"
src_sha="$src_tgz.sha256"
zig_tgz="$LOCAL_OUT_DIR/zig-${ZIG_VERSION}-x86_64-linux.tgz"
params_file="$LOCAL_OUT_DIR/campaign.env"

ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)
scp_opts=(-o BatchMode=yes -o ConnectTimeout=10)
if [[ -n "$PROXMOX_SSH_BIND" ]]; then
  ssh_opts+=(-b "$PROXMOX_SSH_BIND")
  scp_opts+=(-o "BindAddress=${PROXMOX_SSH_BIND}")
fi

ssh_pve() {
  # shellcheck disable=SC2029 # helper intentionally sends commands to the configured Proxmox target
  ssh "${ssh_opts[@]}" "$PROXMOX_SSH_TARGET" "$@"
}

scp_to_pve() {
  scp "${scp_opts[@]}" "$1" "${PROXMOX_SSH_TARGET}:$2"
}

scp_from_pve() {
  scp "${scp_opts[@]}" "${PROXMOX_SSH_TARGET}:$1" "$2"
}

write_param() {
  local key="$1"
  local value="$2"
  printf '%s=' "$key" >>"$params_file"
  printf '%q\n' "$value" >>"$params_file"
}

TARDIGRADE_SHA="$(git rev-parse "${TARDIGRADE_REF}^{commit}")"
say "==> packaging source from ${TARDIGRADE_REF} (${TARDIGRADE_SHA:0:8})"
git archive --format=tar "$TARDIGRADE_SHA" | gzip -n >"$src_tgz"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$src_tgz" | awk '{ print $1 "  source.tgz" }' >"$src_sha"
else
  shasum -a 256 "$src_tgz" | awk '{ print $1 "  source.tgz" }' >"$src_sha"
fi

linux_zig_dir="$repo/.zig/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}"
if [[ -x "$linux_zig_dir/zig" ]]; then
  say "==> packaging local Linux Zig ${ZIG_VERSION} toolchain"
  COPYFILE_DISABLE=1 tar --format ustar -C "$repo/.zig/${ZIG_VERSION}" -czf "$zig_tgz" "zig-x86_64-linux-${ZIG_VERSION}"
else
  rm -f "$zig_tgz"
fi

: >"$params_file"
write_param PROXMOX_MODE "$PROXMOX_MODE"
write_param PROXMOX_GUEST_ID "$PROXMOX_GUEST_ID"
write_param PROXMOX_GUEST_NAME "$PROXMOX_GUEST_NAME"
write_param PROXMOX_TEMPLATE "$PROXMOX_TEMPLATE"
write_param PROXMOX_TEMPLATE_STORAGE "$PROXMOX_TEMPLATE_STORAGE"
write_param PROXMOX_ROOTFS_STORAGE "$PROXMOX_ROOTFS_STORAGE"
write_param PROXMOX_BRIDGE "$PROXMOX_BRIDGE"
write_param PROXMOX_GUEST_IP "$PROXMOX_GUEST_IP"
write_param PROXMOX_VM_GATEWAY "$PROXMOX_VM_GATEWAY"
write_param PROXMOX_VM_IMAGE "$PROXMOX_VM_IMAGE"
write_param PROXMOX_GUEST_CORES "$PROXMOX_GUEST_CORES"
write_param PROXMOX_GUEST_MEMORY_MB "$PROXMOX_GUEST_MEMORY_MB"
write_param PROXMOX_GUEST_DISK_GB "$PROXMOX_GUEST_DISK_GB"
write_param PROXMOX_KEEP_GUEST "$PROXMOX_KEEP_GUEST"
write_param PROXMOX_NONCANONICAL "$PROXMOX_NONCANONICAL"
write_param TARDIGRADE_REF "$TARDIGRADE_REF"
write_param TARDIGRADE_SHA "$TARDIGRADE_SHA"
write_param ZIG_VERSION "$ZIG_VERSION"
write_param K6_VERSION "$K6_VERSION"
write_param H2LOAD_PATH "$H2LOAD_PATH"
write_param SERVERS "$SERVERS"
write_param DURATION "$DURATION"
write_param CONNECTIONS "$CONNECTIONS"
write_param THREADS "$THREADS"
write_param SHARDS "$SHARDS"
write_param ALLOW_MISSING "$ALLOW_MISSING"
write_param TUNE_COMPARISON "$TUNE_COMPARISON"
write_param RUN_COMPETITIVE "$RUN_COMPETITIVE"
write_param RUN_LISTENER_SHARDING "$RUN_LISTENER_SHARDING"
write_param RUN_BACKEND_COMPARISON "$RUN_BACKEND_COMPARISON"
write_param REMOTE_STAGE "$REMOTE_STAGE"

say "==> staging campaign inputs on $PROXMOX_SSH_TARGET"
ssh_pve "rm -rf $(printf '%q' "$REMOTE_STAGE") && mkdir -p $(printf '%q' "$REMOTE_STAGE")"
scp_to_pve "$src_tgz" "$REMOTE_STAGE/source.tgz"
scp_to_pve "$src_sha" "$REMOTE_STAGE/source.tgz.sha256"
scp_to_pve "$params_file" "$REMOTE_STAGE/campaign.env"
if [[ -f "$zig_tgz" ]]; then
  scp_to_pve "$zig_tgz" "$REMOTE_STAGE/zig.tgz"
fi

remote_status=0
set +e
# shellcheck disable=SC2029 # REMOTE_STAGE is locally shell-quoted before being passed to the Proxmox shell.
ssh "${ssh_opts[@]}" "$PROXMOX_SSH_TARGET" "REMOTE_STAGE=$(printf '%q' "$REMOTE_STAGE") bash -s" <<'REMOTE'
set -euo pipefail

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

case "${REMOTE_STAGE:-}" in
  /tmp/tardigrade-proxmox-perf-*) ;;
  *) die "REMOTE_STAGE must stay under /tmp/tardigrade-proxmox-perf-*" ;;
esac
[[ "$REMOTE_STAGE" =~ ^/tmp/[A-Za-z0-9._/@+-]+$ ]] || die "REMOTE_STAGE contains unsafe characters"
# shellcheck source=/dev/null
source "$REMOTE_STAGE/campaign.env"

artifact_tgz="${REMOTE_STAGE}/artifacts.tgz"
guest_created=false
guest_id="$PROXMOX_GUEST_ID"
guest_ip=""
guest_ssh_key="$REMOTE_STAGE/vm_ssh_key"
host_meta="$REMOTE_STAGE/proxmox-host-metadata.txt"

require_host_tool() {
  command -v "$1" >/dev/null 2>&1 || die "$1 not found; run this on a Proxmox host"
}

next_guest_id() {
  if [[ -n "$guest_id" ]]; then
    printf '%s\n' "$guest_id"
  elif command -v pvesh >/dev/null 2>&1; then
    pvesh get /cluster/nextid
  else
    awk 'BEGIN{srand(); print 9000 + int(rand() * 900)}'
  fi
}

storage_with_content() {
  local content="$1"
  local configured="$2"
  if [[ -n "$configured" ]]; then
    printf '%s\n' "$configured"
    return
  fi
  pvesm status -content "$content" 2>/dev/null | awk 'NR > 1 && $3 == "active" { print $1; exit }'
}

capture_host_metadata() {
  {
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'mode=%s\n' "$PROXMOX_MODE"
    printf 'canonical=%s\n' "$([[ "$PROXMOX_MODE" == kvm && "$PROXMOX_NONCANONICAL" != true ]] && echo true || echo false)"
    printf 'proxmox_node=%s\n' "$(hostname)"
    printf 'tardigrade_ref=%s\n' "$TARDIGRADE_REF"
    printf 'tardigrade_sha=%s\n' "$TARDIGRADE_SHA"
    printf 'source_archive_sha256=%s\n' "$(awk '{print $1}' "$REMOTE_STAGE/source.tgz.sha256")"
    printf 'pveversion<<EOF\n'; pveversion -v 2>&1 || true; printf 'EOF\n'
    printf 'host_uname<<EOF\n'; uname -a; printf 'EOF\n'
    printf 'host_lscpu_e<<EOF\n'; lscpu -e 2>&1 || true; printf 'EOF\n'
    printf 'host_memory<<EOF\n'; free -h 2>&1 || true; printf 'EOF\n'
    printf 'host_load<<EOF\n'; uptime 2>&1 || true; printf 'EOF\n'
    printf 'cpu_governor<<EOF\n'; grep -H . /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null || true; printf 'EOF\n'
    printf 'cpu_frequency<<EOF\n'; grep -H . /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq 2>/dev/null || true; printf 'EOF\n'
    printf 'sysctl<<EOF\n'; sysctl kernel.perf_event_paranoid net.core.rmem_max net.core.wmem_max net.ipv4.ip_local_port_range 2>&1 || true; printf 'EOF\n'
    printf 'qm_list<<EOF\n'; qm list 2>&1 || true; printf 'EOF\n'
    printf 'pct_list<<EOF\n'; pct list 2>&1 || true; printf 'EOF\n'
  } >"$host_meta"
}

assert_idle_for_canonical() {
  [[ "$PROXMOX_MODE" == kvm && "$PROXMOX_NONCANONICAL" != true ]] || return 0
  local running
  running="$( { qm list 2>/dev/null | awk 'NR > 1 && $3 == "running" { print "VM " $1 " " $2 }'; pct list 2>/dev/null | awk 'NR > 1 && $2 == "running" { print "CT " $1 " " $4 }'; } || true )"
  if [[ -n "$running" ]]; then
    printf '%s\n' "$running" >&2
    die "canonical mode requires an otherwise-idle Proxmox host; stop other guests or pass --noncanonical"
  fi
}

run_guest() {
  local cmd="$1"
  if [[ "$PROXMOX_MODE" == lxc-smoke ]]; then
    pct exec "$guest_id" -- bash -lc "$cmd"
  else
    ssh -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$guest_ip" "$cmd"
  fi
}

push_guest() {
  local src="$1"
  local dst="$2"
  if [[ "$PROXMOX_MODE" == lxc-smoke ]]; then
    pct push "$guest_id" "$src" "$dst"
  else
    scp -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$src" "root@$guest_ip:$dst"
  fi
}

pull_guest() {
  local src="$1"
  local dst="$2"
  if [[ "$PROXMOX_MODE" == lxc-smoke ]]; then
    pct pull "$guest_id" "$src" "$dst"
  else
    scp -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "root@$guest_ip:$src" "$dst"
  fi
}

cleanup() {
  status=$?
  guest_label="${guest_id:-unknown}"
  if [[ "$guest_created" == true ]]; then
    run_guest '
      set -e
      if [ -d /work/Tardigrade/benchmarks/results ]; then
        tar -C /work/Tardigrade -czf /root/tardigrade-performance-artifacts.tgz benchmarks/results .zig-cache/proxmox-performance-campaign 2>/dev/null || \
          tar -C /work/Tardigrade -czf /root/tardigrade-performance-artifacts.tgz benchmarks/results
      fi
    ' >/dev/null 2>&1 || true
    pull_guest /root/tardigrade-performance-artifacts.tgz "$artifact_tgz" >/dev/null 2>&1 || true
    if [[ "$PROXMOX_MODE" == kvm ]]; then
      qm config "$guest_label" >"$REMOTE_STAGE/guest-config.txt" 2>&1 || true
    else
      pct config "$guest_label" >"$REMOTE_STAGE/guest-config.txt" 2>&1 || true
    fi
    tar -C "$REMOTE_STAGE" -rf "$REMOTE_STAGE/metadata.tar" proxmox-host-metadata.txt guest-config.txt 2>/dev/null || true
  fi
  if [[ "$PROXMOX_KEEP_GUEST" != true && "$guest_created" == true ]]; then
    if [[ "$PROXMOX_MODE" == kvm ]]; then
      say "==> destroying VM $guest_label"
      qm stop "$guest_label" >/dev/null 2>&1 || true
      qm destroy "$guest_label" --purge >/dev/null 2>&1 || true
    else
      say "==> destroying CT $guest_label"
      pct stop "$guest_label" >/dev/null 2>&1 || true
      pct destroy "$guest_label" --purge >/dev/null 2>&1 || true
    fi
  elif [[ "$guest_created" == true ]]; then
    say "==> kept guest $guest_label for inspection"
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

create_lxc_smoke() {
  require_host_tool pct
  require_host_tool pveam
  guest_id="$(next_guest_id)"
  [[ "$guest_id" =~ ^[0-9]+$ ]] || die "invalid CT id: $guest_id"
  pct status "$guest_id" >/dev/null 2>&1 && die "CT $guest_id already exists; pass --guest-id with an unused VMID"

  local template_storage rootfs_storage template available
  template_storage="$(storage_with_content vztmpl "$PROXMOX_TEMPLATE_STORAGE")"
  [[ -n "$template_storage" ]] || die "no active Proxmox storage with vztmpl content found"
  rootfs_storage="$(storage_with_content rootdir "$PROXMOX_ROOTFS_STORAGE")"
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

  say "==> creating CT $guest_id ($PROXMOX_GUEST_NAME) for non-canonical smoke"
  pct create "$guest_id" "$template" \
    --hostname "$PROXMOX_GUEST_NAME" \
    --cores "$PROXMOX_GUEST_CORES" \
    --memory "$PROXMOX_GUEST_MEMORY_MB" \
    --swap 0 \
    --rootfs "${rootfs_storage}:${PROXMOX_GUEST_DISK_GB}" \
    --net0 "name=eth0,bridge=${PROXMOX_BRIDGE},ip=${PROXMOX_GUEST_IP}" \
    --unprivileged 1 \
    --features nesting=1 \
    --start 1
  guest_created=true

  say "==> waiting for CT network and apt"
  for _ in $(seq 1 90); do
    pct exec "$guest_id" -- bash -lc 'test -r /etc/os-release && getent hosts deb.debian.org >/dev/null 2>&1' && return 0
    sleep 1
  done
  die "CT has no working DNS/network"
}

create_kvm() {
  require_host_tool qm
  require_host_tool pvesm
  require_host_tool ssh-keygen
  require_host_tool curl
  guest_id="$(next_guest_id)"
  [[ "$guest_id" =~ ^[0-9]+$ ]] || die "invalid VM id: $guest_id"
  qm status "$guest_id" >/dev/null 2>&1 && die "VM $guest_id already exists; pass --guest-id with an unused VMID"

  local disk_storage image_path ipconfig
  disk_storage="$(storage_with_content images "$PROXMOX_ROOTFS_STORAGE")"
  [[ -n "$disk_storage" ]] || die "no active Proxmox storage with images content found"
  image_path="$PROXMOX_VM_IMAGE"
  if [[ "$image_path" =~ ^https?:// ]]; then
    image_path="$REMOTE_STAGE/debian-genericcloud.qcow2"
    say "==> downloading KVM cloud image"
    curl -fsSL "$PROXMOX_VM_IMAGE" -o "$image_path"
  fi
  [[ -r "$image_path" ]] || die "VM image not readable on Proxmox host: $image_path"

  ssh-keygen -q -t ed25519 -N '' -f "$guest_ssh_key"
  if [[ "$PROXMOX_GUEST_IP" == dhcp ]]; then
    ipconfig="ip=dhcp"
  else
    [[ -n "$PROXMOX_VM_GATEWAY" ]] || die "--vm-gateway is required with static --ip in KVM mode"
    ipconfig="ip=${PROXMOX_GUEST_IP},gw=${PROXMOX_VM_GATEWAY}"
  fi

  say "==> creating VM $guest_id ($PROXMOX_GUEST_NAME)"
  qm create "$guest_id" \
    --name "$PROXMOX_GUEST_NAME" \
    --memory "$PROXMOX_GUEST_MEMORY_MB" \
    --cores "$PROXMOX_GUEST_CORES" \
    --cpu host \
    --net0 "virtio,bridge=${PROXMOX_BRIDGE}" \
    --scsihw virtio-scsi-single \
    --agent enabled=1 \
    --serial0 socket \
    --vga serial0 \
    --ostype l26
  qm importdisk "$guest_id" "$image_path" "$disk_storage" >/dev/null
  qm set "$guest_id" \
    --scsi0 "${disk_storage}:vm-${guest_id}-disk-0" \
    --boot order=scsi0 \
    --ide2 "${disk_storage}:cloudinit" \
    --ciuser root \
    --sshkeys "${guest_ssh_key}.pub" \
    --ipconfig0 "$ipconfig" >/dev/null
  qm resize "$guest_id" scsi0 "${PROXMOX_GUEST_DISK_GB}G" >/dev/null || true
  qm start "$guest_id"
  guest_created=true

  say "==> waiting for VM network and SSH"
  for _ in $(seq 1 180); do
    if [[ "$PROXMOX_GUEST_IP" != dhcp ]]; then
      guest_ip="${PROXMOX_GUEST_IP%%/*}"
    elif qm agent "$guest_id" ping >/dev/null 2>&1; then
      guest_ip="$(qm guest cmd "$guest_id" network-get-interfaces 2>/dev/null | grep -Eo '"ip-address" *: *"([0-9]{1,3}\.){3}[0-9]{1,3}"' | sed -E 's/.*"(([0-9]{1,3}\.){3}[0-9]{1,3})"/\1/' | grep -v '^127\.' | head -1 || true)"
    fi
    if [[ -n "$guest_ip" ]] && ssh -i "$guest_ssh_key" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 "root@$guest_ip" 'test -r /etc/os-release && getent hosts deb.debian.org >/dev/null 2>&1' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  die "VM did not become reachable over SSH; use --keep-guest for manual inspection"
}

install_guest_dependencies() {
  say "==> installing benchmark dependencies in guest"
  run_guest '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates curl xz-utils tar jq wrk nginx haproxy caddy nghttp2-client openssl python3 procps iproute2 psmisc coreutils findutils gawk strace linux-perf
    if ! command -v k6 >/dev/null 2>&1; then
      if apt-cache show k6 >/dev/null 2>&1; then
        apt-get install -y k6
      else
        tag="'"$K6_VERSION"'"
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
}

load_source_and_zig() {
  say "==> loading source into guest"
  run_guest "mkdir -p /work/Tardigrade /work/Tardigrade/.zig-cache/proxmox-performance-campaign"
  push_guest "${REMOTE_STAGE}/source.tgz" /root/source.tgz
  push_guest "${REMOTE_STAGE}/source.tgz.sha256" /root/source.tgz.sha256
  run_guest "cd /root && sha256sum -c source.tgz.sha256 && tar -xzf /root/source.tgz -C /work/Tardigrade"

  if [[ -f "${REMOTE_STAGE}/zig.tgz" ]]; then
    say "==> installing staged Zig $ZIG_VERSION in guest"
    push_guest "${REMOTE_STAGE}/zig.tgz" /root/zig.tgz
    run_guest "
      set -e
      mkdir -p /opt/zig-versions/${ZIG_VERSION}
      tar -xzf /root/zig.tgz -C /opt/zig-versions/${ZIG_VERSION}
      ln -sf /opt/zig-versions/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}/zig /usr/local/bin/zig
    "
  else
    say "==> downloading Zig $ZIG_VERSION in guest"
    run_guest "cd /work/Tardigrade && ./scripts/install-zig.sh '$ZIG_VERSION' /opt/zig-versions >/tmp/zig-path && ln -sf \"\$(cat /tmp/zig-path)/zig\" /usr/local/bin/zig"
  fi
}

run_campaign_in_guest() {
  local guest_script="$REMOTE_STAGE/run-guest-campaign.sh"
  cat >"$guest_script" <<'GUEST'
#!/usr/bin/env bash
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

canonical=false
if [[ "$PROXMOX_MODE" == kvm && "$PROXMOX_NONCANONICAL" != true ]]; then
  canonical=true
fi

cd /work/Tardigrade
out="benchmarks/results/$(date -u +%Y-%m-%d)/proxmox-${PROXMOX_MODE}-campaign-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out" .zig-cache/proxmox-performance-campaign

if [[ -n "$H2LOAD_PATH" ]]; then
  [[ -x "$H2LOAD_PATH" ]] || die "configured --h2load-path is not executable: $H2LOAD_PATH"
  ln -sf "$H2LOAD_PATH" /usr/local/bin/h2load
fi

{
  printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'mode=%s\n' "$PROXMOX_MODE"
  printf 'canonical=%s\n' "$canonical"
  printf 'guest_hostname=%s\n' "$(hostname)"
  printf 'guest_id=%s\n' "$PROXMOX_GUEST_ID"
  printf 'guest_name=%s\n' "$PROXMOX_GUEST_NAME"
  printf 'tardigrade_ref=%s\n' "$TARDIGRADE_REF"
  printf 'tardigrade_sha=%s\n' "$TARDIGRADE_SHA"
  printf 'source_archive_sha256=%s\n' "$(awk '{print $1}' /root/source.tgz.sha256)"
  printf 'zig=%s\n' "$(zig version)"
  printf 'kernel=%s\n' "$(uname -a)"
  printf 'lscpu<<EOF\n'; lscpu; printf 'EOF\n'
  printf 'memory<<EOF\n'; free -h; printf 'EOF\n'
  printf 'ulimit<<EOF\n'; ulimit -a; printf 'EOF\n'
  printf 'ip_addr<<EOF\n'; ip -br addr; printf 'EOF\n'
  printf 'sysctl<<EOF\n'; sysctl kernel.perf_event_paranoid net.core.rmem_max net.core.wmem_max net.ipv4.ip_local_port_range 2>&1 || true; printf 'EOF\n'
  printf 'versions<<EOF\n'
  wrk --version 2>&1 | head -2 || true
  nginx -v 2>&1 || true
  haproxy -v 2>&1 | head -1 || true
  caddy version 2>&1 || true
  h2load --version 2>&1 | head -1 || true
  k6 version 2>&1 | head -1 || true
  strace -V 2>&1 | head -1 || true
  perf --version 2>&1 | head -1 || true
  tc -V 2>&1 | head -1 || true
  printf 'EOF\n'
} >"$out/environment.txt"
cp "$out/environment.txt" .zig-cache/proxmox-performance-campaign/environment.txt

zig build -Doptimize=ReleaseFast -Dversion="$TARDIGRADE_SHA"

if $canonical; then
  ldd "$(command -v h2load)" 2>/dev/null | grep -Eq 'libngtcp2|libnghttp3' || die "h2load is not QUIC-capable; pass --h2load-path with a pinned ngtcp2/nghttp3-linked build"
  strace -c true >/dev/null 2>&1 || die "strace unavailable"
  perf stat -e task-clock true >/dev/null 2>&1 || die "perf_event unavailable"
  tc qdisc show dev lo >/dev/null 2>&1 || die "tc unavailable"
  TARDIGRADE_EVENT_LOOP_BACKEND=io_uring ./zig-out/bin/tardi --help >/dev/null 2>&1 || true
  TARDIGRADE_EVENT_LOOP_BACKEND=io_uring timeout 5s ./zig-out/bin/tardi run --help >/dev/null 2>&1 || die "io_uring runtime preflight unavailable"
fi

if [[ "$RUN_COMPETITIVE" == true ]]; then
  args=(./benchmarks/competitive/run.sh --binary ./zig-out/bin/tardi --servers "$SERVERS" --duration "$DURATION" --connections "$CONNECTIONS" --threads "$THREADS" --out-dir "$out/competitive")
  if [[ "$TUNE_COMPARISON" == true ]]; then args+=(--tune-comparison); fi
  if [[ "$ALLOW_MISSING" == true ]]; then args+=(--allow-missing); fi
  printf '%q ' "${args[@]}" >"$out/competitive-command.txt"
  printf '\n' >>"$out/competitive-command.txt"
  "${args[@]}"
fi

if [[ "$RUN_LISTENER_SHARDING" == true ]]; then
  listener_conf="$out/listener-sharding.conf"
  cat >"$listener_conf" <<EOF
pid $out/listener-sharding.pid;
listen 19090;
access_log $out/listener-access.log;
error_log $out/listener-error.log;
location = /health {
    return 200 ok;
}
location = /proxy/health {
    proxy_pass http://127.0.0.1:19091/health;
}
EOF
  python3 benchmarks/fixtures/upstream_server.py --port 19091 >"$out/listener-upstream.log" 2>&1 &
  upstream_pid=$!
  trap 'kill "$upstream_pid" >/dev/null 2>&1 || true' EXIT
  ./benchmarks/listener-sharding.sh \
    --start-command "./zig-out/bin/tardi run -c $listener_conf >$out/listener-service.log 2>&1" \
    --port 19090 \
    --duration "$DURATION" \
    --connections "$CONNECTIONS" \
    --threads "$THREADS" \
    --shards "$SHARDS" \
    --save-dir "$out/listener-sharding"
  kill "$upstream_pid" >/dev/null 2>&1 || true
  trap - EXIT
fi

if [[ "$RUN_BACKEND_COMPARISON" == true ]]; then
  mkdir -p "$out/backend-comparison"
  backend_upstream_port=19191
  python3 benchmarks/fixtures/upstream_server.py --port "$backend_upstream_port" >"$out/backend-upstream.log" 2>&1 &
  backend_upstream_pid=$!
  trap 'kill "$backend_upstream_pid" >/dev/null 2>&1 || true' EXIT
  for backend in epoll io_uring; do
    backend_dir="$out/backend-comparison/$backend"
    mkdir -p "$backend_dir"
    backend_conf="$backend_dir/tardigrade.conf"
    cat >"$backend_conf" <<EOF
pid $backend_dir/tardigrade.pid;
listen 19092;
access_log $backend_dir/access.log;
error_log $backend_dir/error.log;
location = /tiny.txt {
    return 200 ok;
}
location = /proxy/health {
    proxy_pass http://127.0.0.1:$backend_upstream_port/health;
}
EOF
    (
      cd /work/Tardigrade
      exec env TARDIGRADE_EVENT_LOOP_BACKEND="$backend" \
        strace -qq -f -c -o "$backend_dir/strace-summary.txt" \
        ./zig-out/bin/tardi run -c "$backend_conf"
    ) >"$backend_dir/service.log" 2>&1 &
    backend_pid=$!
    for _ in $(seq 1 100); do
      curl -fsS http://127.0.0.1:19092/health >/dev/null 2>&1 && break
      if ! kill -0 "$backend_pid" >/dev/null 2>&1; then
        cat "$backend_dir/service.log" >&2 || true
        die "$backend backend exited before health check"
      fi
      sleep 0.1
    done
    curl -fsS http://127.0.0.1:19092/health >/dev/null 2>&1 || die "$backend backend did not become healthy"
    printf 'backend=%s\n' "$backend" >"$backend_dir/commands.txt"
    for workload in static proxy keepalive; do
      case "$workload" in
        static) path=/tiny.txt ;;
        proxy) path=/proxy/health ;;
        keepalive) path=/tiny.txt ;;
      esac
      wrk_args=(-t "$THREADS" -c "$CONNECTIONS" -d "${DURATION}s" "http://127.0.0.1:19092${path}")
      if [[ "$workload" == keepalive ]]; then
        wrk_args+=(-H "Connection: keep-alive")
      fi
      printf 'perf stat wrk %q ' "${wrk_args[@]}" >>"$backend_dir/commands.txt"
      printf '\n' >>"$backend_dir/commands.txt"
      perf stat -e task-clock,context-switches,cpu-migrations,page-faults -o "$backend_dir/${workload}.perf-stat.txt" -- wrk "${wrk_args[@]}" >"$backend_dir/${workload}.wrk.txt" 2>&1
      perf record -g -o "$backend_dir/${workload}.perf.data" -p "$backend_pid" -- sleep "$DURATION" >/dev/null 2>"$backend_dir/${workload}.perf-record.txt" || true
    done
    kill "$backend_pid" >/dev/null 2>&1 || true
    wait "$backend_pid" >/dev/null 2>&1 || true
  done
  kill "$backend_upstream_pid" >/dev/null 2>&1 || true
  trap - EXIT
fi

printf '%s\n' "$out" >.zig-cache/proxmox-performance-campaign/result-dir.txt
GUEST
  push_guest "$REMOTE_STAGE/campaign.env" /root/campaign.env
  push_guest "$guest_script" /root/run-guest-campaign.sh
  run_guest "
    set -euo pipefail
    set -a
    . /root/campaign.env
    set +a
    bash /root/run-guest-campaign.sh
  "
}

capture_host_metadata
assert_idle_for_canonical
if [[ "$PROXMOX_MODE" == lxc-smoke ]]; then
  create_lxc_smoke
else
  create_kvm
fi
install_guest_dependencies
load_source_and_zig
run_campaign_in_guest

if [[ "$PROXMOX_MODE" == kvm ]]; then
  say "==> campaign completed in VM ${guest_id:-unknown}"
else
  say "==> campaign completed in CT ${guest_id:-unknown}"
fi
REMOTE
remote_status=$?
set -e

say "==> collecting artifacts"
if scp_from_pve "$REMOTE_STAGE/artifacts.tgz" "$LOCAL_OUT_DIR/artifacts.tgz"; then
  tar -xzf "$LOCAL_OUT_DIR/artifacts.tgz" -C "$LOCAL_OUT_DIR"
  if scp_from_pve "$REMOTE_STAGE/proxmox-host-metadata.txt" "$LOCAL_OUT_DIR/proxmox-host-metadata.txt"; then
    :
  fi
  if scp_from_pve "$REMOTE_STAGE/guest-config.txt" "$LOCAL_OUT_DIR/guest-config.txt"; then
    :
  fi
  say "artifacts: $LOCAL_OUT_DIR"
else
  say "warning: no artifact archive was available on the Proxmox host" >&2
fi

ssh_pve "rm -rf $(printf '%q' "$REMOTE_STAGE")" >/dev/null 2>&1 || true
exit "$remote_status"
