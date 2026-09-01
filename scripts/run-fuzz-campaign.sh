#!/usr/bin/env bash
# Resumable orchestrator for Tardigrade's existing Zig fuzz build steps.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo"

EXPECTED_ZIG_VERSION="${EXPECTED_ZIG_VERSION:-0.16.0}"

tier=""
family=""
target=""
budget=""
output=""
source_sha=""
resume=false
list=false
noncanonical_smoke=false
skip_preflight=false
watchdog_seconds=""

usage() {
  cat <<'EOF'
Usage: scripts/run-fuzz-campaign.sh [OPTIONS]

Runs one existing Zig fuzz family/target at a time and preserves append-only
campaign evidence. This script does not implement fuzzing semantics.

Required for execution:
  --tier 1|2|3
  --family tls-protocol|tls-record|tls-resumption|pki|crypto|quic
  --output DIR

Target selection:
  --target NAME          Exact `test "fuzz: ..."` name. Required for Tier 2/3.
                         Omit for Tier 1 family-wide rows.
  --budget N|K|M|G       Mutation budget. Defaults: Tier 1=10M, Tier 2=50M,
                         Tier 3=100M.

Evidence and safety:
  --source-sha SHA       Refuse canonical runs unless HEAD matches SHA.
  --resume              Skip a row only when manifest proves same SHA, step,
                         filter, same-or-greater budget, and status pass.
  --noncanonical-smoke  Allow dirty worktrees and mark evidence non-canonical.
  --skip-preflight      Only with --noncanonical-smoke; useful for cheap script
                         validation and smoke budgets.
  --watchdog SECONDS    Bound one fuzz process; expiry records possible_hang.

Discovery:
  --list                Print current family/target registry and exit.
  --help                Show this help.

Examples:
  scripts/run-fuzz-campaign.sh --list
  scripts/run-fuzz-campaign.sh --tier 1 --family quic --output artifacts/hardening/fuzz/smoke --noncanonical-smoke --budget 1K --skip-preflight
  scripts/run-fuzz-campaign.sh --family quic --target 'fuzz: packet parser preserves bounded slice and progress invariants' --budget 50M --output artifacts/hardening/fuzz/<campaign-id>
EOF
}

say() { printf '%s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

json_escape() {
  awk 'BEGIN {
    s = ARGV[1]; ARGV[1] = "";
    gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); gsub(/\t/,"\\t",s);
    gsub(/\r/,"\\r",s); gsub(/\n/,"\\n",s);
    printf "%s", s
  }' "$1"
}

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-//; s/-$//; s/-+/-/g'
}

budget_to_mutations() {
  local value="$1" number suffix multiplier
  [[ "$value" =~ ^[0-9]+[KkMmGg]?$ ]] || die "invalid budget: $value"
  number="${value%[KkMmGg]}"
  suffix="${value#"$number"}"
  multiplier=1
  case "$suffix" in
    K|k) multiplier=1000 ;;
    M|m) multiplier=1000000 ;;
    G|g) multiplier=1000000000 ;;
  esac
  awk -v n="$number" -v m="$multiplier" 'BEGIN { printf "%.0f\n", n * m }'
}

family_step() {
  case "$1" in
    tls-protocol) echo "test-tls-protocol-fuzz" ;;
    tls-record) echo "test-tls-record-fuzz" ;;
    tls-resumption) echo "test-tls-resumption-fuzz" ;;
    pki) echo "test-pki-fuzz" ;;
    crypto) echo "test-crypto-provider-fuzz" ;;
    quic) echo "test-quic" ;;
    *) die "unknown family: $1" ;;
  esac
}

family_filter_option() {
  case "$1" in
    tls-protocol) echo "-Dtls-protocol-test-filter=$2" ;;
    tls-record) echo "-Dtls-record-test-filter=$2" ;;
    tls-resumption) echo "-Dtls-resumption-test-filter=$2" ;;
    pki) echo "-Dpki-test-filter=$2" ;;
    crypto) echo "-Dcrypto-test-filter=$2" ;;
    quic) echo "-Dquic-test-filter=$2" ;;
    *) die "unknown family: $1" ;;
  esac
}

target_family() {
  local path="$1" name="$2"
  case "$name" in
    "fuzz: TLS protocol:"*) echo "tls-protocol"; return ;;
    "fuzz: TLS record:"*) echo "tls-record"; return ;;
    "fuzz: TLS resumption:"*) echo "tls-resumption"; return ;;
    "fuzz: PKI:"*) echo "pki"; return ;;
  esac
  case "$path" in
    tests/crypto_provider_fuzz.zig) echo "crypto" ;;
    src/quic/*|src/http3/*) echo "quic" ;;
    *) return 1 ;;
  esac
}

discover_targets() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git grep -n 'test "fuzz:' -- src tests
  elif command -v rg >/dev/null 2>&1; then
    rg -n 'test "fuzz:' src tests
  else
    grep -R -n 'test "fuzz:' src tests
  fi | while IFS=: read -r path line rest; do
    name="$(printf '%s\n' "$rest" | sed -n 's/.*test "\(fuzz: [^"]*\)".*/\1/p')"
    [[ -n "$name" ]] || continue
    fam="$(target_family "$path" "$name" 2>/dev/null || true)"
    [[ -n "${fam:-}" ]] || continue
    printf '%s\t%s\t%s\t%s\n' "$fam" "$(family_step "$fam")" "$name" "$path:$line"
  done | sort -u
}

git_head_value() {
  if git rev-parse HEAD >/dev/null 2>&1; then
    git rev-parse HEAD
  elif [[ -n "$source_sha" ]]; then
    printf '%s\n' "$source_sha"
  else
    die "not a Git checkout; pass --source-sha when running from a source archive"
  fi
}

git_status_short_value() {
  if git rev-parse --git-dir >/dev/null 2>&1; then
    git status --short
  else
    printf '%s\n' "source archive: no git worktree status available"
  fi
}

target_selects_current_fuzz() {
  local fam="$1" name="$2"
  discover_targets | awk -F '\t' -v f="$fam" -v n="$name" '
    $1 == f && $3 == n {
      count += 1
      selected = selected $3 "\n"
    }
    END {
      if (count == 1) exit 0
      if (count == 0) {
        printf "no current fuzz target selected by filter: %s\n", n > "/dev/stderr"
      } else {
        printf "ambiguous fuzz filter selects %d targets:\n%s", count, selected > "/dev/stderr"
      }
      exit 1
    }'
}

resume_has_pass() {
  local manifest="$1" sha="$2" step="$3" filter="$4" min_budget="$5"
  [[ -f "$manifest" ]] || return 1
  awk -v sha="$sha" -v step="$step" -v filter="$filter" -v min_budget="$min_budget" '
    $0 ~ "\"source_commit_sha\":\"" sha "\"" &&
    $0 ~ "\"build_step\":\"" step "\"" &&
    $0 ~ "\"filter\":\"" filter "\"" &&
    $0 ~ "\"status\":\"pass\"" {
      line = $0
      sub(/^.*"budget_mutations":/, "", line)
      sub(/[^0-9].*$/, "", line)
      if (line + 0 >= min_budget + 0) found = 1
    }
    END { exit(found ? 0 : 1) }
  ' "$manifest"
}

capture_environment() {
  local file="$1"
  {
    printf 'date_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'git_head=%s\n' "$(git_head_value)"
    printf 'git_status_short<<EOF\n'; git_status_short_value; printf 'EOF\n'
    printf 'zig_version=%s\n' "$(zig version 2>/dev/null || true)"
    printf 'uname=%s\n' "$(uname -a)"
    printf 'os_arch=%s/%s\n' "$(uname -s)" "$(uname -m)"
    if command -v lscpu >/dev/null 2>&1; then
      printf 'lscpu<<EOF\n'; lscpu 2>&1 || true; printf 'EOF\n'
    fi
    if [[ -r /proc/meminfo ]]; then
      printf 'proc_meminfo<<EOF\n'; cat /proc/meminfo; printf 'EOF\n'
    fi
    if command -v sysctl >/dev/null 2>&1; then
      printf 'sysctl_cpu_mem<<EOF\n'
      sysctl -n machdep.cpu.brand_string hw.ncpu hw.memsize 2>&1 || true
      printf 'EOF\n'
    fi
  } >"$file"
}

cpu_identity() {
  local cpu=""
  if command -v lscpu >/dev/null 2>&1; then
    cpu="$(lscpu 2>/dev/null | awk -F ': +' '/Model name:/ { print $2; exit }')"
  fi
  if [[ -z "$cpu" && -r /proc/cpuinfo ]]; then
    cpu="$(awk -F ': +' '/model name/ { print $2; exit }' /proc/cpuinfo)"
  fi
  if [[ -z "$cpu" ]] && command -v sysctl >/dev/null 2>&1; then
    cpu="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
  fi
  if [[ -z "$cpu" ]]; then
    cpu="unknown"
  fi
  printf '%s\n' "$cpu"
}

run_preflight() {
  local dir="$1"
  mkdir -p "$dir"
  capture_environment "$dir/environment.txt"
  {
    printf '%s\n' 'zig fmt --check build.zig src/ tests/'
    zig fmt --check build.zig src/ tests/
  } >"$dir/01-zig-fmt.log" 2>&1
  {
    printf '%s\n' 'zig build test --summary all --error-style verbose'
    zig build test --summary all --error-style verbose
  } >"$dir/02-zig-build-test.log" 2>&1
  {
    printf '%s\n' 'zig build test-security-corpus --summary all --error-style verbose'
    zig build test-security-corpus --summary all --error-style verbose
  } >"$dir/03-security-corpus.log" 2>&1
  {
    printf '%s\n' 'zig build test-integration --summary all --error-style verbose'
    zig build test-integration --summary all --error-style verbose
  } >"$dir/04-integration.log" 2>&1
}

ensure_campaign_metadata() {
  local canonical_json="$1"
  local created_utc metadata_tmp targets_tmp environment_tmp
  created_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

  mkdir -p "$output"
  if [[ -f "$output/campaign.json" ]]; then
    grep -F "\"source_commit_sha\":\"$head_sha\"" "$output/campaign.json" >/dev/null ||
      die "output directory belongs to a different source SHA"
    grep -F "\"canonical\":$canonical_json" "$output/campaign.json" >/dev/null ||
      die "output directory belongs to a different canonical/smoke mode"
    grep -F "\"expected_zig_version\":\"$EXPECTED_ZIG_VERSION\"" "$output/campaign.json" >/dev/null ||
      die "output directory belongs to a different Zig version"
  else
    metadata_tmp="$(mktemp "${output}/campaign.json.tmp.XXXXXX")"
    cat >"$metadata_tmp" <<EOF
{"campaign_id":"$(json_escape "$campaign_id")","source_commit_sha":"$head_sha","canonical":$canonical_json,"expected_zig_version":"$(json_escape "$EXPECTED_ZIG_VERSION")","created_utc":"$created_utc"}
EOF
    mv "$metadata_tmp" "$output/campaign.json"
  fi

  if [[ ! -f "$output/targets.tsv" ]]; then
    targets_tmp="$(mktemp "${output}/targets.tsv.tmp.XXXXXX")"
    discover_targets >"$targets_tmp"
    mv "$targets_tmp" "$output/targets.tsv"
  fi

  if [[ ! -f "$output/environment.txt" ]]; then
    environment_tmp="$(mktemp "${output}/environment.txt.tmp.XXXXXX")"
    capture_environment "$environment_tmp"
    mv "$environment_tmp" "$output/environment.txt"
  fi
}

ensure_preflight() {
  local preflight_root="$output/preflight" preflight_attempt
  if $skip_preflight; then
    say "==> skipping deterministic preflight for non-canonical smoke"
    return
  fi
  mkdir -p "$preflight_root/attempts"
  if [[ -f "$preflight_root/complete" ]]; then
    say "==> reusing retained deterministic preflight evidence"
    return
  fi

  preflight_attempt="$preflight_root/attempts/$(date -u '+%Y%m%dT%H%M%SZ')-$$"
  say "==> running deterministic preflight"
  run_preflight "$preflight_attempt"
  printf '%s\n' "$preflight_attempt" >"$preflight_root/complete"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tier) tier="$2"; shift 2 ;;
    --family) family="$2"; shift 2 ;;
    --target) target="$2"; shift 2 ;;
    --budget) budget="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --source-sha) source_sha="$2"; shift 2 ;;
    --watchdog) watchdog_seconds="$2"; shift 2 ;;
    --resume) resume=true; shift ;;
    --list) list=true; shift ;;
    --noncanonical-smoke) noncanonical_smoke=true; shift ;;
    --skip-preflight) skip_preflight=true; shift ;;
    --help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

if $list; then
  discover_targets
  exit 0
fi

[[ -n "$tier" ]] || tier=2
case "$tier" in 1|2|3) ;; *) die "--tier must be 1, 2, or 3" ;; esac
[[ -n "$family" ]] || die "--family is required"
step="$(family_step "$family")"
[[ -n "$output" ]] || die "--output is required"

if [[ -z "$budget" ]]; then
  case "$tier" in
    1) budget=10M ;;
    2) budget=50M ;;
    3) budget=100M ;;
  esac
fi
budget_mutations="$(budget_to_mutations "$budget")"
[[ -z "$watchdog_seconds" || "$watchdog_seconds" =~ ^[0-9]+$ ]] || die "--watchdog must be seconds"

if [[ "$tier" != 1 && -z "$target" ]]; then
  die "--target is required for Tier $tier"
fi
if [[ -n "$target" ]] && ! target_selects_current_fuzz "$family" "$target"; then
  die "target filter is not a unique current $family fuzz target: $target"
fi
if $skip_preflight && ! $noncanonical_smoke; then
  die "--skip-preflight is only allowed with --noncanonical-smoke"
fi

head_sha="$(git_head_value)"
if [[ -n "$source_sha" && "$source_sha" != "$head_sha" ]]; then
  die "requested source SHA $source_sha does not match checked-out HEAD $head_sha"
fi
if [[ "$(zig version 2>/dev/null || true)" != "$EXPECTED_ZIG_VERSION" ]]; then
  die "expected Zig $EXPECTED_ZIG_VERSION; found $(zig version 2>/dev/null || echo unavailable)"
fi
if ! $noncanonical_smoke && git rev-parse --git-dir >/dev/null 2>&1 && [[ -n "$(git status --short)" ]]; then
  git status --short >&2
  die "canonical campaign requires a clean worktree; pass --noncanonical-smoke for setup smoke evidence"
fi

campaign_id="$(basename "$output")"
canonical_json="$($noncanonical_smoke && echo false || echo true)"
ensure_campaign_metadata "$canonical_json"
mkdir -p "$output/preflight" "$output/runs" "$output/findings"

ensure_preflight

filter="<family>"
run_key="${family}__family__${budget}"
if [[ -n "$target" ]]; then
  filter="$target"
  run_key="${family}__$(slugify "$target")__${budget}"
fi

manifest="$output/manifest.jsonl"
if $resume && resume_has_pass "$manifest" "$head_sha" "$step" "$filter" "$budget_mutations"; then
  say "==> resume: existing same-SHA pass satisfies $family $filter >= $budget"
  exit 0
fi

attempt_id="$(date -u '+%Y%m%dT%H%M%SZ')-$$"
run_dir="$output/runs/$run_key/attempts/$attempt_id"
mkdir -p "$run_dir"
stdout_log="$run_dir/stdout.log"
stderr_log="$run_dir/stderr.log"
command_file="$run_dir/command.txt"
result_file="$run_dir/result.json"
finding_dir="$output/findings/${family}__$(slugify "$filter")/$attempt_id"

cmd=(zig build "$step" -Doptimize=ReleaseFast "--fuzz=$budget" --summary all --error-style verbose)
if [[ -n "$target" ]]; then
  cmd+=("$(family_filter_option "$family" "$target")")
fi
printf '%q ' "${cmd[@]}" >"$command_file"
printf '\n' >>"$command_file"

say "==> running ${cmd[*]}"
started_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
start_epoch="$(date +%s)"
interrupted=false
child_pid=""
terminate_child() {
  if [[ -n "$child_pid" ]]; then
    if command -v pkill >/dev/null 2>&1; then
      pkill -TERM -P "$child_pid" 2>/dev/null || true
    fi
    kill -TERM "$child_pid" 2>/dev/null || true
  fi
}
on_interrupt() {
  interrupted=true
  terminate_child
}
trap on_interrupt INT TERM
set +e
if [[ -n "$watchdog_seconds" ]]; then
  command -v timeout >/dev/null 2>&1 || die "--watchdog requires the timeout command"
  timeout "$watchdog_seconds" "${cmd[@]}" >"$stdout_log" 2>"$stderr_log" &
else
  "${cmd[@]}" >"$stdout_log" 2>"$stderr_log" &
fi
child_pid=$!
wait "$child_pid"
exit_code=$?
if $interrupted || [[ "$exit_code" -eq 130 || "$exit_code" -eq 143 ]]; then
  terminate_child
  wait "$child_pid" >/dev/null 2>&1 || true
fi
child_pid=""
set -e
trap - INT TERM
end_epoch="$(date +%s)"
ended_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
elapsed=$((end_epoch - start_epoch))

status="pass"
if $interrupted; then
  status="interrupted"
elif [[ "$exit_code" -eq 124 ]]; then
  status="possible_hang"
elif [[ "$exit_code" -eq 130 || "$exit_code" -eq 143 ]]; then
  status="interrupted"
elif [[ "$exit_code" -ne 0 ]]; then
  status="fail"
fi

execs_per_sec="$(grep -Eho '[0-9]+(\.[0-9]+)?[[:space:]]+(exec|execs|executions)/s(ec)?' "$stdout_log" "$stderr_log" 2>/dev/null | tail -1 | awk '{print $1}' || true)"
if [[ -z "$execs_per_sec" ]]; then
  execs_per_sec="null"
else
  execs_per_sec="\"$(json_escape "$execs_per_sec")\""
fi

finding_sha_json="null"
if [[ "$status" != "pass" ]]; then
  mkdir -p "$finding_dir"
  cp "$command_file" "$finding_dir/command.txt"
  cp "$stdout_log" "$finding_dir/stdout.log"
  cp "$stderr_log" "$finding_dir/stderr.log"
  if [[ -d .zig-cache ]]; then
    tar -czf "$finding_dir/zig-cache-preserved.tgz" .zig-cache 2>/dev/null || true
  fi
  {
    printf 'family=%s\n' "$family"
    printf 'build_step=%s\n' "$step"
    printf 'filter=%s\n' "$filter"
    printf 'source_commit_sha=%s\n' "$head_sha"
    printf 'status=%s\n' "$status"
    printf 'exit_code=%s\n' "$exit_code"
    printf 'replay_command='
    printf '%q ' zig build "$step" --summary all --error-style verbose
    if [[ -n "$target" ]]; then printf '%q ' "$(family_filter_option "$family" "$target")"; fi
    printf '\n'
    printf 'note=%s\n' 'Exact Zig crash input path was not inferred automatically; complete logs and .zig-cache state were preserved for deliberate recovery.'
  } >"$finding_dir/provenance.txt"
fi

cat >"$result_file" <<EOF
{"status":"$status","exit_code":$exit_code,"started_utc":"$started_utc","ended_utc":"$ended_utc","elapsed_seconds":$elapsed}
EOF

printf '{"campaign_id":"%s","started_utc":"%s","ended_utc":"%s","source_commit_sha":"%s","zig_version":"%s","os_arch":"%s/%s","cpu":"%s","family":"%s","build_step":"%s","filter":"%s","budget":"%s","budget_mutations":%s,"optimize":"ReleaseFast","elapsed_seconds":%s,"executions_per_second":%s,"status":"%s","exit_code":%s,"finding_path":%s,"finding_sha256":%s,"stdout_path":"%s","stderr_path":"%s"}\n' \
  "$(json_escape "$campaign_id")" "$started_utc" "$ended_utc" "$head_sha" "$(json_escape "$(zig version)")" "$(json_escape "$(uname -s)")" "$(json_escape "$(uname -m)")" \
  "$(json_escape "$(cpu_identity)")" \
  "$(json_escape "$family")" "$(json_escape "$step")" "$(json_escape "$filter")" "$(json_escape "$budget")" "$budget_mutations" "$elapsed" "$execs_per_sec" "$status" "$exit_code" \
  "$([[ "$status" == pass ]] && echo null || printf '"%s"' "$(json_escape "$finding_dir")")" "$finding_sha_json" "$(json_escape "$stdout_log")" "$(json_escape "$stderr_log")" >>"$manifest"

if [[ "$status" != "pass" ]]; then
  say "==> $status: preserved logs/state under $finding_dir"
  exit "$exit_code"
fi
say "==> pass: evidence appended to $manifest"
