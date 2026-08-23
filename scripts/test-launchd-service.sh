#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT_DIR=""
TEMPLATE="${REPO_ROOT}/packaging/launchd/io.baresystems.tardigrade.plist"
LABEL="io.baresystems.tardigrade"
TEMP_ROOT=""
AGENT_PLIST="${HOME}/Library/LaunchAgents/${LABEL}.plist"
RENDERED_PLIST=""
TARDI_PID=""
PORT=""

usage() {
    cat <<'EOF'
Usage: test-launchd-service.sh --artifact-dir DIR [--template PLIST]

Runs the checked-in macOS launchd plist through a real user-domain launchctl
bootstrap, readiness/request, and bootout lifecycle. DIR must contain the
packaged Darwin archive shape: executable tardi plus tardigrade -> tardi.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifact-dir) ARTIFACT_DIR="$2"; shift 2 ;;
        --template) TEMPLATE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "launchd smoke requires macOS/Darwin" >&2
    exit 1
fi

if [[ -z "$ARTIFACT_DIR" ]]; then
    echo "--artifact-dir is required" >&2
    usage >&2
    exit 1
fi

if [[ ! -x "$ARTIFACT_DIR/tardi" ]]; then
    echo "artifact directory does not contain executable tardi: $ARTIFACT_DIR" >&2
    exit 1
fi

if [[ ! -L "$ARTIFACT_DIR/tardigrade" ]] || [[ "$(readlink "$ARTIFACT_DIR/tardigrade")" != "tardi" ]]; then
    echo "artifact directory must contain tardigrade -> tardi compatibility alias" >&2
    exit 1
fi

if [[ ! -f "$TEMPLATE" ]]; then
    echo "launchd template not found: $TEMPLATE" >&2
    exit 1
fi

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "$1 is required for launchd smoke" >&2
        exit 1
    }
}

require_command curl
require_command launchctl
require_command plutil
require_command python3

plist_read() {
    /usr/libexec/PlistBuddy -c "Print $1" "$RENDERED_PLIST"
}

print_job() {
    launchctl print "gui/${UID}/${LABEL}" 2>/dev/null || true
}

job_is_loaded() {
    launchctl print "gui/${UID}/${LABEL}" >/dev/null 2>&1
}

job_is_owned_by_smoke() {
    [[ -n "$TEMP_ROOT" ]] || return 1
    print_job | grep -F "$TEMP_ROOT" >/dev/null 2>&1
}

capture_pid() {
    print_job | awk -F'= ' '/^[[:space:]]*pid = / { print $2; exit }'
}

job_summary() {
    print_job | awk '
        /^[[:space:]]*path = / && !seen_path++ { print; next }
        /^[[:space:]]*state = / && !seen_state++ { print; next }
        /^[[:space:]]*program = / && !seen_program++ { print; next }
        /^[[:space:]]*working directory = / && !seen_workdir++ { print; next }
        /^[[:space:]]*stdout path = / && !seen_stdout++ { print; next }
        /^[[:space:]]*stderr path = / && !seen_stderr++ { print; next }
        /^[[:space:]]*runs = / && !seen_runs++ { print; next }
        /^[[:space:]]*pid = / && !seen_pid++ { print; next }
        /^[[:space:]]*last exit code = / && !seen_exit++ { print; next }
    '
}

job_runs() {
    print_job | awk -F'= ' '/^[[:space:]]*runs = / { print $2; exit }'
}

job_last_exit_code() {
    print_job | awk -F'= ' '/^[[:space:]]*last exit code = / { print $2; exit }'
}

diagnostics() {
    status="$1"
    if [[ "$status" -eq 0 ]]; then
        return
    fi

    echo "launchd smoke failed with status $status" >&2
    if [[ -n "$RENDERED_PLIST" && -f "$RENDERED_PLIST" ]]; then
        echo "plutil validation:" >&2
        plutil -lint "$RENDERED_PLIST" >&2 || true
        echo "rendered service fields:" >&2
        {
            printf '  Label=%s\n' "$(plist_read :Label 2>/dev/null || true)"
            printf '  Program[0]=%s\n' "$(plist_read :ProgramArguments:0 2>/dev/null || true)"
            printf '  Program config=%s\n' "$(plist_read :ProgramArguments:3 2>/dev/null || true)"
            printf '  Env config=%s\n' "$(plist_read :EnvironmentVariables:TARDIGRADE_CONFIG_PATH 2>/dev/null || true)"
            printf '  WorkingDirectory=%s\n' "$(plist_read :WorkingDirectory 2>/dev/null || true)"
            printf '  StandardOutPath=%s\n' "$(plist_read :StandardOutPath 2>/dev/null || true)"
            printf '  StandardErrorPath=%s\n' "$(plist_read :StandardErrorPath 2>/dev/null || true)"
        } >&2
    fi
    if job_is_owned_by_smoke; then
        echo "launchctl summary gui/${UID}/${LABEL}:" >&2
        job_summary >&2
    elif job_is_loaded; then
        echo "pre-existing ${LABEL} job present; launchctl details suppressed" >&2
    fi
    if [[ -n "$TEMP_ROOT" ]]; then
        for log in "$TEMP_ROOT/var/log/tardigrade/stdout.log" "$TEMP_ROOT/var/log/tardigrade/stderr.log"; do
            if [[ -f "$log" ]]; then
                echo "tail ${log}:" >&2
                tail -n 80 "$log" >&2 || true
            fi
        done
    fi
}

cleanup() {
    if job_is_owned_by_smoke; then
        launchctl bootout "gui/${UID}/${LABEL}" >/dev/null 2>&1 || true
    fi
    if [[ -f "$AGENT_PLIST" && ! -L "$AGENT_PLIST" && -n "$RENDERED_PLIST" ]] && cmp -s "$AGENT_PLIST" "$RENDERED_PLIST"; then
        rm -f "$AGENT_PLIST"
    fi
    if [[ -n "$TEMP_ROOT" ]]; then
        rm -rf "$TEMP_ROOT"
    fi
}

on_exit() {
    status=$?
    if [[ "$status" -ne 0 ]]; then
        diagnostics "$status"
    fi
    cleanup
    exit "$status"
}

trap on_exit EXIT
trap 'cleanup; exit 130' INT TERM

if job_is_loaded; then
    echo "Refusing to touch pre-existing launchd job ${LABEL}; boot it out manually if it belongs to this test" >&2
    exit 1
fi

if [[ -e "$AGENT_PLIST" || -L "$AGENT_PLIST" ]]; then
    echo "Refusing to overwrite pre-existing LaunchAgent plist: $AGENT_PLIST" >&2
    exit 1
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/tardigrade-launchd-smoke.XXXXXX")"
TEMP_ROOT="$(cd "$TEMP_ROOT" && pwd -P)"
BIN_DIR="$TEMP_ROOT/usr/local/bin"
CONFIG_DIR="$TEMP_ROOT/usr/local/etc/tardigrade"
WORK_DIR="$TEMP_ROOT/usr/local/var/tardigrade"
LOG_DIR="$TEMP_ROOT/usr/local/var/log/tardigrade"
PUBLIC_DIR="$WORK_DIR/public"
RENDERED_PLIST="$TEMP_ROOT/${LABEL}.plist"

mkdir -p "$BIN_DIR" "$CONFIG_DIR" "$WORK_DIR" "$PUBLIC_DIR" "$LOG_DIR" "$(dirname "$AGENT_PLIST")"
install -m 0755 "$ARTIFACT_DIR/tardi" "$BIN_DIR/tardi"
ln -s tardi "$BIN_DIR/tardigrade"
printf '%s\n' '<h1>launchd smoke</h1>' > "$PUBLIC_DIR/index.html"
: > "$LOG_DIR/stdout.log"
: > "$LOG_DIR/stderr.log"

PORT="$(python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
PY
)"

CONFIG_PATH="$CONFIG_DIR/tardigrade.conf"
cat > "$CONFIG_PATH" <<EOF
listen 127.0.0.1:${PORT};
server_name localhost;

root ./public;
try_files \$uri /index.html;

location = /health {
    return 200 ok;
}

location / {
    root ./public;
    try_files \$uri /index.html;
}
EOF

python3 - "$TEMPLATE" "$RENDERED_PLIST" "$TEMP_ROOT" <<'PY'
import pathlib
import sys

template, output, root = map(pathlib.Path, sys.argv[1:])
replacements = {
    "/usr/local/bin/tardigrade": root / "usr/local/bin/tardigrade",
    "/usr/local/etc/tardigrade/tardigrade.conf": root / "usr/local/etc/tardigrade/tardigrade.conf",
    "/usr/local/var/tardigrade": root / "usr/local/var/tardigrade",
    "/usr/local/var/log/tardigrade/stdout.log": root / "usr/local/var/log/tardigrade/stdout.log",
    "/usr/local/var/log/tardigrade/stderr.log": root / "usr/local/var/log/tardigrade/stderr.log",
}
data = template.read_text()
for old, new in replacements.items():
    data = data.replace(old, str(new))
output.write_text(data)
PY

plutil -lint "$RENDERED_PLIST"

assert_equals() {
    local actual="$1"
    local expected="$2"
    local description="$3"
    if [[ "$actual" != "$expected" ]]; then
        printf '%s mismatch\n  expected: %s\n  actual:   %s\n' "$description" "$expected" "$actual" >&2
        exit 1
    fi
}

assert_equals "$(plist_read :Label)" "$LABEL" "Label"
assert_equals "$(plist_read :ProgramArguments:0)" "$BIN_DIR/tardigrade" "ProgramArguments[0]"
assert_equals "$(plist_read :ProgramArguments:1)" "run" "ProgramArguments[1]"
assert_equals "$(plist_read :ProgramArguments:2)" "-c" "ProgramArguments[2]"
assert_equals "$(plist_read :ProgramArguments:3)" "$CONFIG_PATH" "ProgramArguments[3]"
assert_equals "$(plist_read :EnvironmentVariables:TARDIGRADE_CONFIG_PATH)" "$CONFIG_PATH" "TARDIGRADE_CONFIG_PATH"
assert_equals "$(plist_read :KeepAlive)" "true" "KeepAlive"
assert_equals "$(plist_read :RunAtLoad)" "true" "RunAtLoad"
assert_equals "$(plist_read :WorkingDirectory)" "$WORK_DIR" "WorkingDirectory"
assert_equals "$(plist_read :StandardOutPath)" "$LOG_DIR/stdout.log" "StandardOutPath"
assert_equals "$(plist_read :StandardErrorPath)" "$LOG_DIR/stderr.log" "StandardErrorPath"

test -x "$BIN_DIR/tardi"
test -L "$BIN_DIR/tardigrade"
assert_equals "$(readlink "$BIN_DIR/tardigrade")" "tardi" "staged compatibility alias"
test -f "$CONFIG_PATH"
test -d "$WORK_DIR"
test -d "$LOG_DIR"

"$BIN_DIR/tardi" check "$CONFIG_PATH"

install -m 0644 "$RENDERED_PLIST" "$AGENT_PLIST"
launchctl bootstrap "gui/${UID}" "$AGENT_PLIST"

echo "launchctl print after bootstrap:"
job_summary

ready=false
body=""
deadline=$((SECONDS + 20))
reported_exit=false
while (( SECONDS < deadline )); do
    TARDI_PID="$(capture_pid || true)"
    if body="$(curl -fsS --connect-timeout 1 --max-time 2 -H 'Host: localhost' "http://127.0.0.1:${PORT}/" 2>/dev/null)"; then
        ready=true
        break
    fi
    if job_is_loaded; then
        runs="$(job_runs || true)"
        last_exit="$(job_last_exit_code || true)"
        if [[ "$last_exit" =~ ^[0-9]+$ && "$last_exit" -ne 0 && -z "$TARDI_PID" ]]; then
            echo "launchd job exited before readiness: last exit code $last_exit" >&2
            job_summary >&2
            exit 1
        fi
        if [[ "$runs" =~ ^[0-9]+$ && "$runs" -ge 5 ]]; then
            echo "launchd job restarted repeatedly before readiness: runs=$runs" >&2
            job_summary >&2
            exit 1
        fi
        if [[ "$reported_exit" != true && "$last_exit" =~ ^[0-9]+$ && "$last_exit" -ne 0 ]]; then
            echo "launchd job reported non-zero exit before readiness: last exit code $last_exit" >&2
            job_summary >&2
            reported_exit=true
        fi
    else
        echo "launchd job disappeared before readiness" >&2
        exit 1
    fi
    sleep 0.2
done

if [[ "$ready" != true ]]; then
    echo "launchd-managed Tardigrade did not become ready on port $PORT" >&2
    exit 1
fi

assert_equals "$body" '<h1>launchd smoke</h1>' "root response body"
assert_equals "$(curl -fsS --connect-timeout 1 --max-time 2 -H 'Host: localhost' "http://127.0.0.1:${PORT}/health")" "ok" "health response body"

if [[ -z "$TARDI_PID" ]]; then
    TARDI_PID="$(capture_pid || true)"
fi

launchctl bootout "gui/${UID}/${LABEL}"

for _ in {1..50}; do
    if ! job_is_loaded; then
        break
    fi
    sleep 0.2
done

if job_is_loaded; then
    echo "launchd job still resolves after bootout" >&2
    exit 1
fi

if [[ -n "$TARDI_PID" ]]; then
    for _ in {1..50}; do
        if ! kill -0 "$TARDI_PID" >/dev/null 2>&1; then
            break
        fi
        sleep 0.2
    done
    if kill -0 "$TARDI_PID" >/dev/null 2>&1; then
        echo "launchd-managed process $TARDI_PID survived bootout" >&2
        exit 1
    fi
fi

rm -f "$AGENT_PLIST"
rm -rf "$TEMP_ROOT"
TEMP_ROOT=""

trap - EXIT
echo "launchd smoke succeeded on user domain gui/${UID} using $BIN_DIR/tardigrade"
