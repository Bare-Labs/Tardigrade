#!/usr/bin/env bash
# Production binary linkage audit and dependency inventory (#379, epic #327,
# cutover #634, retirement #649, #651).
#
# Inspects a produced tardi binary's dynamic dependencies and emits a
# machine-readable inventory. Every supported profile (`general` and
# `appliance`) is native-only: this fails if the binary links any unexplained
# dynamic dependency outside the narrow per-platform OS/runtime substrate
# allowlist, and confirms the binary self-reports the native TLS path.
#
# Usage:
#   audit-release-binary.sh --binary PATH --profile {general|appliance} \
#       [--output inventory.json]
#   audit-release-binary.sh --self-test
#
# Exit code 0 means the audit passed. A forbidden linkage, or a profile that
# disagrees with the binary's self-report, exits 1.

set -euo pipefail

BINARY=""
PROFILE=""
OUTPUT=""
SELF_TEST=false

usage() {
    cat <<'EOF'
Usage: audit-release-binary.sh --binary PATH --profile {general|appliance} [--output FILE]
       audit-release-binary.sh --self-test
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
    --binary)
        BINARY="$2"
        shift 2
        ;;
    --profile)
        PROFILE="$2"
        shift 2
        ;;
    --output)
        OUTPUT="$2"
        shift 2
        ;;
    --self-test)
        SELF_TEST=true
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        usage
        exit 2
        ;;
    esac
done

allowed_dynamic_dependency() {
    local host_os="$1" dep="$2"
    case "$host_os" in
    Darwin)
        case "$dep" in
        libSystem.B.dylib | /usr/lib/libSystem.B.dylib) return 0 ;;
        *) return 1 ;;
        esac
        ;;
    Linux)
        case "$dep" in
        libc.so.* | ld-linux*.so.* | ld64.so.* | libpthread.so.* | libm.so.* | libdl.so.* | librt.so.* | libresolv.so.* | libgcc_s.so.* | libunwind.so.*) return 0 ;;
        *) return 1 ;;
        esac
        ;;
    *)
        return 1
        ;;
    esac
}

evaluate_dependency_list() {
    local host_os="$1" deps_in="$2" dep
    while IFS= read -r dep; do
        [ -z "$dep" ] && continue
        if ! allowed_dynamic_dependency "$host_os" "$dep"; then
            printf '%s\n' "$dep"
        fi
    done <<<"$deps_in"
}

parse_darwin_dependencies() {
    awk 'NR > 1 { print $1 }' | sort -u
}

run_self_test() {
    local parsed unknown expected
    parsed="$(printf '%s\n' \
        $'fake:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n\t@rpath/ForeignCodec.dylib (compatibility version 1.0.0, current version 1.0.0)\n\t/System/Library/Frameworks/Foreign.framework/Versions/A/Foreign (compatibility version 1.0.0, current version 1.0.0)' |
        parse_darwin_dependencies)"
    expected=$'/System/Library/Frameworks/Foreign.framework/Versions/A/Foreign\n/usr/lib/libSystem.B.dylib\n@rpath/ForeignCodec.dylib'
    if [ "$parsed" != "$expected" ]; then
        echo "self-test failed: Darwin parser did not preserve every dependency install name" >&2
        return 1
    fi
    unknown="$(evaluate_dependency_list Darwin "$parsed")"
    expected=$'/System/Library/Frameworks/Foreign.framework/Versions/A/Foreign\n@rpath/ForeignCodec.dylib'
    if [ "$unknown" != "$expected" ]; then
        echo "self-test failed: Darwin unknown dependency was not rejected" >&2
        return 1
    fi
    unknown="$(evaluate_dependency_list Linux $'libc.so.6\nlibforeigncodec.so.1')"
    if [ "$unknown" != "libforeigncodec.so.1" ]; then
        echo "self-test failed: Linux unknown dependency was not rejected" >&2
        return 1
    fi
    unknown="$(evaluate_dependency_list Linux $'libc.so.6\nlibpthread.so.0')"
    if [ -n "$unknown" ]; then
        echo "self-test failed: Linux OS substrate dependency was rejected: $unknown" >&2
        return 1
    fi
    echo "binary audit self-test passed"
}

if [ "$SELF_TEST" = true ]; then
    run_self_test
    exit $?
fi

if [ -z "$BINARY" ] || [ -z "$PROFILE" ]; then
    usage
    exit 2
fi
if [ ! -f "$BINARY" ]; then
    echo "binary not found: $BINARY" >&2
    exit 2
fi
case "$PROFILE" in
general | appliance) ;;
*)
    echo "invalid profile: $PROFILE (expected general or appliance)" >&2
    exit 2
    ;;
esac

# ── Collect dynamic dependencies across platforms ────────────────────────────
#
# The inspection must distinguish two very different outcomes: a binary with no
# dynamic dependencies (a valid, fully static build — an empty dependency list)
# from a failed inspection (missing tool, unreadable/corrupt binary, wrong
# architecture). The former is legitimate; the latter must never be reported as
# a clean, dependency-free appliance artifact, so it exits with an error rather
# than an empty list. On Linux we read the ELF dynamic section directly
# (readelf/objdump) instead of executing the binary through `ldd`.
os="$(uname -s)"
deps=""
inspection_tool=""
case "$os" in
Linux)
    if command -v readelf >/dev/null 2>&1; then
        inspection_tool="readelf -d"
        if ! deps="$(readelf -d "$BINARY" 2>/dev/null)"; then
            echo "inspection failed: readelf could not read '$BINARY' (not an ELF object, corrupt, or wrong architecture)" >&2
            exit 2
        fi
    elif command -v objdump >/dev/null 2>&1; then
        inspection_tool="objdump -p"
        if ! deps="$(objdump -p "$BINARY" 2>/dev/null)"; then
            echo "inspection failed: objdump could not read '$BINARY'" >&2
            exit 2
        fi
    else
        echo "inspection failed: no ELF inspection tool (readelf or objdump) available" >&2
        exit 2
    fi
    # readelf/objdump both render NEEDED entries as "[libfoo.so.N]"; a static
    # binary simply has none. No match therefore means static, not a failure.
    dep_names="$(printf '%s\n' "$deps" |
        grep -E 'NEEDED' |
        grep -oE '\[[^][]+\]' |
        tr -d '[]' |
        sort -u || true)"
    ;;
Darwin)
    inspection_tool="otool -L"
    if ! deps="$(otool -L "$BINARY" 2>/dev/null)"; then
        echo "inspection failed: otool could not read '$BINARY' (not a Mach-O object, corrupt, or wrong architecture)" >&2
        exit 2
    fi
    # otool -L lists the binary path on the first line, then one dependency
    # install name per indented line. Keep the full first token so non-lib
    # dylibs and frameworks cannot disappear before policy evaluation.
    dep_names="$(printf '%s\n' "$deps" |
        parse_darwin_dependencies || true)"
    ;;
*)
    echo "unsupported host OS for binary inspection: $os" >&2
    exit 2
    ;;
esac

links_openssl=false
if printf '%s\n' "$dep_names" | grep -qiE 'libssl|libcrypto'; then
    links_openssl=true
fi

unallowed_deps="$(evaluate_dependency_list "$os" "$dep_names")"

# ── Binary self-report (the version line records the built-in profile) ───────
# Both the profile and the backend are parsed and checked: the requested
# --profile must match the profile compiled into the artifact, and the backend
# must be consistent with it. A binary that cannot report its profile is a
# violation, not a pass.
self_report="$("$BINARY" version 2>/dev/null || true)"
reported_backend="unknown"
case "$self_report" in
*"tls-backend=native"*) reported_backend="native" ;;
esac
reported_profile="$(printf '%s' "$self_report" | sed -nE 's/.*tls-profile=([a-zA-Z0-9_-]+).*/\1/p')"
[ -n "$reported_profile" ] || reported_profile="unknown"

# ── Policy evaluation ────────────────────────────────────────────────────────
status="pass"
declare -a violations=()

if [ -n "$unallowed_deps" ]; then
    while IFS= read -r hit; do
        [ -z "$hit" ] && continue
        violations+=("unallowed dynamic dependency outside OS/runtime substrate: $hit")
    done <<<"$unallowed_deps"
fi

# The artifact must actually be the profile it is being audited as, regardless
# of profile: a native appliance binary audited as general (or vice versa) is a
# mismatch, not a pass.
if [ "$reported_profile" != "$PROFILE" ]; then
    violations+=("artifact self-reports tls-profile '$reported_profile' but was audited as '$PROFILE'")
fi

# Every supported profile is native-only (#649): no profile-specific carve-out
# permits OpenSSL linkage any more.
if [ "$links_openssl" = true ]; then
    violations+=("$PROFILE artifact links OpenSSL (libssl/libcrypto)")
fi
if [ "$reported_backend" != "native" ]; then
    violations+=("$PROFILE artifact does not self-report the native TLS path (got '$reported_backend')")
fi

if [ "${#violations[@]}" -gt 0 ]; then
    status="fail"
fi

# ── Emit machine-readable inventory ──────────────────────────────────────────
emit_inventory() {
    printf '{\n'
    printf '  "binary": %s,\n' "$(json_string "$BINARY")"
    printf '  "profile": %s,\n' "$(json_string "$PROFILE")"
    printf '  "host_os": %s,\n' "$(json_string "$os")"
    printf '  "inspection_tool": %s,\n' "$(json_string "$inspection_tool")"
    printf '  "reported_profile": %s,\n' "$(json_string "$reported_profile")"
    printf '  "reported_backend": %s,\n' "$(json_string "$reported_backend")"
    printf '  "self_report": %s,\n' "$(json_string "$self_report")"
    printf '  "links_openssl": %s,\n' "$links_openssl"
    printf '  "status": %s,\n' "$(json_string "$status")"
    printf '  "dependencies": ['
    first=true
    while IFS= read -r dep; do
        [ -z "$dep" ] && continue
        if [ "$first" = true ]; then
            first=false
            printf '\n'
        else
            printf ',\n'
        fi
        printf '    %s' "$(json_string "$dep")"
    done <<<"$dep_names"
    [ "$first" = false ] && printf '\n  '
    printf '],\n'
    printf '  "violations": ['
    first=true
    for violation in "${violations[@]:-}"; do
        [ -z "$violation" ] && continue
        if [ "$first" = true ]; then
            first=false
            printf '\n'
        else
            printf ',\n'
        fi
        printf '    %s' "$(json_string "$violation")"
    done
    [ "$first" = false ] && printf '\n  '
    printf ']\n'
    printf '}\n'
}

json_string() {
    # Minimal JSON string escaping for the fields we emit (paths, lib names,
    # a version line): backslash, double-quote, and control-free ASCII.
    printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"
}

inventory="$(emit_inventory)"
if [ -n "$OUTPUT" ]; then
    printf '%s\n' "$inventory" >"$OUTPUT"
fi
printf '%s\n' "$inventory"

if [ "$status" = "fail" ]; then
    echo "binary audit failed for profile '$PROFILE':" >&2
    for violation in "${violations[@]}"; do
        echo "  - $violation" >&2
    done
    exit 1
fi

echo "binary audit passed for profile '$PROFILE' (backend: $reported_backend)" >&2
