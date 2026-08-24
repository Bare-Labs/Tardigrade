#!/usr/bin/env bash
# Production dependency boundary audit (#379, #634, #649, #651).
#
# Enforces the project-wide rule before anything is compiled:
#
#   Production `tardi` implementation inputs may use Tardigrade Zig code,
#   Zig stdlib, reviewed pure-Zig packages, and narrow OS/kernel/platform ABI
#   substrate. Foreign-language product implementations are allowed only in
#   explicit test/interop/differential/fuzz/benchmark scopes.
#
# Production scope audited here:
#   - src/**/*.zig production source (comments/prose ignored);
#   - build.zig and its imported build helpers plus build.zig.zon;
#   - .github workflows, packaging metadata, package builders, Dockerfiles,
#     and non-interop scripts that can affect shipped artifacts.
#
# Explicit non-production exemptions:
#   - tests/ and src/**/testdata fixture generators;
#   - scripts/interop/ external peer tooling;
#   - benchmark competitors and fuzz/differential/oracle tools when they are
#     clearly wired outside the `tardi` executable graph.
#
# Usage:
#   scripts/audit-dependencies.sh [--root PATH]
#   scripts/audit-dependencies.sh --self-test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SELF_TEST=false

while [ "$#" -gt 0 ]; do
    case "$1" in
    --root)
        REPO_ROOT="$(cd "$2" && pwd)"
        shift 2
        ;;
    --self-test)
        SELF_TEST=true
        shift
        ;;
    -h | --help)
        sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    *)
        echo "unknown argument: $1" >&2
        exit 2
        ;;
    esac
done

failures=0
SELF_TEST_TMP=""

fail() {
    echo "AUDIT FAIL: $1" >&2
    failures=$((failures + 1))
}

strip_comments() {
    awk -v style="$2" '
    BEGIN { dq = sprintf("%c", 34); sq = sprintf("%c", 39) }
    {
        line = $0
        if (style == "zig") {
            tmp = line
            sub(/^[ \t]+/, "", tmp)
            if (substr(tmp, 1, 2) == "\\\\") { print line; next }
        }
        out = ""; inq = ""; n = length(line); i = 1
        while (i <= n) {
            ch = substr(line, i, 1)
            if (inq != "") {
                out = out ch
                if (ch == "\\") { i++; if (i <= n) out = out substr(line, i, 1); i++; continue }
                if (ch == inq) inq = ""
                i++; continue
            }
            if (ch == dq || ch == sq) { inq = ch; out = out ch; i++; continue }
            if (style == "zig" && ch == "/" && substr(line, i + 1, 1) == "/") break
            if (style == "hash" && ch == "#") {
                prev = (i == 1) ? " " : substr(line, i - 1, 1)
                if (prev == " " || prev == "\t") break
            }
            out = out ch; i++
        }
        print out
    }' "$1"
}

comment_style_for() {
    case "$1" in
    *.zig | *.zon) echo zig ;;
    *.sh | *.yml | *.yaml | *.toml | *Dockerfile* | *.spec | *.control | *.service | *.plist | *.rb) echo hash ;;
    *) echo none ;;
    esac
}

stripped() {
    local style
    style="$(comment_style_for "$1")"
    if [ "$style" = none ]; then
        cat "$1"
    else
        strip_comments "$1" "$style"
    fi
}

relpath() {
    local path="$1"
    case "$path" in
    "$REPO_ROOT"/*) printf '%s\n' "${path#"$REPO_ROOT"/}" ;;
    *) printf '%s\n' "$path" ;;
    esac
}

resolve_build_sources() {
    local -a queue=("build.zig")
    local -A seen=()
    local f dir imp target
    while [ "${#queue[@]}" -gt 0 ]; do
        f="${queue[0]}"
        queue=("${queue[@]:1}")
        [ -n "${seen[$f]:-}" ] && continue
        seen[$f]=1
        [ -f "$REPO_ROOT/$f" ] || continue
        printf '%s\n' "$f"
        dir="$(dirname "$f")"
        while IFS= read -r imp; do
            [ -z "$imp" ] && continue
            if target="$(
                cd "$REPO_ROOT/$dir" &&
                    cd "$(dirname "$imp")" 2>/dev/null &&
                    pwd -P
            )"; then
                :
            else
                target=""
            fi
            [ -n "$target" ] || continue
            target="$(relpath "$target/$(basename "$imp")")"
            case "$target" in
            ../* | /*) continue ;;
            esac
            queue+=("$target")
        done < <(grep -oE '@import\("[^"]+\.zig"\)' "$REPO_ROOT/$f" 2>/dev/null | sed -E 's/.*@import\("([^"]+)"\).*/\1/')
    done
}

is_nonproduction_file() {
    case "$1" in
    tests/* | scripts/interop/* | benchmarks/* | src/*/testdata/*) return 0 ;;
    scripts/test-deb-package.sh | scripts/test-rpm-package.sh | scripts/test-homebrew-formula.sh | scripts/test-homebrew-release-formula.sh | scripts/test-homebrew-tap-sync.sh | scripts/test-install.sh | scripts/test-docker-image.sh | scripts/test-launchd-service.sh) return 0 ;;
    *) return 1 ;;
    esac
}

forbidden_dependency_pattern() {
    printf '%s\n' 'openssl|libssl|libcrypto|ngtcp2|nghttp3|quiche|boringssl|mbedtls|wolfssl|gnutls|libressl|rustls|s2n|botan|brotli|libbrotli|libbrotlienc'
}

logical_zig_statements() {
    awk '
    {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line == "") next
        stmt = stmt " " line
        if (line ~ /;[ \t]*$/ || line ~ /\{[ \t]*$/ || line ~ /\}[ \t]*$/) {
            print stmt
            stmt = ""
        }
    }
    END { if (stmt != "") print stmt }
    ' "$1"
}

logical_shell_statements() {
    awk '
    {
        line = $0
        sub(/^[ \t]+/, "", line)
        if (line == "") next
        if (line ~ /\\[ \t]*$/) {
            sub(/\\[ \t]*$/, "", line)
            stmt = stmt " " line
            next
        }
        stmt = stmt " " line
        print stmt
        stmt = ""
    }
    END { if (stmt != "") print stmt }
    ' "$1"
}

resolve_build_string() {
    local file="$1" token="$2"
    stripped "$file" | sed -nE "s/^[[:space:]]*(const|var)[[:space:]]+${token}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\\2/p" | tail -n 1
}

is_allowed_nonproduction_build_statement() {
    local stmt="$1"
    case "$stmt" in
    *evp_oracle* | *crypto_openssl_diff* | *pki_openssl_diff* | *interop* | *differential* | *fuzz* | *benchmark*) return 0 ;;
    *'tests/'*) return 0 ;;
    *) return 1 ;;
    esac
}

allowed_c_header() {
    case "$1" in
    arpa/inet.h | dirent.h | errno.h | fcntl.h | grp.h | limits.h | netdb.h | netinet/in.h | poll.h | pthread.h | pwd.h | regex.h | signal.h | stdint.h | stdlib.h | string.h | sys/epoll.h | sys/event.h | sys/ioctl.h | sys/mman.h | sys/resource.h | sys/socket.h | sys/stat.h | sys/time.h | sys/types.h | sys/uio.h | sys/un.h | time.h | unistd.h) return 0 ;;
    *) return 1 ;;
    esac
}

allowed_system_library() {
    case "$1" in
    c | System | pthread | m | dl | rt | resolv | regex | util | socket | nsl) return 0 ;;
    *) return 1 ;;
    esac
}

scan_source_ffi() {
    [ -d "$REPO_ROOT/src" ] || return 0
    local zigfile rel import_lines headers include_line include_header
    while IFS= read -r zigfile; do
        rel="$(relpath "$zigfile")"
        is_nonproduction_file "$rel" && continue
        import_lines="$(stripped "$zigfile" | grep -nE '@cImport[[:space:]]*\(' || true)"
        [ -z "$import_lines" ] && continue
        headers="$(stripped "$zigfile" | grep -nE '@cInclude\("[^"]+"\)' || true)"
        if [ -z "$headers" ]; then
            while IFS= read -r include_line; do
                [ -z "$include_line" ] && continue
                fail "production @cImport without reviewable @cInclude header list in $rel:$include_line"
            done <<<"$import_lines"
            continue
        fi
        while IFS= read -r include_line; do
            [ -z "$include_line" ] && continue
            include_header="$(printf '%s\n' "$include_line" | sed -nE 's/^[0-9]+:.*@cInclude\("([^"]+)"\).*/\1/p')"
            [ -n "$include_header" ] || continue
            if ! allowed_c_header "$include_header"; then
                fail "foreign/product C header imported from production source $rel:$include_line"
            fi
        done <<<"$headers"
    done < <(find "$REPO_ROOT/src" -name '*.zig' -type f | sort)
}

scan_runtime_loading() {
    [ -d "$REPO_ROOT/src" ] || return 0
    local zigfile rel matches line
    while IFS= read -r zigfile; do
        rel="$(relpath "$zigfile")"
        is_nonproduction_file "$rel" && continue
        if matches="$(stripped "$zigfile" | grep -niE 'DynLib|DynamicLibrary|dlopen|LoadLibrary[A-Za-z]*' 2>/dev/null)"; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                fail "production runtime dynamic loading boundary in $rel: $line"
            done <<<"$matches"
        fi
    done < <(find "$REPO_ROOT/src" -name '*.zig' -type f | sort)
}

scan_build_graph() {
    local file rel stmt lib token srcfile
    while IFS= read -r file; do
        [ -f "$REPO_ROOT/$file" ] || continue
        while IFS= read -r stmt; do
            case "$stmt" in
            *linkSystemLibrary*'('*)
                case "$stmt" in
                " fn linkSystemLibrary("* | *"compile.root_module.linkSystemLibrary(name"*) continue ;;
                esac
                if is_allowed_nonproduction_build_statement "$stmt"; then
                    continue
                fi
                lib="$(printf '%s\n' "$stmt" | sed -nE 's/.*linkSystemLibrary[^(]*\([^"]*"([^"]+)".*/\1/p')"
                if [ -z "$lib" ]; then
                    token="$(printf '%s\n' "$stmt" | sed -nE 's/.*linkSystemLibrary[^(]*\([[:space:]]*([A-Za-z_][A-Za-z0-9_]*).*/\1/p')"
                    if [ -n "$token" ] && [ "$token" != "name" ]; then
                        lib="$(resolve_build_string "$REPO_ROOT/$file" "$token")"
                    fi
                fi
                if [ -z "$lib" ]; then
                    fail "production system library link uses unresolved library expression in $file: $stmt"
                elif ! allowed_system_library "$lib"; then
                    fail "production foreign system library link in $file: $stmt"
                fi
                ;;
            *addCSourceFiles* | *addCSourceFile* | *addObjectFile*)
                if ! is_allowed_nonproduction_build_statement "$stmt"; then
                    fail "production vendored foreign source/object compilation in $file: $stmt"
                fi
                ;;
            esac
        done < <(logical_zig_statements <(stripped "$REPO_ROOT/$file"))
    done < <(resolve_build_sources)

    if [ -f "$REPO_ROOT/build.zig.zon" ]; then
        if stripped "$REPO_ROOT/build.zig.zon" | grep -niE '\.(url|path)[[:space:]]*=' | grep -qEi "$(forbidden_dependency_pattern)|\.c(pp)?($|[?#\"])"; then
            fail "production manifest dependency appears to introduce a foreign runtime implementation in build.zig.zon"
        fi
    fi

    while IFS= read -r srcfile; do
        rel="$(relpath "$srcfile")"
        is_nonproduction_file "$rel" && continue
        case "$rel" in
        *.c | *.cc | *.cpp | *.cxx | *.m | *.mm) fail "vendored foreign implementation source in production scope: $rel" ;;
        esac
    done < <(find "$REPO_ROOT/src" -type f | sort 2>/dev/null || true)
}

scan_metadata() {
    local -a scan_files=()
    local f rel matches line pattern
    pattern="$(forbidden_dependency_pattern)"
    [ -f "$REPO_ROOT/.github/workflows/release.yml" ] && scan_files+=("$REPO_ROOT/.github/workflows/release.yml")
    while IFS= read -r f; do scan_files+=("$f"); done < <(find "$REPO_ROOT/packaging" -type f 2>/dev/null | sort)
    while IFS= read -r f; do
        rel="$(relpath "$f")"
        case "$rel" in
        scripts/interop/* | scripts/audit-dependencies.sh | scripts/audit-release-binary.sh) ;;
        *) scan_files+=("$f") ;;
        esac
    done < <(find "$REPO_ROOT/scripts" -type f 2>/dev/null | sort)
    while IFS= read -r f; do scan_files+=("$f"); done < <(find "$REPO_ROOT" -path "$REPO_ROOT/.zig-cache" -prune -o -path "$REPO_ROOT/zig-out" -prune -o -name 'Dockerfile*' -type f -print | sort)

    for f in "${scan_files[@]}"; do
        [ -f "$f" ] || continue
        rel="$(relpath "$f")"
        is_nonproduction_file "$rel" && continue
        case "$rel" in
        *.md) continue ;;
        esac
        if matches="$(logical_shell_statements <(stripped "$f") | grep -niE "(^|[[:space:][:punct:]])(apt(-get)? install|apk add|brew install|depends_on|Depends:|Requires:|RUN .*install|cargo|go get|pip install).*($pattern)" 2>/dev/null)"; then
            while IFS= read -r line; do
                [ -z "$line" ] && continue
                fail "production package/container metadata introduces foreign implementation dependency in $rel: $line"
            done <<<"$matches"
        fi
    done
}

run_audit() {
    cd "$REPO_ROOT"
    failures=0
    scan_source_ffi
    scan_runtime_loading
    scan_build_graph
    scan_metadata
    if [ "$failures" -gt 0 ]; then
        echo "dependency audit failed with $failures violation(s)" >&2
        return 1
    fi
    echo "dependency audit passed: production graph is Zig/native-only with only reviewed OS/platform ABI boundaries"
}

make_fixture_repo() {
    local root="$1" kind="$2"
    mkdir -p "$root/src" "$root/tests" "$root/scripts/interop" "$root/packaging" "$root/.github/workflows"
    cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    _ = b;
}
EOF
    printf '.{}\n' >"$root/build.zig.zon"
    printf 'pub fn main() void {}\n' >"$root/src/main.zig"
    case "$kind" in
    fail-cimport)
        cat >"$root/src/main.zig" <<'EOF'
const c = @cImport({
    @cInclude("wolfssl/options.h");
});
pub fn main() void { _ = c; }
EOF
        ;;
    fail-link)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.linkSystemLibrary("foreignssl");
}
EOF
        ;;
    fail-link-multiline)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.root_module.linkSystemLibrary(
        "foreignssl",
        .{},
    );
}
EOF
        ;;
    fail-link-indirect)
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const product_lib = "foreignssl";
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.root_module.linkSystemLibrary(product_lib, .{});
}
EOF
        ;;
    fail-csource)
        printf 'int foreign_impl(void) { return 1; }\n' >"$root/src/foreign_impl.c"
        ;;
    fail-build-csource-multiline)
        printf 'int foreign_impl(void) { return 1; }\n' >"$root/foreign_impl.c"
        cat >"$root/build.zig" <<'EOF'
const std = @import("std");
pub fn build(b: *std.Build) void {
    const exe = b.addExecutable(.{ .name = "tardi", .root_source_file = b.path("src/main.zig") });
    exe.addCSourceFile(.{
        .file = b.path("foreign_impl.c"),
    });
}
EOF
        ;;
    fail-package)
        printf 'Package: tardigrade\nDepends: libssl3\n' >"$root/packaging/control"
        ;;
    fail-docker-multiline)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates libssl3
EOF
        ;;
    fail-test-helper-reached)
        cat >"$root/Dockerfile" <<'EOF'
FROM debian:bookworm-slim
RUN ./scripts/test-install-runtime.sh
EOF
        cat >"$root/scripts/test-install-runtime.sh" <<'EOF'
#!/usr/bin/env bash
apt-get update \
    && apt-get install -y --no-install-recommends \
        libssl3
EOF
        chmod +x "$root/scripts/test-install-runtime.sh"
        ;;
    fail-dlopen)
        printf 'const std = @import("std");\npub fn main() void { _ = std.DynLib.open("libssl.so"); }\n' >"$root/src/main.zig"
        ;;
    pass-platform)
        cat >"$root/src/main.zig" <<'EOF'
const c = @cImport({
    @cInclude("unistd.h");
});
pub fn main() void { _ = c; }
EOF
        ;;
    pass-test-peer)
        printf 'openssl version\n' >"$root/scripts/interop/run.sh"
        chmod +x "$root/scripts/interop/run.sh"
        printf 'Package docs mention libssl in prose only.\n' >"$root/packaging/README.md"
        ;;
    pass-pure-zig)
        mkdir -p "$root/vendor/pure_zig"
        cat >"$root/build.zig.zon" <<'EOF'
.{
    .dependencies = .{
        .pure_zig = .{ .path = "vendor/pure_zig" },
    },
}
EOF
        ;;
    esac
}

run_self_test() {
    local tmp kind rc
    tmp="$(mktemp -d)"
    SELF_TEST_TMP="$tmp"
    trap 'rm -rf "$SELF_TEST_TMP"' EXIT
    for kind in fail-cimport fail-link fail-link-multiline fail-link-indirect fail-csource fail-build-csource-multiline fail-package fail-docker-multiline fail-test-helper-reached fail-dlopen; do
        make_fixture_repo "$tmp/$kind" "$kind"
        if "$0" --root "$tmp/$kind" >/dev/null 2>&1; then
            echo "self-test failed: $kind unexpectedly passed" >&2
            return 1
        fi
    done
    for kind in pass-platform pass-test-peer pass-pure-zig; do
        make_fixture_repo "$tmp/$kind" "$kind"
        if ! "$0" --root "$tmp/$kind" >/dev/null; then
            rc=$?
            echo "self-test failed: $kind unexpectedly failed with $rc" >&2
            "$0" --root "$tmp/$kind" || true
            return 1
        fi
    done
    echo "dependency audit self-test passed"
}

if [ "$SELF_TEST" = true ]; then
    run_self_test
else
    run_audit
fi
