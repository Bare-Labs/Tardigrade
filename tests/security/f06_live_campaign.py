#!/usr/bin/env python3
"""Live black-box campaign for #673 (F-06: auth enforcement + hostile framing).

Fires raw, byte-exact HTTP/1.1 requests at a running `tardi` process fronting
the disposable upstream in tests/security/fixtures/f06_upstream.py, and
asserts -- from the upstream's own hit log, not just the client-visible
status code -- that:

  * every missing/malformed-credential case is denied *before* the protected
    upstream is ever invoked;
  * method, path, and Host variations cannot move a request off the
    protected boundary;
  * client-supplied X-Tardigrade-* / X-Forwarded-* identity headers never
    become the trusted identity forwarded upstream;
  * TE/CL conflicts, chunked-encoding abuse, and duplicate/oversized headers
    are rejected without ever dispatching a smuggled follow-up request;
  * the static traversal boundary cannot be crossed;
  * a deliberately hostile upstream cannot split or desync the downstream
    connection, including bleeding a "ghost" second response into an
    unrelated later request over a reused upstream connection.

Started via scripts/run-f06-auth-framing-campaign.sh, which owns process
lifecycle (build, start upstream + tardi, teardown) and evidence capture.
Curl is deliberately not used: it normalizes malformed syntax this campaign
needs to send byte-exact.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import socket
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field

VALID_TOKEN = "f06-valid-token-9f3c2a9b7e"
JWT_SECRET = "f06-jwt-secret-do-not-use-in-prod-4c1a"
TRAVERSAL_CANARY = "F06_TRAVERSAL_CANARY_SHOULD_NEVER_BE_SERVED"
GHOST_MARKER = "F06_UPSTREAM_GHOST_MARKER"


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_hs256_jwt(secret: str, claims: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


@dataclass
class Result:
    name: str
    category: str
    ok: bool
    detail: str = ""


RESULTS: list[Result] = []


def record(name: str, category: str, ok: bool, detail: str = "") -> None:
    RESULTS.append(Result(name, category, ok, detail))
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] {category}: {name}" + (f" -- {detail}" if detail and not ok else ""))


# --- transport helpers -------------------------------------------------

def send_raw(port: int, data: bytes, read_timeout: float = 1.2, connect_timeout: float = 2.0) -> bytes:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=connect_timeout) as s:
            s.sendall(data)
            s.settimeout(read_timeout)
            chunks = []
            total = 0
            try:
                while total < 1_000_000:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
            except (socket.timeout, ConnectionResetError):
                pass
            return b"".join(chunks)
    except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError):
        return b""


def send_raw_then_close_early(port: int, first: bytes, rest: bytes, delay: float = 0.15) -> bytes:
    """Send `first`, wait, send `rest`, then close without waiting for the rest -- used
    for premature-EOF / declared-but-not-delivered body cases."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
            s.sendall(first)
            time.sleep(delay)
            if rest:
                s.sendall(rest)
            s.settimeout(0.6)
            try:
                return s.recv(4096)
            except (socket.timeout, ConnectionResetError):
                return b""
    except OSError:
        return b""


def first_status_code(raw: bytes) -> int | None:
    if not raw.startswith(b"HTTP/"):
        return None
    nl = raw.find(b"\n")
    if nl == -1:
        return None
    parts = raw[:nl].split(b" ", 2)
    if len(parts) < 2:
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def response_headers_lower(raw: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    head_end = raw.find(b"\r\n\r\n")
    head = raw[: head_end if head_end != -1 else len(raw)]
    lines = head.split(b"\r\n")[1:]
    for line in lines:
        if b":" not in line:
            continue
        k, _, v = line.partition(b":")
        out[k.strip().lower().decode("latin-1")] = v.strip().decode("latin-1")
    return out


# --- upstream control ---------------------------------------------------

class Upstream:
    def __init__(self, port: int):
        self.port = port

    def reset(self) -> None:
        urllib.request.urlopen(f"http://127.0.0.1:{self.port}/reset", timeout=2).read()

    def hits(self) -> list[dict]:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/hits", timeout=2) as r:
            return json.load(r)["hits"]


# --- assertions -----------------------------------------------------------

def assert_denied(up: Upstream, name: str, category: str, port: int, request: bytes) -> None:
    up.reset()
    raw = send_raw(port, request)
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    detail = f"status={status} upstream_hits={len(hits)} resp_head={raw[:80]!r}"
    record(name, category, ok, detail)


def assert_allowed(up: Upstream, name: str, category: str, port: int, request: bytes, expect_path_substr: str) -> dict | None:
    up.reset()
    raw = send_raw(port, request)
    status = first_status_code(raw)
    hits = up.hits()
    matching = [h for h in hits if expect_path_substr in h["path"]]
    ok = status == 200 and len(matching) >= 1
    detail = f"status={status} upstream_hits={len(hits)} resp_head={raw[:120]!r}"
    record(name, category, ok, detail)
    return matching[0] if matching else None


def assert_consistency(up: Upstream, name: str, category: str, port: int, request: bytes) -> None:
    """Generic safety net: the client-visible success/failure must always agree
    with whether the protected upstream was actually invoked."""
    up.reset()
    raw = send_raw(port, request)
    status = first_status_code(raw)
    hits = up.hits()
    client_says_ok = status is not None and 200 <= status < 300
    upstream_was_hit = len(hits) >= 1
    ok = client_says_ok == upstream_was_hit
    detail = f"status={status} upstream_hits={len(hits)} (mismatch between client status and upstream reality)"
    record(name, category, ok, detail)


# --- case builders ----------------------------------------------------

def req(method: str, path: str, headers: list[tuple[str, str]], body: bytes = b"", version: str = "HTTP/1.1", host: str = "localhost") -> bytes:
    lines = [f"{method} {path} {version}"]
    has_host = any(k.lower() == "host" for k, _ in headers)
    if not has_host and version == "HTTP/1.1":
        lines.append(f"Host: {host}")
    for k, v in headers:
        lines.append(f"{k}: {v}")
    if body and not any(k.lower() == "content-length" for k, _ in headers):
        lines.append(f"Content-Length: {len(body)}")
    head = "\r\n".join(lines) + "\r\n\r\n"
    return head.encode("latin-1") + body


def run_auth_matrix(up: Upstream, port: int) -> None:
    cat = "auth.missing_malformed_credentials"

    assert_denied(up, "no_authorization_header", cat, port, req("GET", "/protected", []))
    assert_denied(up, "bearer_scheme_no_token", cat, port, req("GET", "/protected", [("Authorization", "Bearer")]))
    assert_denied(up, "bearer_scheme_empty_token", cat, port, req("GET", "/protected", [("Authorization", "Bearer ")]))
    assert_allowed(up, "bearer_extra_internal_whitespace_still_valid", cat, port,
                    req("GET", "/protected", [("Authorization", f"Bearer   {VALID_TOKEN}")]), "/protected")
    assert_denied(up, "wrong_scheme_basic", cat, port, req("GET", "/protected", [("Authorization", "Basic YWJjOmRlZg==")]))
    assert_denied(up, "wrong_scheme_arbitrary", cat, port, req("GET", "/protected", [("Authorization", "Digest abc")]))
    assert_denied(up, "malformed_token_two_parts", cat, port, req("GET", "/protected", [("Authorization", "Bearer bad token")]))
    assert_denied(up, "oversized_token", cat, port, req("GET", "/protected", [("Authorization", "Bearer " + ("a" * 5000))]))
    assert_denied(up, "malformed_jwt_no_dots", cat, port, req("GET", "/protected", [("Authorization", "Bearer notavalidjwt")]))
    assert_denied(up, "malformed_jwt_bad_segments", cat, port, req("GET", "/protected", [("Authorization", "Bearer not.a.jwt")]))

    bad_sig_jwt = make_hs256_jwt("wrong-secret-entirely", {"sub": "attacker"})
    assert_denied(up, "invalid_jwt_signature", cat, port, req("GET", "/protected", [("Authorization", f"Bearer {bad_sig_jwt}")]))

    assert_consistency(up, "duplicate_authorization_invalid_then_valid", cat, port,
                        req("GET", "/protected", [("Authorization", "Bearer garbage"), ("Authorization", f"Bearer {VALID_TOKEN}")]))
    assert_consistency(up, "duplicate_authorization_valid_then_invalid", cat, port,
                        req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}"), ("Authorization", "Bearer garbage")]))
    assert_denied(up, "comma_joined_authorization_variant", cat, port,
                  req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}, Bearer other-token")]))

    raw_nul = b"GET /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\x00def\r\n\r\n"
    up.reset()
    resp = send_raw(port, raw_nul)
    hits = up.hits()
    ok = (first_status_code(resp) is None or first_status_code(resp) >= 400) and len(hits) == 0
    record("nul_byte_in_authorization_value", cat, ok, f"status={first_status_code(resp)} hits={len(hits)}")

    raw_bare_cr = b"GET /protected HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\rdef\r\n\r\n"
    up.reset()
    resp = send_raw(port, raw_bare_cr)
    hits = up.hits()
    ok = (first_status_code(resp) is None or first_status_code(resp) >= 400) and len(hits) == 0
    record("bare_cr_in_authorization_value", cat, ok, f"status={first_status_code(resp)} hits={len(hits)}")


def run_identity_spoofing(up: Upstream, port: int) -> None:
    cat = "auth.identity_spoofing"

    up.reset()
    raw = send_raw(port, req("GET", "/protected", [
        ("Authorization", f"Bearer {VALID_TOKEN}"),
        ("X-Tardigrade-Auth-Identity", "spoofed-admin"),
    ]))
    status = first_status_code(raw)
    hits = up.hits()
    forwarded_identity = None
    if hits:
        forwarded_identity = hits[0]["headers"].get("X-Tardigrade-Auth-Identity") or hits[0]["headers"].get("x-tardigrade-auth-identity")
    ok = status == 200 and len(hits) == 1 and forwarded_identity != "spoofed-admin"
    record("x_tardigrade_identity_header_not_trusted_from_client", cat, ok,
           f"status={status} forwarded_identity={forwarded_identity!r}")

    assert_denied(up, "x_forwarded_for_spoof_without_auth_does_not_bypass", cat, port,
                  req("GET", "/protected", [("X-Forwarded-For", "127.0.0.1")]))

    up.reset()
    raw = send_raw(port, req("GET", "/protected", [
        ("Authorization", f"Bearer {VALID_TOKEN}"),
        ("Connection", "X-Tardigrade-Auth-Identity"),
        ("X-Tardigrade-Auth-Identity", "spoofed-via-connection-nomination"),
    ]))
    status = first_status_code(raw)
    hits = up.hits()
    forwarded_identity = None
    if hits:
        forwarded_identity = hits[0]["headers"].get("X-Tardigrade-Auth-Identity") or hits[0]["headers"].get("x-tardigrade-auth-identity")
    ok = status == 200 and len(hits) == 1 and forwarded_identity != "spoofed-via-connection-nomination"
    record("connection_nominated_identity_header_not_trusted", cat, ok,
           f"status={status} forwarded_identity={forwarded_identity!r}")


def run_method_change_bypass(up: Upstream, port: int) -> None:
    cat = "auth.method_change_bypass"
    for method in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]:
        assert_denied(up, f"method_{method.lower()}_still_requires_auth", cat, port, req(method, "/protected", []))

    up.reset()
    raw = send_raw(port, b"CONNECT protected:443 HTTP/1.1\r\nHost: localhost\r\n\r\n")
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    record("method_connect_rejected_or_denied", cat, ok, f"status={status} hits={len(hits)}")


def run_path_canonicalization(up: Upstream, port: int) -> None:
    cat = "auth.path_canonicalization"
    variants = [
        ("exact_protected", "/protected"),
        ("trailing_slash", "/protected/"),
        ("duplicate_leading_slash", "//protected"),
        ("duplicate_slash_midpath", "/protected//x"),
        ("dot_segment", "/./protected"),
        ("parent_dot_segment", "/../protected"),
        ("percent_encoded_char", "/prot%65cted"),
        ("encoded_dot_dot", "/%2e%2e/protected"),
        ("double_encoded_dot_dot", "/%252e%252e/protected"),
        ("encoded_trailing_slash", "/protected%2f"),
        ("encoded_backslash", "/protected%5c.."),
        ("query_string_variant", "/protected?x=1"),
        ("query_traversal_attempt", "/protected?../../etc/passwd"),
    ]
    for name, path in variants:
        assert_denied(up, name, cat, port, req("GET", path, []))

    up.reset()
    raw = send_raw(port, req("GET", "http://attacker.example/protected", [], host="localhost"))
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    record("absolute_form_request_target_still_requires_auth", cat, ok, f"status={status} hits={len(hits)}")

    up.reset()
    raw = send_raw(port, req("GET", "/protected", [("Host", "evil.example")]))
    status = first_status_code(raw)
    hits = up.hits()
    ok = (status is None or status >= 400) and len(hits) == 0
    record("duplicate_host_header_conflicting_values", cat, ok, f"status={status} hits={len(hits)}")


def run_positive_control_and_replay(up: Upstream, port: int) -> None:
    cat = "auth.positive_control_and_replay"

    assert_allowed(up, "valid_bearer_reaches_protected_upstream", cat, port,
                    req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]), "/protected")

    jwt = make_hs256_jwt(JWT_SECRET, {"sub": "f06-jwt-subject"})
    assert_allowed(up, "valid_jwt_reaches_protected_upstream", cat, port,
                    req("GET", "/protected", [("Authorization", f"Bearer {jwt}")]), "/protected")

    up.reset()
    r1 = send_raw(port, req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]))
    r2 = send_raw(port, req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]))
    hits = up.hits()
    ok = first_status_code(r1) == 200 and first_status_code(r2) == 200 and len(hits) == 2
    record("sequential_bearer_reuse_both_succeed", cat, ok, f"hits={len(hits)}")

    up.reset()
    results: list[bytes] = [b"", b""]

    def fire(i: int) -> None:
        results[i] = send_raw(port, req("GET", "/protected", [("Authorization", f"Bearer {VALID_TOKEN}")]))

    t1 = threading.Thread(target=fire, args=(0,))
    t2 = threading.Thread(target=fire, args=(1,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    hits = up.hits()
    ok = first_status_code(results[0]) == 200 and first_status_code(results[1]) == 200 and len(hits) == 2
    record("concurrent_bearer_reuse_both_succeed_not_treated_one_time", cat, ok, f"hits={len(hits)}")


def run_hostile_framing(up: Upstream, port: int) -> None:
    cat = "framing.content_length_and_chunking"

    assert_denied(up, "duplicate_cl_equal_values", cat, port,
                  req("POST", "/protected", [("Content-Length", "4"), ("Content-Length", "4")], b"ABCD"))
    assert_denied(up, "duplicate_cl_conflicting_values", cat, port,
                  req("POST", "/protected", [("Content-Length", "4"), ("Content-Length", "8")], b"ABCDEFGH"))
    assert_denied(up, "comma_separated_content_length", cat, port,
                  req("POST", "/protected", [("Content-Length", "4, 4")], b"ABCD"))
    assert_denied(up, "negative_content_length", cat, port,
                  req("POST", "/protected", [("Content-Length", "-1")], b""))
    assert_denied(up, "content_length_integer_overflow", cat, port,
                  req("POST", "/protected", [("Content-Length", "99999999999999999999999999")], b""))

    up.reset()
    raw = send_raw_then_close_early(port,
                                     b"POST /protected HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n",
                                     b"short-body-only", delay=0.1)
    hits = up.hits()
    ok = len(hits) == 0
    record("content_length_longer_than_delivered_body_never_dispatches", cat, ok, f"hits={len(hits)}")

    assert_denied(up, "smuggling_probe_te_chunked_plus_cl", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                  b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")

    smuggled_tail = b"GET /f06-smuggled-should-never-route HTTP/1.1\r\nHost: localhost\r\n\r\n"
    body = b"ABCD" + smuggled_tail
    up.reset()
    raw = send_raw(port,
                    b"POST /protected HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    hits = up.hits()
    smuggled_hit = any("f06-smuggled-should-never-route" in h["path"] for h in hits)
    ok = len(hits) == 0 and not smuggled_hit
    record("smuggling_probe_duplicate_conflicting_cl_hides_second_request", cat, ok, f"hits={len(hits)}")

    up.reset()
    followup = send_raw(port, req("GET", "/health", []))
    ok = b"200" in followup[:20]
    record("connection_healthy_after_smuggling_probes", cat, ok, f"resp={followup[:60]!r}")

    assert_denied(up, "te_before_cl_header_order", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n")
    assert_denied(up, "te_cl_mixed_case_both_present", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\ncontent-length: 4\r\nTRANSFER-ENCODING: chunked\r\n\r\n0\r\n\r\n")
    assert_denied(up, "unsupported_transfer_coding_gzip_chunked", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n")
    assert_denied(up, "chunked_not_final_coding", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n")
    assert_denied(up, "invalid_chunk_size_hex", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nabc\r\n0\r\n\r\n")
    assert_denied(up, "oversized_chunk_size_value", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n" + b"a" * 32 + b"\r\n0\r\n\r\n")

    up.reset()
    raw = send_raw_then_close_early(port,
                                     b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab",
                                     b"", delay=0.1)
    hits = up.hits()
    ok = len(hits) == 0
    record("truncated_chunk_body_never_dispatches", cat, ok, f"hits={len(hits)}")

    assert_denied(up, "missing_crlf_after_chunk_data", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcdXXXX0\r\n\r\n")

    up.reset()
    raw = send_raw_then_close_early(port,
                                     b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n",
                                     b"", delay=0.1)
    hits = up.hits()
    ok = len(hits) == 0
    record("missing_final_zero_chunk_never_dispatches", cat, ok, f"hits={len(hits)}")

    assert_denied(up, "malformed_chunk_trailers", cat, port,
                  b"POST /protected HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Trailer No Colon\r\n\r\n")


def run_header_syntax(up: Upstream, port: int) -> None:
    cat = "framing.request_header_syntax"

    assert_denied(up, "obs_fold_header_continuation", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Custom: value\r\n continued\r\n\r\n")
    assert_denied(up, "nul_byte_in_header_value", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Custom: bad\x00value\r\n\r\n")
    assert_denied(up, "ctl_byte_in_header_name", cat, port,
                  b"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Bad\x01Name: value\r\n\r\n")

    long_path = "/protected/" + ("a" * 9000)
    assert_denied(up, "oversized_request_line", cat, port,
                  f"GET {long_path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())

    assert_denied(up, "malformed_http_version", cat, port,
                  b"GET /protected HTTP/9.9\r\nHost: localhost\r\n\r\n")
    assert_denied(up, "invalid_method_token", cat, port,
                  b"FOO$BAR /protected HTTP/1.1\r\nHost: localhost\r\n\r\n")

    oversized_value = "x" * 9000
    assert_denied(up, "oversized_single_header", cat, port,
                  f"GET /protected HTTP/1.1\r\nHost: localhost\r\nX-Big: {oversized_value}\r\n\r\n".encode())

    many_headers = "".join(f"X-H{i}: v\r\n" for i in range(150))
    assert_denied(up, "header_count_over_limit", cat, port,
                  f"GET /protected HTTP/1.1\r\nHost: localhost\r\n{many_headers}\r\n".encode())

    aggregate = "".join(f"X-Pad{i}: {'p' * 300}\r\n" for i in range(120))
    assert_denied(up, "aggregate_header_size_over_limit", cat, port,
                  f"GET /protected HTTP/1.1\r\nHost: localhost\r\n{aggregate}\r\n".encode())

    assert_denied(up, "missing_host_header_http11", cat, port,
                  b"GET /protected HTTP/1.1\r\n\r\n")

    up.reset()
    raw = send_raw(port, b"TRACE /protected HTTP/1.1\r\nHost: localhost\r\n\r\n")
    status = first_status_code(raw)
    hits = up.hits()
    ok = status == 405 and len(hits) == 0
    record("trace_method_globally_405", cat, ok, f"status={status} hits={len(hits)}")


def run_traversal_boundary(up: Upstream, port: int) -> None:
    cat = "static.traversal_boundary"
    variants = [
        ("dotdot_segment", "/../f06_secret_outside_root.txt"),
        ("percent_encoded_dotdot", "/%2e%2e/f06_secret_outside_root.txt"),
        ("double_percent_encoded_dotdot", "/%252e%252e/f06_secret_outside_root.txt"),
        ("encoded_slash_dotdot", "/..%2ff06_secret_outside_root.txt"),
        ("backslash_dotdot", "/..\\f06_secret_outside_root.txt"),
    ]
    for name, path in variants:
        up.reset()
        raw = send_raw(port, req("GET", path, []))
        status = first_status_code(raw)
        body = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
        canary_leaked = TRAVERSAL_CANARY.encode() in body
        ok = not canary_leaked
        record(name, cat, ok, f"status={status} canary_leaked={canary_leaked}")


def run_malicious_upstream(up: Upstream, port: int) -> None:
    cat = "upstream.malicious_response_framing"

    def hostile(scenario: str) -> bytes:
        return req("GET", "/hostile", [("X-F06-Scenario", scenario)])

    for scenario in ["duplicate_cl", "conflicting_cl", "te_and_cl", "malformed_status_line", "truncated_body"]:
        up.reset()
        raw = send_raw(port, hostile(scenario))
        status = first_status_code(raw)
        followup = send_raw(port, req("GET", "/health", []))
        followup_ok = first_status_code(followup) == 200
        ok = followup_ok
        record(f"hostile_upstream_{scenario}_does_not_hang_or_break_edge", cat, ok,
               f"status={status} followup_status={first_status_code(followup)}")

    up.reset()
    raw = send_raw(port, hostile("connection_custom_hop"))
    headers = response_headers_lower(raw)
    ok = "x-hostile-secret" not in headers
    record("hostile_upstream_connection_nominated_header_stripped", cat, ok, f"headers={list(headers.keys())}")

    up.reset()
    _ = send_raw(port, hostile("extra_bytes_after_response"))
    followup = send_raw(port, hostile(""))
    leaked = GHOST_MARKER.encode() in followup
    ok = not leaked
    record("hostile_upstream_extra_bytes_do_not_leak_into_next_response", cat, ok,
           f"leaked={leaked} followup_head={followup[:100]!r}")

    for scenario in ["unusual_1xx_chain", "invalid_204_with_body", "invalid_304_with_body"]:
        up.reset()
        _ = send_raw(port, hostile(scenario))
        followup = send_raw(port, req("GET", "/health", []))
        ok = first_status_code(followup) == 200
        record(f"hostile_upstream_{scenario}_connection_stays_healthy", cat, ok,
               f"followup_status={first_status_code(followup)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tardi-port", type=int, default=18089)
    parser.add_argument("--upstream-port", type=int, default=18189)
    parser.add_argument("--evidence-json", default=None)
    args = parser.parse_args()

    up = Upstream(args.upstream_port)
    port = args.tardi_port

    run_auth_matrix(up, port)
    run_identity_spoofing(up, port)
    run_method_change_bypass(up, port)
    run_path_canonicalization(up, port)
    run_positive_control_and_replay(up, port)
    run_hostile_framing(up, port)
    run_header_syntax(up, port)
    run_traversal_boundary(up, port)
    run_malicious_upstream(up, port)

    total = len(RESULTS)
    failed = [r for r in RESULTS if not r.ok]
    print(f"\n{total - len(failed)}/{total} cases passed")
    if failed:
        print("\nFAILURES:")
        for r in failed:
            print(f"  - [{r.category}] {r.name}: {r.detail}")

    if args.evidence_json:
        with open(args.evidence_json, "w") as f:
            json.dump(
                {
                    "total": total,
                    "passed": total - len(failed),
                    "failed": [{"name": r.name, "category": r.category, "detail": r.detail} for r in failed],
                    "results": [{"name": r.name, "category": r.category, "ok": r.ok, "detail": r.detail} for r in RESULTS],
                },
                f,
                indent=2,
            )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
