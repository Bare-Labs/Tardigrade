#!/usr/bin/env python3
"""Disposable upstream fixture for the #673 live F-06 campaign.

Records every request it receives (method, path, a subset of headers, and
body) so the probe engine in tests/security/f06_live_campaign.py can assert
that unauthorized or malformed requests never reach the protected upstream,
and that no smuggled follow-up request is ever dispatched.

Two route families:

  * `/protected*`, `/health`, and anything else -> normal responses that
    embed a unique UPSTREAM_REACHED marker plus a running hit counter, so the
    probe engine can distinguish "never hit" from "hit N times".
  * `/hostile*` -> deliberately malformed raw HTTP/1.1 response bytes,
    selected by the inbound `X-F06-Scenario` header, used for the malicious
    upstream response matrix. These bypass send_response()/send_header()
    entirely and write raw bytes so genuinely invalid framing can be sent.

Not a general-purpose test server; do not reuse outside this campaign.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_lock = threading.Lock()
_hits: list[dict] = []


def _record(method: str, path: str, headers: dict, body: bytes) -> int:
    with _lock:
        _hits.append(
            {
                "method": method,
                "path": path,
                "headers": headers,
                "body_len": len(body),
                "body_preview": body[:200].decode("latin-1"),
            }
        )
        return len(_hits)


HOSTILE_SCENARIOS = {
    # Two Content-Length fields with the SAME value -- still ambiguous per
    # RFC 7230 (HTTP does not grant an exception for matching duplicates),
    # kept distinct from the differing-values case below (#673 review).
    "duplicate_cl_equal": (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n"
        b"ok"
    ),
    "conflicting_cl": (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Content-Length: 99\r\n"
        b"\r\n"
        b"ok"
    ),
    # Reverse field order from "conflicting_cl" (#673 review): a
    # last-one-wins parser would pick the SMALLER value here, leaving
    # "extra" bytes past what it thinks is the response boundary --
    # exactly the ordering that would have masked the bug if only the
    # small-first case were ever tested.
    "reverse_conflicting_cl": (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 99\r\n"
        b"Content-Length: 2\r\n"
        b"\r\n"
        b"ok"
    ),
    # A bare LF (not part of a \r\n pair) right after the status line, with
    # a real Connection-nominated hostile header immediately following
    # (#673 review). Composes two explicit #673 malicious-upstream cases:
    # malformed status line and Connection-nominated hop-by-hop header.
    "bare_lf_hides_connection_nomination": (
        b"HTTP/1.1 200 OK\nConnection: X-Hostile-Secret\r\n"
        b"X-Hostile-Secret: must-not-leak\r\n"
        b"Content-Length: 2\r\n\r\nok"
    ),
    "te_and_cl": (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"2\r\nok\r\n0\r\n\r\n"
    ),
    "malformed_status_line": b"HTTP/1.1 20O WEIRD\r\nContent-Length: 0\r\n\r\n",
    # Genuine malformed-byte injection attempt: a NUL and a bare CR (not
    # part of a \r\n pair) embedded inside an otherwise well-formed header
    # value, probing whether Tardigrade sanitizes/rejects control characters
    # in upstream header values before re-emitting them to the client the
    # way it already validates client-supplied header values (#673 review --
    # the prior version of this scenario used two syntactically valid
    # headers and tested nothing malformed).
    "ctl_and_bare_cr_in_header_value": (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"X-Hostile: val\x00ue\rwith-ctl-and-bare-cr\r\n"
        b"Content-Length: 2\r\n\r\nok"
    ),
    "connection_custom_hop": (
        b"HTTP/1.1 200 OK\r\n"
        b"Connection: X-Hostile-Secret\r\n"
        b"X-Hostile-Secret: should-not-reach-client\r\n"
        b"Content-Length: 2\r\n\r\nok"
    ),
    # RFC 7230 §6.1 hop-by-hop headers a hostile upstream might try to ride
    # through verbatim; each must be stripped before the client sees it.
    "proxy_connection_header": (
        b"HTTP/1.1 200 OK\r\nProxy-Connection: keep-alive\r\nContent-Length: 2\r\n\r\nok"
    ),
    "te_header": b"HTTP/1.1 200 OK\r\nTE: trailers\r\nContent-Length: 2\r\n\r\nok",
    "trailer_header": b"HTTP/1.1 200 OK\r\nTrailer: X-Checksum\r\nContent-Length: 2\r\n\r\nok",
    "upgrade_header": (
        b"HTTP/1.1 200 OK\r\nUpgrade: websocket\r\nContent-Length: 2\r\n\r\nok"
    ),
    "server_header": b"HTTP/1.1 200 OK\r\nServer: hostile-upstream/1.0\r\nContent-Length: 2\r\n\r\nok",
    "x_powered_by_header": (
        b"HTTP/1.1 200 OK\r\nX-Powered-By: hostile-framework\r\nContent-Length: 2\r\n\r\nok"
    ),
    "truncated_body": b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
    "extra_bytes_after_response": (
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nF06_UPSTREAM_GHOST_MARKER"
    ),
    "unusual_1xx_chain": (
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"
        b"HTTP/1.1 103 Early Hints\r\nLink: </style2.css>\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    ),
    "invalid_204_with_body": b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nnope!",
    "invalid_304_with_body": b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\nnope!",
}

# #673 review: a hostile upstream can send just a bodiless response's header
# block, flush, wait until Tardigrade decides the connection is idle/reusable,
# and only then send an illegal body or a full ghost response -- bytes that
# would poison a pooled upstream connection for whatever unrelated request
# checks it out next. This scenario is handled specially (not via
# HOSTILE_SCENARIOS) because it needs a real sleep between two separate
# writes, which a single static byte string cannot express.
DELAYED_GHOST_SCENARIO = "delayed_ghost_after_bodiless"
DELAYED_GHOST_DELAY_SECONDS = 0.35
DELAYED_GHOST_HEAD = b"HTTP/1.1 204 No Content\r\nConnection: keep-alive\r\n\r\n"
DELAYED_GHOST_TAIL = b"HTTP/1.1 200 OK\r\nContent-Length: 25\r\n\r\nF06_UPSTREAM_GHOST_MARKER"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self) -> None:
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def do_PUT(self) -> None:
        self._handle()

    def do_PATCH(self) -> None:
        self._handle()

    def do_DELETE(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle(send_body=False)

    def do_OPTIONS(self) -> None:
        self._handle()

    def _handle(self, *, send_body: bool = True) -> None:
        body = self._read_body()

        if self.path == "/reset":
            with _lock:
                _hits.clear()
            self._write_json(200, {"ok": True})
            return

        if self.path == "/hits":
            with _lock:
                snapshot = list(_hits)
            self._write_json(200, {"count": len(snapshot), "hits": snapshot})
            return

        if self.path.startswith("/hostile"):
            scenario = self.headers.get("X-F06-Scenario", "")
            count = _record(self.command, self.path, dict(self.headers.items()), body)
            if scenario == DELAYED_GHOST_SCENARIO:
                self.wfile.write(DELAYED_GHOST_HEAD)
                self.wfile.flush()
                time.sleep(DELAYED_GHOST_DELAY_SECONDS)
                try:
                    self.wfile.write(DELAYED_GHOST_TAIL)
                    self.wfile.flush()
                except OSError:
                    # Expected once the fix holds: Tardigrade has already
                    # closed this connection rather than pooling it.
                    pass
                self.close_connection = True
                return
            raw = HOSTILE_SCENARIOS.get(scenario)
            if raw is None:
                raw = f"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".encode()
            self.wfile.write(raw)
            self.wfile.flush()
            self.close_connection = True
            return

        count = _record(self.command, self.path, dict(self.headers.items()), body)
        marker = f"UPSTREAM_REACHED:{count}:{self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(marker)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        if send_body:
            self.wfile.write(marker)
            self.wfile.flush()

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18189)
    args = parser.parse_args()

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
