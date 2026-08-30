#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import signal
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import BaseServer
from urllib.parse import parse_qs, urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    PAYLOAD_64K = b"x" * (64 * 1024)
    PAYLOAD_256K = b"y" * (256 * 1024)
    PAYLOAD_1M = b"m" * (1024 * 1024)
    PAYLOAD_16M = b"z" * (16 * 1024 * 1024)

    def setup(self) -> None:
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def do_HEAD(self) -> None:
        self._handle(send_body=False)

    def do_GET(self) -> None:
        self._handle(send_body=True)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/upload-large":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", "0") or "0")
        remaining = content_length
        while remaining > 0:
            chunk = self.rfile.read(min(64 * 1024, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
        body = b"uploaded"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _handle(self, *, send_body: bool) -> None:
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/health":
            body = b"ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(body)
                self.wfile.flush()
            return

        if path == "/slow":
            # Hold the request for ?ms= milliseconds before answering — used by
            # benchmarks/upstream-reuse.sh to demonstrate the per-origin active
            # cap (#239): slow responses keep connections checked out.
            delay_ms = int(query.get("ms", ["100"])[0] or "100")
            time.sleep(delay_ms / 1000.0)
            body = b"slow-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(body)
                self.wfile.flush()
            return

        if path == "/payload-64k.bin":
            payload = self.PAYLOAD_64K
            if query.get("size", [""])[0] == "256k":
                payload = self.PAYLOAD_256K
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(payload)
                self.wfile.flush()
            return

        if path == "/payload-256k.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_256K)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_256K)
                self.wfile.flush()
            return

        if path == "/payload-1m.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_1M)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_1M)
                self.wfile.flush()
            return

        if path == "/payload-16m.bin":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(self.PAYLOAD_16M)))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            if send_body:
                self.wfile.write(self.PAYLOAD_16M)
                self.wfile.flush()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class PreforkedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that serves an already-bound, already-listening
    socket instead of creating its own.

    One of these runs per worker process, all sharing a single listening
    socket created before fork(). The kernel wakes exactly one blocked
    accept() per incoming connection, spreading concurrent connections across
    worker processes (and their GILs) instead of serializing them behind one
    process — see #722.
    """

    def __init__(self, sock: socket.socket, handler_class: type) -> None:
        BaseServer.__init__(self, sock.getsockname(), handler_class)
        self.socket = sock

    def server_bind(self) -> None:
        pass

    def server_activate(self) -> None:
        pass

    def handle_error(self, request: object, client_address: object) -> None:
        # Benchmark clients (wrk et al.) routinely reset connections under
        # load or when a run ends; that's not a fixture bug worth a traceback.
        exc_type = sys.exc_info()[0]
        if exc_type is not None and issubclass(
            exc_type, (ConnectionError, TimeoutError)
        ):
            return
        super().handle_error(request, client_address)


def make_listen_socket(host: str, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1024)
    return sock


def run_worker(sock: socket.socket) -> None:
    PreforkedServer(sock, Handler).serve_forever()


def terminate_workers(pids: list[int]) -> None:
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    for pid in pids:
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass


def exit_code_for(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return 128 + os.WTERMSIG(status)
    return 1


def fork_workers(sock: socket.socket, count: int) -> list[int]:
    child_pids: list[int] = []
    try:
        for _ in range(count):
            pid = os.fork()
            if pid == 0:
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                run_worker(sock)
                os._exit(0)
            child_pids.append(pid)
    except BaseException:
        # A partial pool must not outlive this process: an unhandled fork()
        # failure here would otherwise leak already-started workers that
        # keep the shared listener open after the manager exits (#722 review).
        terminate_workers(child_pids)
        sock.close()
        raise
    return child_pids


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="worker processes preforked onto the shared listening socket "
        "(default: 4); avoids a single GIL becoming the concurrency "
        "bottleneck under proxied c32-c128 load (#722)",
    )
    args = parser.parse_args()

    sock = make_listen_socket("127.0.0.1", args.port)
    workers = max(1, args.workers)

    if workers == 1 or not hasattr(os, "fork"):
        run_worker(sock)
        return

    child_pids = fork_workers(sock, workers)
    remaining = set(child_pids)

    def shutdown(signum: int, frame: object) -> None:
        terminate_workers(list(remaining))
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    sock.close()  # only workers accept; the manager just supervises

    # serve_forever() never returns on its own, so the only expected way out
    # of this call is `shutdown` above interrupting it. If a worker exits on
    # its own instead, that's a silent capacity loss the fixture must not
    # paper over: tear down the rest and fail loudly rather than continuing
    # to serve benchmark traffic from a smaller, uninspected pool (#722 review).
    pid, status = os.wait()
    remaining.discard(pid)
    terminate_workers(list(remaining))
    code = exit_code_for(status)
    raise SystemExit(code if code != 0 else 1)


if __name__ == "__main__":
    main()
