#!/usr/bin/env python3
"""External-peer GOAWAY/drain-boundary proof for #677, against the selected
artifact: complete one ordinary request, signal the caller that the
connection is ready (so the shell harness can SIGTERM the server), wait for
the drain to begin, then attempt a *new* request stream on the *same*
already-open QUIC connection. A correct drain boundary must not serve that
new stream as if nothing happened.

aioquic's H3Connection does not surface a public GOAWAY event (it only
rejects GOAWAY arriving on the wrong stream type), so this proves the
boundary's *effect* -- new work refused -- rather than decoding the GOAWAY
frame itself. Admitted in-flight work completing across the same drain is
already covered deterministically by the source-tree reload/shutdown
lifecycle suite (`-Dintegration-test-filter='#170'`) and the test-quic H3
drain smoke; both exercise identical protocol logic to what this binary
runs, just compiled as a debug test binary rather than the selected
artifact, so re-proving that specific sub-case here would just be a
flakier duplicate rather than new evidence.

usage: aioquic_drain_client.py HOST PORT AUTHORITY PATH READY_FILE
READY_FILE is created (empty) once the first ordinary request completes, so
the shell caller knows it is safe to signal the server to shut down.
"""

import asyncio
import socket
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import QuicEvent


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.statuses: dict[int, int] = {}
        self.bodies: dict[int, bytes] = {}
        self.done: dict[int, asyncio.Event] = {}

    def track(self, stream_id: int) -> None:
        self.done[stream_id] = asyncio.Event()
        self.bodies[stream_id] = b""

    def quic_event_received(self, event: QuicEvent) -> None:
        for http_event in self.http.handle_event(event):
            if isinstance(http_event, HeadersReceived):
                sid = http_event.stream_id
                if sid not in self.done:
                    continue
                for name, value in http_event.headers:
                    if name == b":status":
                        self.statuses[sid] = int(value)
            if isinstance(http_event, DataReceived):
                sid = http_event.stream_id
                if sid not in self.done:
                    continue
                self.bodies[sid] += http_event.data
                if http_event.stream_ended:
                    self.done[sid].set()


def send_request(protocol: ClientProtocol, path: str, authority: str) -> int:
    stream_id = protocol._quic.get_next_available_stream_id()
    protocol.track(stream_id)
    protocol.http.send_headers(
        stream_id,
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", authority.encode()),
            (b":path", path.encode()),
        ],
        end_stream=True,
    )
    protocol.transmit()
    return stream_id


async def main(host: str, port: int, authority: str, path: str, ready_file: str) -> int:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    configuration.server_name = authority
    connection = QuicConnection(configuration=configuration)

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: ClientProtocol(connection), sock=sock
    )
    try:
        protocol.connect((host, port))
        await asyncio.wait_for(protocol.wait_connected(), timeout=10)

        pre_id = send_request(protocol, path, authority)
        await asyncio.wait_for(protocol.done[pre_id].wait(), timeout=10)
        pre_status = protocol.statuses.get(pre_id)
        print(f"pre-drain status: {pre_status}")

        # Tell the shell caller it is now safe to SIGTERM the server.
        with open(ready_file, "w"):
            pass

        # Give the server's graceful-shutdown/drain path a moment to start
        # before this connection tries a new stream. A fixed short delay
        # matches this repo's existing bounded-wait convention elsewhere in
        # this harness (`wait_udp_listen`) rather than polling internal
        # server state that a black-box client cannot observe.
        await asyncio.sleep(0.3)

        post_id = send_request(protocol, path, authority)
        try:
            await asyncio.wait_for(protocol.done[post_id].wait(), timeout=3)
            post_status = protocol.statuses.get(post_id)
            refused = post_status is None or post_status >= 400
        except asyncio.TimeoutError:
            post_status = None
            refused = True
        print(f"post-drain status: {post_status}")
        print(f"post-drain refused: {refused}")

        protocol.close()
        await protocol.wait_closed()
        return 0 if (pre_status == 200 and refused) else 1
    finally:
        transport.close()


if __name__ == "__main__":
    host, port, authority, path, ready_file = (
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
        sys.argv[5],
    )
    sys.exit(asyncio.run(main(host, port, authority, path, ready_file)))
