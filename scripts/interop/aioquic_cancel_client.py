#!/usr/bin/env python3
"""External-peer QUIC-level cancellation proof for #677: on a single H3
connection, abort one request stream with a real QUIC RESET_STREAM (client
gives up sending) and a second with STOP_SENDING (client gives up
receiving), then complete an ordinary third request on the *same*
connection. Proves the selected artifact's H3 cancellation handling does not
poison unrelated streams -- a CLI accepting "--h3" is not proof of this; this
drives the actual QUIC transport primitives via aioquic's low-level API
rather than any client-exposed "cancel" flag (ngtcp2's example client has
none).

usage: aioquic_cancel_client.py HOST PORT AUTHORITY RECOVERY_PATH
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


async def main(host: str, port: int, authority: str, recovery_path: str) -> int:
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

        # 1. RESET_STREAM: abandon a request immediately after sending it,
        # before any response arrives. The server must treat this as a
        # cancelled request, not a connection-fatal event.
        reset_id = send_request(protocol, recovery_path, authority)
        protocol._quic.reset_stream(reset_id, 0)
        protocol.transmit()
        print(f"sent RESET_STREAM on stream {reset_id}")

        # 2. STOP_SENDING: request a response, then tell the server we no
        # longer want to receive it (client-side abort of the receive
        # direction), before reading anything back.
        stop_id = send_request(protocol, recovery_path, authority)
        protocol._quic.stop_stream(stop_id, 0)
        protocol.transmit()
        print(f"sent STOP_SENDING on stream {stop_id}")

        # 3. Ordinary recovery request on the SAME connection: this is the
        # actual proof that cancellation didn't poison the connection.
        recovery_id = send_request(protocol, recovery_path, authority)
        await asyncio.wait_for(protocol.done[recovery_id].wait(), timeout=10)
        status = protocol.statuses.get(recovery_id)
        body = protocol.bodies.get(recovery_id, b"")
        print(f"recovery status: {status}")
        sys.stdout.write(body.decode(errors="replace"))

        protocol.close()
        await protocol.wait_closed()
        return 0 if status == 200 else 1
    finally:
        transport.close()


if __name__ == "__main__":
    host, port, authority, recovery_path = (
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
    )
    sys.exit(asyncio.run(main(host, port, authority, recovery_path)))
