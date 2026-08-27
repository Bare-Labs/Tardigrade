#!/usr/bin/env python3
"""External-peer GOAWAY/drain-boundary proof for #677, against the selected
artifact. Unlike a plain "send a request, then SIGTERM, then see what
happens" probe, this makes every half of the boundary an observed protocol
event rather than an inference from silence:

1. Send a request to a deliberately slow upstream route. The upstream writes
   an "admitted" marker file once it has received the request (proving the
   server actually admitted it) and then blocks until released -- so there
   is a genuinely in-flight, already-admitted request when the shell signals
   readiness.
2. Signal the shell harness (via READY_FILE) that it is now safe to SIGTERM
   the selected artifact.
3. Wait for a real HTTP/3 GOAWAY control frame, observed by subclassing
   `H3Connection` and intercepting `_handle_control_frame` -- aioquic does
   not surface GOAWAY as a public event otherwise.
4. Release the upstream (via RELEASE_FILE) and require the already-admitted
   request to complete with 200 within the drain deadline.
5. Attempt a *new* request stream on the same connection, after the observed
   GOAWAY boundary, and require an explicit protocol-level rejection --
   either a QUIC `StreamReset` for that stream, or the connection itself
   terminating. A bare timeout does not count as proof: an abruptly dead
   connection would satisfy a timeout-only check without proving the
   server's drain contract was actually exercised.

usage: aioquic_drain_client.py HOST PORT AUTHORITY SLOW_PATH ADMITTED_FILE READY_FILE RELEASE_FILE
"""

import asyncio
import pathlib
import socket
import ssl
import sys

from aioquic.asyncio import QuicConnectionProtocol
from aioquic.buffer import Buffer
from aioquic.h3.connection import H3_ALPN, FrameType, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamReset


class ObservingH3Connection(H3Connection):
    """H3Connection that surfaces the GOAWAY control frame aioquic otherwise
    swallows silently."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.goaway_received = asyncio.Event()
        self.goaway_id = None

    def _handle_control_frame(self, frame_type, frame_data):
        if frame_type == FrameType.GOAWAY:
            buf = Buffer(data=frame_data)
            self.goaway_id = buf.pull_uint_var()
            self.goaway_received.set()
            return
        return super()._handle_control_frame(frame_type, frame_data)


class ClientProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = ObservingH3Connection(self._quic)
        self.statuses: dict[int, int] = {}
        self.bodies: dict[int, bytes] = {}
        self.done: dict[int, asyncio.Event] = {}
        self.reset_streams: set[int] = set()
        self.terminated = asyncio.Event()

    def track(self, stream_id: int) -> None:
        self.done[stream_id] = asyncio.Event()
        self.bodies[stream_id] = b""

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamReset):
            self.reset_streams.add(event.stream_id)
            if event.stream_id in self.done:
                self.done[event.stream_id].set()
            return
        if isinstance(event, ConnectionTerminated):
            self.terminated.set()
            for done in self.done.values():
                done.set()
            return
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


async def wait_for_file(path: str, timeout: float) -> bool:
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if pathlib.Path(path).exists():
            return True
        await asyncio.sleep(0.05)
    return False


async def main(
    host: str,
    port: int,
    authority: str,
    slow_path: str,
    admitted_file: str,
    ready_file: str,
    release_file: str,
) -> int:
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

        # 1. Send the slow request; wait for the upstream to admit it.
        slow_id = send_request(protocol, slow_path, authority)
        if not await wait_for_file(admitted_file, 10):
            print("FAIL: upstream never admitted the slow request")
            return 1

        # 2. Tell the shell harness it is now safe to SIGTERM the server.
        with open(ready_file, "w"):
            pass

        # 3. Require an observed GOAWAY frame. On an otherwise-idle
        # connection (no traffic since admission), this has been observed
        # to take on the order of 10s -- well inside the server's own 30s
        # graceful-shutdown deadline, but close enough to a tight bound here
        # to be worth a generous margin rather than flaking on timing.
        try:
            await asyncio.wait_for(protocol.http.goaway_received.wait(), timeout=20)
        except asyncio.TimeoutError:
            print("FAIL: no GOAWAY frame observed after SIGTERM")
            return 1
        print(f"goaway received: id={protocol.http.goaway_id}")

        # 4. Release the upstream; the already-admitted request must still
        # complete with 200 within the drain deadline.
        with open(release_file, "w"):
            pass
        try:
            await asyncio.wait_for(protocol.done[slow_id].wait(), timeout=15)
        except asyncio.TimeoutError:
            print("FAIL: admitted request never completed")
            return 1
        admitted_status = protocol.statuses.get(slow_id)
        print(f"admitted request status: {admitted_status}")
        if admitted_status != 200:
            print("FAIL: admitted request did not complete with 200")
            return 1

        # 5. A new stream beyond the observed boundary must be explicitly
        # rejected (stream reset or connection termination) -- not silence.
        post_id = send_request(protocol, slow_path, authority)
        deadline = loop.time() + 5
        while loop.time() < deadline:
            if post_id in protocol.reset_streams or protocol.terminated.is_set():
                break
            if protocol.done[post_id].is_set():
                break
            await asyncio.sleep(0.05)
        explicit_rejection = post_id in protocol.reset_streams or protocol.terminated.is_set()
        print(f"post-boundary explicit rejection: {explicit_rejection}")

        try:
            protocol.close()
            await asyncio.wait_for(protocol.wait_closed(), timeout=2)
        except Exception:
            pass
        return 0 if explicit_rejection else 1
    finally:
        transport.close()


if __name__ == "__main__":
    (
        host,
        port,
        authority,
        slow_path,
        admitted_file,
        ready_file,
        release_file,
    ) = (
        sys.argv[1],
        int(sys.argv[2]),
        sys.argv[3],
        sys.argv[4],
        sys.argv[5],
        sys.argv[6],
        sys.argv[7],
    )
    sys.exit(
        asyncio.run(
            main(host, port, authority, slow_path, admitted_file, ready_file, release_file)
        )
    )
