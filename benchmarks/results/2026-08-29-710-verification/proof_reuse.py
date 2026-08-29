#!/usr/bin/env python3
"""Direct proof: send 3 sequential GET /proxy/health requests over ONE raw
TCP socket and report whether the server let the socket survive (keep-alive)
or terminated it (close) after each response. Also runs an explicit
Connection: close case for contrast.
"""
import socket
import sys

HOST = "127.0.0.1"
PORT = 8069


def send_and_read(sock, close_header=False):
    req = f"GET /proxy/health HTTP/1.1\r\nHost: test\r\n" + \
          ("Connection: close\r\n" if close_header else "") + "\r\n"
    sock.sendall(req.encode())
    sock.settimeout(3)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return None, data
        data += chunk
    header_end = data.index(b"\r\n\r\n") + 4
    headers_raw = data[:header_end].decode(errors="replace")
    conn_header = None
    chunked = False
    for line in headers_raw.split("\r\n"):
        if line.lower().startswith("connection:"):
            conn_header = line.split(":", 1)[1].strip()
        if line.lower().startswith("transfer-encoding:") and "chunked" in line.lower():
            chunked = True
    body = data[header_end:]
    if chunked:
        # Drain until the terminal "0\r\n\r\n" chunk so the next request's
        # response isn't misread as leftover body from this one.
        while b"0\r\n\r\n" not in body:
            chunk = sock.recv(4096)
            if not chunk:
                break
            body += chunk
    return conn_header, data


def peer_closed(sock, wait_s=0.3):
    """Non-destructively check whether the peer has sent FIN (server closed)."""
    import select
    r, _, _ = select.select([sock], [], [], wait_s)
    if not r:
        return False
    peek = sock.recv(1, socket.MSG_PEEK)
    return peek == b""


def probe_sequential(label, n=3):
    print(f"=== {label}: sequential requests over ONE socket ===")
    s = socket.create_connection((HOST, PORT), timeout=3)
    local_port = s.getsockname()[1]
    for i in range(n):
        conn_header, data = send_and_read(s)
        if conn_header is None:
            print(f"  request {i+1}: connection closed by server before/at response (socket EOF) -- local_port={local_port}")
            break
        closed = peer_closed(s)
        print(f"  request {i+1}: Connection header = {conn_header!r}, local_port={local_port}, "
              f"peer closed after response = {closed}")
        if closed:
            break
    s.close()


def probe_explicit_close(label):
    print(f"=== {label}: explicit client Connection: close ===")
    s = socket.create_connection((HOST, PORT), timeout=3)
    conn_header, data = send_and_read(s, close_header=True)
    print(f"  Connection header = {conn_header!r}")
    # Try to read again -- should get EOF (0 bytes) since server must close.
    try:
        s.settimeout(2)
        extra = s.recv(1)
        print(f"  after response, extra recv() returned {len(extra)} bytes (expected 0 = server closed)")
    except socket.timeout:
        print("  after response, recv() timed out (server did not close -- UNEXPECTED for close request)")
    s.close()


if __name__ == "__main__":
    label = sys.argv[1] if len(sys.argv) > 1 else "server"
    probe_sequential(label)
    probe_explicit_close(label)
