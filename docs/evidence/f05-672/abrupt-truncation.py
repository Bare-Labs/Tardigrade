import socket
import ssl
import struct


HOST = "127.0.0.1"
PORT = 18443
SERVER_NAME = "tardigrade.test"


ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.maximum_version = ssl.TLSVersion.TLSv1_3
ctx.set_alpn_protocols(["http/1.1"])

raw = socket.create_connection((HOST, PORT), timeout=5)
ssock = ctx.wrap_socket(raw, server_hostname=SERVER_NAME)
print("negotiated", ssock.version(), ssock.cipher(), ssock.selected_alpn_protocol())
ssock.sendall(b"GET /health HTTP/1.1\r\nHost: tardigrade.test\r\n")
ssock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
ssock.close()
print("closed with TCP RST after partial request")
