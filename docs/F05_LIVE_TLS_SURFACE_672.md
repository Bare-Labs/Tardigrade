# F-05 Live Native TLS Surface Evidence (#672)

Date: 2026-08-26

This note records the sanitized evidence for the F-05 live TLS surface pass.
The target was an isolated loopback-only `tardi` listener with synthetic
credentials. Private keys, ticket keys, TLS keylog material, and reusable
session secrets were not committed.

## Target

- Target: `127.0.0.1:18443`
- Binary: `./zig-out/bin/tardi`
- `tardi version`: `dev (tls-profile=general, tls-backend=native)`
- Source SHA: `d2bc042db94f45850c4a9defdb4ebc821768107f`
- OS/architecture: Darwin 25.3.0, arm64
- OpenSSL: OpenSSL 3.6.3, 2026-06-09
- Scanner tooling:
  - Nmap 7.98 with `ssl-enum-ciphers`
  - `testssl.sh` 3.3dev cloned into `/tmp`, commit
    `6d555cac4e151c61e9836559bcbd437b3f0a75c3`
- Listener protocol policy: TLS 1.3 over record transport, ALPN `h2` and
  `http/1.1`; the live record listener policy offers
  `TLS_AES_128_GCM_SHA256` and X25519 by default.

## Synthetic Identities

All identities were generated under `/tmp` and removed from the repository
surface. Only public metadata is retained here.

| Name | Key / signature exercised | SAN | SHA-256 fingerprint |
| --- | --- | --- | --- |
| `tardigrade.test` | Ed25519 | `tardigrade.test`, `default.tardigrade.test` | `CF:CF:54:B1:3F:77:AA:C7:27:08:F6:3C:22:2E:15:09:E1:95:08:9C:CA:30:2E:47:63:E2:40:E1:E6:34:10:FA` |
| `ecdsa.tardigrade.test` | ECDSA P-256/SHA-256 | `ecdsa.tardigrade.test` | `C2:A8:5D:75:E9:5D:06:FB:71:86:D2:54:08:77:9C:24:A2:C6:21:80:26:9C:17:9F:CE:5A:B2:36:A0:98:E8:8E` |
| `rsa.tardigrade.test` | RSA-2048 candidate | `rsa.tardigrade.test` | `CB:09:F4:6C:7B:27:BD:C7:3A:0E:96:75:3D:C7:3E:54:10:0E:4D:A6:B6:52:5C:F9:27:C0:B0:59:07:4F:79:ED` |

The RSA credential was configured only to verify fail-closed behavior for the
current live record policy. RSA-PSS is an engine-level capability, but the
default live record listener policy does not advertise RSA-PSS signatures.

## Scanner Pass

`tls-scan` / `tls_scan` was not available on the host. Two maintained
black-box scanners were run as equivalents and their full text/XML/JSON output
is retained under [`docs/evidence/f05-672/`](evidence/f05-672/).

```bash
nmap -Pn -sV --version-all --script +ssl-enum-ciphers \
  --script-args tls.servername=tardigrade.test \
  -p 18443 -oX tls-nmap.xml 127.0.0.1
```

Result: the port was open, but Nmap did not enumerate ciphers. The listener
requires an acceptable ALPN offer; Nmap's cipher script does not provide one
for this target shape. Full retained outputs:
[`tls-nmap.txt`](evidence/f05-672/tls-nmap.txt) and
[`tls-nmap.xml`](evidence/f05-672/tls-nmap.xml).

```bash
testssl.sh --protocols --server-preference --cipher-per-proto \
  --jsonfile-pretty testssl.json --logfile testssl.log \
  --warnings batch 127.0.0.1:18443
```

Result: `testssl.sh` reported SSLv2/SSLv3/TLS 1.0/TLS 1.1/TLS 1.2 as not
offered. It also reported TLS 1.3 as not offered because its protocol/cipher
probes do not send the ALPN extension required by this listener. Manual
ALPN-bearing OpenSSL and `nghttp` probes below are therefore the authoritative
semantic evidence for TLS 1.3, cipher, SNI, and ALPN behavior. Full retained
outputs: [`testssl.log`](evidence/f05-672/testssl.log) and
[`testssl.json`](evidence/f05-672/testssl.json). The retained `testssl.sh`
banner includes its own short display version; the full commit above was
verified from the cloned scanner repository with `git rev-parse HEAD`.

## Live Certificate Surface

Each row was captured from the live listener with:

```bash
openssl s_client \
  -connect 127.0.0.1:18443 \
  -tls1_3 \
  -servername <name> \
  -alpn http/1.1 \
  -showcerts </dev/null

openssl s_client ... -showcerts </dev/null 2>/dev/null |
  openssl x509 -noout -subject -issuer -dates \
    -ext subjectAltName -fingerprint -sha256 -text
```

| Name | Live result | Retained output |
| --- | --- | --- |
| `tardigrade.test` | Presented a one-certificate self-signed chain with `subject=CN=tardigrade.test`, `issuer=CN=tardigrade.test`, SAN `DNS:tardigrade.test, DNS:default.tardigrade.test`, validity `Aug 26 14:03:43 2026 GMT` to `Sep 2 14:03:43 2026 GMT`, SHA-256 fingerprint `CF:CF:54:B1:3F:77:AA:C7:27:08:F6:3C:22:2E:15:09:E1:95:08:9C:CA:30:2E:47:63:E2:40:E1:E6:34:10:FA`, public-key algorithm `ED25519`, and signature algorithm `ED25519`. | [`live-cert-tardigrade.test.txt`](evidence/f05-672/live-cert-tardigrade.test.txt) |
| `ecdsa.tardigrade.test` | Presented a one-certificate self-signed chain with `subject=CN=ecdsa.tardigrade.test`, `issuer=CN=ecdsa.tardigrade.test`, SAN `DNS:ecdsa.tardigrade.test`, validity `Aug 26 14:03:43 2026 GMT` to `Sep 2 14:03:43 2026 GMT`, SHA-256 fingerprint `C2:A8:5D:75:E9:5D:06:FB:71:86:D2:54:08:77:9C:24:A2:C6:21:80:26:9C:17:9F:CE:5A:B2:36:A0:98:E8:8E`, public-key algorithm `id-ecPublicKey` / P-256, and signature algorithm `ecdsa-with-SHA256`. | [`live-cert-ecdsa.tardigrade.test.txt`](evidence/f05-672/live-cert-ecdsa.tardigrade.test.txt) |
| `rsa.tardigrade.test` | No live certificate was presented. The handshake failed before certificate transmission with TLS alert `internal error`, matching the default live record listener policy that does not advertise RSA-PSS credentials. The synthetic public certificate metadata is retained in the identity table above for the configured candidate. | [`live-cert-rsa.tardigrade.test.txt`](evidence/f05-672/live-cert-rsa.tardigrade.test.txt) |

## Manual Probe Matrix

All OpenSSL probes used `/opt/homebrew/bin/openssl` 3.6.3 against the loopback
listener.

| Matrix row | Probe | Observed result |
| --- | --- | --- |
| TLS 1.3 / X25519 / baseline cipher success | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn h2,http/1.1 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519 -brief` | Success: `Protocol version: TLSv1.3`, `Ciphersuite: TLS_AES_128_GCM_SHA256`, `Signature type: ed25519`, `Peer Temp Key: X25519` |
| TLS 1.2 rejected | `openssl s_client -connect 127.0.0.1:18443 -tls1_2 -servername tardigrade.test -alpn http/1.1 -brief` | Failed closed with alert `protocol version` |
| Cipher no-overlap | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -ciphersuites TLS_AES_128_CCM_SHA256 -brief` | Failed closed with alert `handshake failure` |
| AES-256 pinned | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -ciphersuites TLS_AES_256_GCM_SHA384 -brief` | Failed with `handshake failure`; not product-enabled by the live record listener policy |
| ChaCha20 pinned | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -brief` | Failed with `handshake failure`; not product-enabled by the live record listener policy |
| P-256 group pinned | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -groups P-256 -brief` | Failed with `handshake failure`; not product-enabled by the live record listener policy |
| Group no-overlap | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -groups P-384 -brief` | Failed closed with alert `handshake failure` |
| Ed25519 signature pin | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -sigalgs ed25519 -brief` | Success; selected `CN=tardigrade.test`, signature type `ed25519` |
| ECDSA P-256 signature pin | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername ecdsa.tardigrade.test -alpn http/1.1 -sigalgs ecdsa_secp256r1_sha256 -brief` | Success; selected `CN=ecdsa.tardigrade.test`, signature type `ecdsa_secp256r1_sha256` |
| RSA-PSS signature pin | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername rsa.tardigrade.test -alpn http/1.1 -sigalgs rsa_pss_rsae_sha256 -brief` | Failed closed; RSA-PSS is not advertised by the default live record listener policy |
| No applicable credential | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername ecdsa.tardigrade.test -alpn http/1.1 -sigalgs rsa_pss_rsae_sha256 -brief` | Failed closed with alert `handshake failure` |
| Missing SNI | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -noservername -alpn http/1.1 -brief` | Success; selected the default `CN=tardigrade.test` identity, matching the documented general-profile absent-SNI policy |
| Unknown SNI | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername unknown.tardigrade.test -alpn http/1.1 -brief` | Failed closed with alert `handshake failure`; the default certificate SAN did not cover the requested name |
| ALPN no-overlap | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn acme-tls/1 -brief` | Failed closed with alert `no application protocol` |
| HTTP/1.1 ALPN request | `printf 'GET /health HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n' \| openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -quiet` | Returned `HTTP/1.1 200 OK` and body `ok` |
| HTTP/2 ALPN request | `nghttp -v -y -t 5 -H ':authority: tardigrade.test' https://127.0.0.1:18443/health` | Negotiated `h2`, exchanged SETTINGS, received `:status: 200` and body `ok` |
| Clean TLS close | `openssl s_client -connect 127.0.0.1:18443 -tls1_3 -servername tardigrade.test -alpn http/1.1 -brief </dev/null` | Success with `DONE` |
| Abrupt truncation | `python3 docs/evidence/f05-672/abrupt-truncation.py` | Client completed TLS 1.3, sent a partial HTTP/1.1 request, then closed with TCP RST via `SO_LINGER`; listener logged `error.SocketReadFailed` for the edge connection and remained healthy |
| Repeated malformed handshakes | `for _ in $(seq 1 30); do printf '\x16\x03\x01\x00\x01\x00' \| nc 127.0.0.1 18443 >/dev/null 2>&1 \|\| true; done` | Listener logged bounded `error.TruncatedStream` handshake failures and did not crash or wedge |
| Post-failure health | Same HTTP/1.1 ALPN request after the malformed-handshake burst | Returned `HTTP/1.1 200 OK` and body `ok` |

## Outcome

- No unintended legacy protocol exposure was observed.
- The live listener accepted only the product-enabled baseline cipher/group
  tuple for record TLS and failed closed for non-overlap probes.
- SNI behavior matched `docs/TLS_DEPENDENCY_POLICY.md`: explicit matching SNI
  selected the configured identity, absent SNI selected the default identity,
  and unknown SNI outside the default certificate SAN failed closed.
- ALPN `http/1.1` and `h2` both reached their application entrypoints.
- ALPN no-overlap failed with `no_application_protocol`.
- Clean close and abrupt truncation were distinguishable in live behavior.
- A bounded malformed-handshake run did not crash or wedge the listener.

No product defect was found in this pass, so no lower-layer regression test was
added.
