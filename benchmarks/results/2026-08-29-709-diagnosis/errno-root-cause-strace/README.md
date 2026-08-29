# Errno-level root cause of the "32 errors" signature

Addresses follow-up review feedback that the report deferred the exact
Linux-side cause of `wrk`'s `Socket errors: connect 32` as "most plausibly
listen-backlog pressure" without evidence. `wrk`'s "Socket errors: connect"
counter is a **client-side** count (`wrk`'s own `connect()` calls failing),
not a server-reported error -- so the trace target is `wrk` itself, not
Tardigrade.

## Method

`strace -f -tt -e trace=connect,close,socket -o wrk-strace2.txt wrk --latency
-t4 -c32 -d20s http://192.168.86.56:8069/proxy/health`, run on the client
LXC container (107) against the SUT container (106) in `response` mode
(commit `a81cfcdc...`, same binary as the rest of this diagnosis). The
first attempt at 15s duration produced 0 errors (strace's overhead changes
timing enough that the race didn't manifest that run -- a real observer
effect, noted honestly rather than omitted); the second attempt at 20s
duration reproduced the exact "32 errors" signature while traced.

## Result

**All 32 failures are `connect()` returning `-1 EADDRNOTAVAIL` ("Cannot
assign requested address")** -- see `wrk-strace-errors-only.txt` (the 32
matching lines) and `wrk-strace-excerpt-EADDRNOTAVAIL.txt` (400 lines of
surrounding context showing the socket()/connect()/close()/retry cycle on
each of wrk's 4 OS threads).

`EADDRNOTAVAIL` on an outbound `connect()` (not `bind()`) means the kernel
could not find a free local `(source IP, source port)` tuple to originate
the connection -- i.e. **client-side ephemeral-port exhaustion**, driven by
accumulated `TIME_WAIT` sockets from the same forced-reconnect-every-request
behavior this diagnosis already attributes to the `Connection: close`
defect. Immediately after the failing run, `ss -tan state time-wait | wc -l`
on the client reported 8747 sockets in `TIME_WAIT` (matching that run's
8745 completed requests almost exactly) -- and that count was still
elevated from the *previous* traced run's ~21,000 connections, which had
not yet aged out of `TIME_WAIT` (60s default) when this run started.
Combined, the two runs' connection counts approached this container's
28,232-port ephemeral range (`net.ipv4.ip_local_port_range = 32768 60999`).

**This is the same mechanism identified for the Mac client**
(`EADDRNOTAVAIL` / `errno 49` there, `EADDRNOTAVAIL` / `errno 99` here --
same POSIX error, OS-specific errno number), not a different, unexplained
Linux-side cause. The two platforms differ only in how much sustained churn
is needed to trigger it (macOS: 16,383 ports / 30s `TIME_WAIT`; Linux:
28,232 ports / ~60s `TIME_WAIT`), which is exactly why some of this
diagnosis's Linux/`wrk` rows show 0 errors (lower aggregate churn within
the drained window) and others show exactly 32 (concurrency-matched, one
failure per `wrk` thread, once the cumulative `TIME_WAIT` population from
that thread's own reconnect loop -- or a preceding run's leftover
`TIME_WAIT` -- exhausts the local port budget). This directly supersedes
the earlier "most plausibly listen-backlog pressure" speculation.
