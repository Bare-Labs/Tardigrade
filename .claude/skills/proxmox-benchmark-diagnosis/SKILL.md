---
name: proxmox-benchmark-diagnosis
description: "Run a live benchmark/diagnosis against real Tardigrade instances on the lab Proxmox host (root@10.250.250.2 over the dedicated 5GbE link — NOT the `proxmox` SSH alias, which resolves to the slower general-LAN address 192.168.86.50) — reproducing a reported performance issue, isolating a root cause, or gathering real-network/real-RTT/real-error evidence for a diagnostic issue or PR review. Use whenever a task needs actual running Tardigrade processes under real network conditions rather than static code reading, and the work involves SSH access to the Proxmox host, provisioning KVM guests or LXC containers, running wrk/tc netem/strace, or explaining a client-side connection-establishment failure."
---

# Proxmox live benchmark diagnosis

This documents a real workflow used for issue #709 (streaming-proxy
connection-churn diagnosis, PR #715) — provisioning real Tardigrade
instances on the lab's Proxmox host and gathering real evidence (throughput,
RTT sensitivity, worker/upstream metrics, syscall-level error causes)
rather than reasoning from code alone. Read this before improvising the
same kind of work from scratch; several of the gotchas below cost real time
to discover and are not obvious from the tool descriptions.

## Ground rule: only touch the Proxmox host

Unless a human explicitly says otherwise, **reach infrastructure only
through the Proxmox host** (`root@10.250.250.2`, hostname reports as
`beelink`, a Proxmox VE 9 host — see "Which network path to use" below for
why that address, not the `proxmox` SSH alias). Do not go hunting for
other LAN hosts by default — this was tried and every alternative was a
dead end or a real risk:

- A separate `beelink` SSH alias (`192.168.86.53`) had a changed host key
  (later found to be benign — the box had been reimaged — but confirm with
  a human before accepting a changed key on a host you don't control) and,
  even after accepting the key, had no authorized key for this session
  (reimaging drops old `authorized_keys`).
- A Jetson device on the LAN had a **fully read-only root filesystem**
  (`mount` shows `ro`), including `/tmp` — nothing can be built or
  installed there.
- A third host (`public`, `192.168.86.54`) was simply unreachable
  (`Operation timed out`) — it turned out to be a *stopped* LXC container
  on the Proxmox host itself (`pct list` showed VMID 103 named "public"),
  not a live host at all.

If a task genuinely needs a second, independently-owned machine and the
Proxmox host can't provide one, say so explicitly and ask — don't silently
substitute a workaround.

## Which network path to use: default to the dedicated 5GbE line

There are **two separate paths** to the same physical Proxmox host, and
they are not interchangeable for anything performance-sensitive:

- **Dedicated 5GbE link** (`10.250.250.1` this Mac ↔ `10.250.250.2` the
  Proxmox host, interface `en8` locally) — a direct point-to-point
  connection set up specifically for benchmark/control traffic. **This is
  the default for all Proxmox management and test traffic.**
- **General LAN** (`192.168.86.50`, over WiFi and the household router) —
  the `proxmox` SSH alias in `~/.ssh/config` currently resolves to *this*
  address, not the dedicated one. Slower, shared with other household
  traffic, and not what this link was set up for.

**Always target `root@10.250.250.2` explicitly** for `ssh`/`scp` to the
Proxmox host itself (e.g. `ssh root@10.250.250.2 "..."`, or
`--target root@10.250.250.2` for `scripts/run-proxmox-performance-campaign.sh`,
which already defaults to it) — do not rely on the `proxmox` alias, since
it silently takes the slower general-LAN path. If `10.250.250.2` is not
reachable (link down, host firewalled from it, etc.), **stop and ask the
user before falling back to the general-LAN/WiFi path** rather than
silently substituting it — this was learned the hard way in the #709
diagnosis, where a whole round of `pct create`/`pct exec` work for two LXC
containers went over the general LAN by oversight because the `proxmox`
alias was used unthinkingly instead of the dedicated address, without
asking first.

This only governs the path *to the Proxmox host itself*. Traffic between
two guest VMs/containers created on that host (e.g. a client container
benchmarking an SUT container) travels over Proxmox's own internal bridge
(`vmbr0`) regardless of which path was used to issue the `pct`/`qm`
commands that created them — the 5GbE line only reaches the host, not its
guests.

## Two ways to get a real Tardigrade instance

### Fast path: LXC containers (seconds to boot)

Best for anything that doesn't specifically need `tc netem`/`CAP_NET_ADMIN`/
`perf_event` (unprivileged LXC containers may not reliably expose these —
use a KVM guest instead if the task needs them).

```bash
PVE=root@10.250.250.2   # the dedicated 5GbE link, not the `proxmox` alias

ssh "$PVE" "pveam list local"   # confirm a cached template, e.g.
                                 # local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
ssh "$PVE" "pvesh get /cluster/nextid"   # get a free VMID

ssh "$PVE" "pct create 106 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
  --hostname my-sut --cores 4 --memory 2048 --swap 0 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp --rootfs local-lvm:8 \
  --unprivileged 1 --onboot 0"
ssh "$PVE" "pct start 106"
ssh "$PVE" "pct exec 106 -- ip -4 addr show eth0 | grep inet"   # get its DHCP IP
```

Install packages and run commands via `pct exec <vmid> -- <cmd>`. For a
**genuinely separate client** (e.g. to avoid a reviewer correctly pointing
out that "the physical Proxmox host as client" isn't a real cross-machine
test — see #715's review history), create a **second** container instead
of using the Proxmox host itself as one endpoint of the test.

Destroy when done, matching the ephemeral-resource convention used
elsewhere in this repo's benchmark tooling:

```bash
ssh "$PVE" "pct stop 106; pct destroy 106 --purge 1"
```

### Thorough path: `scripts/run-proxmox-performance-campaign.sh`

The repo's existing canonical #593 infra. Provisions a disposable **KVM**
guest (real `tc netem`/`perf`/`CAP_NET_ADMIN` support), builds Tardigrade
from an **exact local git ref/SHA** via `git archive` (so the tested binary
is independently verifiable — pass `--tardigrade-ref <full SHA>`, not a
branch name, for a reproducible artifact), and can run the full competitive
suite. Its defaults already target the dedicated link
(`PROXMOX_SSH_TARGET=root@10.250.250.2`, `PROXMOX_SSH_BIND=10.250.250.1`)
— leave them unless you have a specific reason not to.

```bash
./scripts/run-proxmox-performance-campaign.sh \
  --tardigrade-ref <exact-git-sha> \
  --suite competitive --smoke --servers tardigrade \
  --duration 3 --connections 4 --threads 2 \
  --noncanonical --keep-guest --name my-diag
```

**Caveat**: dependency installation (nginx/haproxy/caddy, and especially a
from-source QUIC-capable `h2load` build across nghttp2/nghttp3/ngtcp2) runs
**unconditionally**, regardless of `--smoke` or `--servers` filtering — a
run can easily take 15–30 minutes even when only Tardigrade itself is
needed. For a quick targeted diagnosis, prefer cross-compiling locally and
pushing the binary into a fast LXC container instead (see below).

`--noncanonical` is required if the host isn't otherwise idle (check
`qm list`/`pct list` first — there may be a long-running unrelated guest,
e.g. a prior campaign's SUT left up).

### Cross-compiling and deploying a binary directly (fastest for LXC)

```bash
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-linux-gnu
scp zig-out/bin/tardi "$PVE:/root/tardi-tmp"
ssh "$PVE" "pct push 106 /root/tardi-tmp /root/tardi --perms 0755"
```

If `pct push` hangs on a config lock (see Gotchas below), skip it and pipe
the file in through `pct exec` instead:

```bash
ssh "$PVE" "pct exec 106 -- bash -c 'cat > /root/tardi' < /root/tardi-tmp && \
             pct exec 106 -- chmod +x /root/tardi"
```

## Gotchas (each of these cost real debugging time — don't rediscover them)

1. **`pkill -f <pattern>` can kill your own SSH session.** `pkill -f` grep-
   matches a process's full command line, including the pkill invocation's
   *own* argv — if your pattern string is a literal substring of the
   `ssh ... "pkill -f '<pattern>' ..."` command line itself (it almost
   always is), `pkill` can match and kill the shell hosting your own SSH
   session, silently dropping the connection (`exit 255`, no error
   message). Fix: match by process name only (`pkill tardi`, no `-f`) when
   the name is unambiguous, or use the classic bracket trick
   (`pkill -f '[t]ardi run'` — the target's real cmdline contains `tardi`
   but the pkill invocation's own argv contains the literal `[t]ardi`
   string, which the regex `[t]ardi` does not match).

2. **Backgrounding a remote daemon via `ssh "$PVE" "cmd & disown"` hangs
   the SSH session**, even with output redirected to a file — the
   connection just never returns. Use `ssh -f "$PVE" "cmd"` instead (`-f`
   backgrounds the ssh client itself after auth, before running the
   command) for a clean, non-hanging detached launch. If you do end up
   with a hung `ssh` call, it's safe to `kill` the local hung `ssh`
   process (the remote command already started, detached, and keeps
   running — check with a fresh `ssh "$PVE" "ps aux | grep ..."` before
   assuming anything went wrong).

3. **`pct push`/`pct stop`/`pct destroy` can hang indefinitely on
   `/run/lock/lxc/pve-config-<vmid>.lock`.** Observed: the container's own
   `vzstart` supervisor task held this lock for the container's entire
   running lifetime in a way that blocked other lock-needing `pct`
   operations (this may be specific to how the container was started —
   e.g. if the original `pct start` command's SSH session was itself
   killed mid-flight per gotcha #2 above). Diagnose with
   `ssh "$PVE" "fuser /run/lock/lxc/pve-config-<vmid>.lock"` — if it
   points at a long-running `task ... vzstart` process, `kill -TERM` that
   PID (safe: it's just the supervisor/lock-holder, not the container
   itself) and retry the `pct` command.

4. **`wrk` is blocked from opening outbound sockets in this sandboxed
   session**, even a copy freshly rebuilt from source (ruling out a
   binary-signature/hash-based block) — confirmed by the identical
   `No route to host` failure that plain `curl`/`nc`/Python `urllib` do
   **not** hit. This looks like a host-level network policy specific to
   this session's environment, not something fixable by changing the
   `wrk` binary. When `wrk` is required, run it on a Linux box reachable
   via `$PVE` (the physical host, or an LXC/KVM guest) instead of
   the agent's own local machine. If `wrk` is truly unavailable anywhere
   reachable, fall back to a small dependency-free Python `http.client`
   load driver as a last resort, and say so explicitly in any evidence
   produced that way — it is not a drop-in equivalent (different
   performance characteristics; only trust *relative* comparisons made
   with it, and only when made with itself at both ends of a comparison,
   never mixed with `wrk` numbers).

5. **Client-side TCP `TIME_WAIT`/ephemeral-port exhaustion is a real,
   reproducible failure mode**, not a benchmark artifact to work around —
   it may be exactly the thing under investigation. Any workload that
   forces a new TCP connection per request (`Connection: close`, explicit
   reconnect testing) fills the *client's* local ephemeral port range
   within seconds to tens of seconds, symptom `EADDRNOTAVAIL` on
   `connect()` (`errno 49` on macOS, `errno 99` on Linux). Budgets differ
   by OS: macOS defaults to ~16,383 ports / ~30s `TIME_WAIT`
   (`sysctl net.inet.ip.portrange.{first,last}`, `net.inet.tcp.msl`);
   Linux defaults to ~28,232 ports / ~60s `TIME_WAIT`
   (`sysctl net.ipv4.ip_local_port_range`). **This contaminates
   back-to-back benchmark rows**: a heavy-churn row's sockets don't clear
   `TIME_WAIT` for up to a minute, so the *next* row (even an unrelated
   one) can inherit thousands of stale entries and report misleadingly
   bad numbers. Before starting a new churn-heavy row, poll
   `ss -tan state time-wait | wc -l` (Linux) on the client until it drops
   to near zero.

6. **`wrk`'s `Socket errors: connect N` counter is client-side** (`wrk`'s
   own `connect()` calls failing) — it is not something the server under
   test reports. To root-cause a `connect` error count, `strace` (or
   equivalent) **`wrk` itself**, not the server:
   `strace -f -tt -e trace=connect,close,socket -o out.txt wrk ...`. Note
   `strace`'s own overhead is a real observer effect — a straced run may
   not reproduce a race that an untraced run hits reliably; a longer
   duration or a second attempt may be needed to catch it while traced.

7. **`git rev-parse <ref>` + `git archive` (as
   `run-proxmox-performance-campaign.sh` does) gives a genuinely verifiable
   build** — record the exact SHA and, ideally, the built binary's SHA-256,
   in any evidence produced. "This worktree's HEAD" is not reproducible
   evidence once the worktree moves on.

## General shape of a diagnosis

1. Confirm the dedicated link is reachable
   (`ssh -o ConnectTimeout=5 root@10.250.250.2 "echo ok"`) and use it for
   everything that follows. Only if it fails, stop and ask the user before
   falling back to the `proxmox` alias/general LAN — don't substitute it
   silently. Once confirmed, check what's already running (`qm list`,
   `pct list`) so you don't collide with or misinterpret a pre-existing
   resource.
2. Provision the minimum viable SUT (and a genuinely separate client, if
   the diagnosis needs one) via the fast or thorough path above.
3. Deploy the exact code under test (cross-compiled binary, or built via
   the campaign script from an exact SHA) plus any fixture/config needed.
4. Run the smallest matrix that actually isolates the variable in
   question — a targeted diagnosis is not a full competitive benchmark
   campaign; don't run scenarios the specific question doesn't need.
5. Capture raw tool output (not just parsed numbers) for anything a
   reviewer might later ask to see verbatim — `wrk`'s stdout, `strace`
   excerpts, `/status/metrics` scrapes before/after.
6. Destroy ephemeral resources (`pct destroy`/`qm destroy --purge`) when
   done, and say so in the write-up.
7. Write up caveats honestly, including where results disagree across
   environments (e.g. a KVM-guest run and an LXC-container run of the
   "same" test showing different magnitudes for one factor) — report both
   rather than picking the more convenient one.
