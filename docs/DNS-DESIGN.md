# DNS Behavior Design — Phase 8

> Status: **IMPLEMENTED (2026-09-19).** The recommended path below has been
> built: `Socks5UdpAssociateClient` (ProxyApp.Network — the RFC 1928 §7 leg,
> unit-tested against a real loopback SOCKS5 + UDP relay peer) and
> `UdpDnsFerry` (ProxyApp.WinDivert — the E8-a/E8-b capture/attribution/
> injection mechanics, ported from the spikes). Opt-in via Settings → DNS.
> Fail-closed on relay failure; loop-free (injected replies are inbound, the
> filter is outbound-only). The remaining OPEN question is E8-c: the full
> elevated chain against a real proxy + real resolver. DoH/DoT remains an
> unavoidable leak — never claim otherwise.
>
> **Scope correction (2026-09-19, from a live ipleak.net test):** interception
> is SYSTEM-WIDE, not per-app. Windows apps do not send DNS themselves — the
> DNS Cache service (svchost.exe, dnscache) sends the UDP 53 query on the
> app's behalf, so a per-process gate attributed the query to svchost,
> found no matching rule, and passed the query through — the leak persisted
> (the DNS test still showed the real IP). Attribution is now diagnostic-only
> (traced), and every captured UDP 53 query is relayed while the setting is
> enabled. **WebRTC** (STUN over UDP 3478+) also revealed the real IP in the
> same test — arbitrary-UDP tunneling is R6, a separate phase; DoH/DoT and
> IPv6-transport DNS remain uncovered as below.

## 1. Current behavior — the ferry leaks DNS

### What the ferry does today

The ferry (`TcpFerry`) intercepts **outbound TCP SYNs** whose destination is an
**IP address**:

- Capture filter: `outbound and ip and tcp and not loopback` — TCP only; UDP
  (port 53) is never captured.
- On a captured SYN it attributes the owning process, applies rules, and
  establishes a SOCKS5 CONNECT to the destination **IP literal**
  (`new Socks5Destination(tuple.DstIp.ToString(), tuple.DstPort)`,
  `src/ProxyApp.WinDivert/TcpFerry.cs`), which the SOCKS5 client encodes as
  ATYP IPv4/IPv6 (never domain — `BuildConnectRequest`'s domain path is
  unreachable from the ferry).

### The leak

An application that resolves a hostname itself — **the dominant case for
browsers and most apps** — calls `getaddrinfo` / its own resolver, which sends
DNS queries through the **system resolver** (UDP 53 to the configured DNS
server, or DoH/DoT on 443) **before** any TCP SYN exists for the ferry to see.
Those queries are:

1. **Not proxied** — the ferry never touches UDP, so the queries go direct.
2. **Not visible** — by the time the SYN arrives, the name is already an IP.

Therefore: **the app currently leaks DNS for most real-world traffic. The
project must NOT claim any DNS-leak protection.** The existing
`docs/WINDIVERT_SPIKE.md` table correctly records **R5 (DNS leak) NOT TESTED**
and **R6 (QUIC/UDP) NOT TESTED**; this document is the first treatment.

### What is proxied today (the honest picture)

- TCP connections whose destination is already an IP (e.g. curl to a literal
  IP, or any app after local resolution) — the SYN is captured, the traffic
  flows through the SOCKS5 CONNECT to the proxy.
- **Nothing else**: no DNS, no UDP, no QUIC, no ICMP. Non-TCP traffic and
  TCP-443 QUIC (HTTP/3) bypass the ferry entirely (R6).

## 2. The design space

### 2.1 Who resolves the name — local vs remote

| | Local resolution (today) | Remote resolution (via proxy) |
|---|---|---|
| Who resolves | The app's `getaddrinfo` → system resolver → UDP 53 / DoH / DoT direct | The SOCKS5 proxy, given a domain ATYP 0x03 CONNECT |
| Ferry sees | A SYN to an IP | A SYN to an IP (the app resolved first) |
| Leak | **Yes** (queries go direct) | **No** — but only if the app passes the NAME, which it does not |

**Key fact:** once the app has resolved locally, the SYN carries an IP. The
ferry cannot recover the original hostname from the IP. So remote resolution
only helps if the app never resolves — i.e. the ferry must **intercept the DNS
queries themselves** so the app never learns the IP.

### 2.2 Options to close the leak

**(a) Intercept UDP 53 and redirect resolution to the proxy's remote resolver.**
The ferry captures outbound UDP 53 queries for selected processes, forwards the
query to the proxy's resolver (SOCKS5 **UDP ASSOCIATE** leg, or a local UDP
forwarder tunneled through the proxy), and relays the reply back to the app —
with the query/response IP headers rewritten so the app believes its own DNS
server answered. The app then connects to the proxy-resolved IP; the TCP leg
flows through the existing CONNECT path.

- Requires: a SOCKS5 UDP ASSOCIATE implementation (RFC 1928 §7), UDP packet
  capture/rewrite in WinDivert, reply spoofing (the app expects a reply from
  the original DNS server, not from 127.0.0.1 or the proxy), and careful loop
  avoidance (our injected UDP replies must not be re-captured).
- Complexity: **high**. This is the only option that fully closes the leak for
  locally-resolving apps.

**(b) Force name-based SOCKS5 CONNECT (domain ATYP) so the proxy resolves.**
The SOCKS5 client already supports domain ATYP 0x03 (`BuildConnectRequest`),
but the ferry always passes an IP literal. If the ferry knew the hostname it
could send the domain — but **it does not**: the app resolved first. This option
alone **cannot work** for locally-resolving apps; it only helps apps that pass a
hostname directly (none in the dominant browser case, and the ferry never sees
the name anyway).

- **Verdict: (b) alone is insufficient.** It could complement (a) as a
  belt-and-braces for apps that DO send hostnames (e.g. some CLI tools with
  `--resolve`-style behavior), but it cannot close the leak.

**(c) DoH/DoT (DNS over HTTPS/TLS).** The app contacts a resolver IP on 443
directly over TLS. Packet interception **cannot** see inside the TLS stream to
inspect or redirect the queries — and since the resolver IP itself is the
destination, there is no hostname to rewrite. **This leak is unavoidable by
packet-level means** unless the app is configured (by the user) to use a
specific resolver the proxy can reach. State this limitation honestly: a
determined app with DoH/DoT leaks DNS regardless of the ferry.

### 2.3 IPv4 / IPv6

- DNS queries can be IPv4 (UDP 53) and IPv6 (UDP 53 on the v6 stack);
  responses must be rewritten for whichever family the query used.
- A dual-stack client may query A and AAAA; the proxy's resolver must answer
  both, and the ferry must forward both query families.
- The current ferry is IPv4-only in its tested path (spike R7: IPv6 NOT
  TESTED); UDP 53 interception must not assume v4-only.

### 2.4 Security / complexity tradeoffs

| Option | Closes leak | Complexity | Risk |
|---|---|---|---|
| (a) UDP 53 intercept + UDP ASSOCIATE | **Yes** (for non-DoH apps) | High | UDP reply spoofing, loop avoidance, per-process UDP attribution (WinDivert does not attach PIDs to UDP datagrams — needs connection-table correlation like TCP's `GetExtendedTcpTable`, but for UDP: `GetExtendedUdpTable`) |
| (b) Domain ATYP CONNECT | No (alone) | Low | None new (client already supports it) |
| (c) DoH/DoT | **Cannot** (packet-level) | — | None (out of scope; document as a limitation) |

Per-process UDP attribution is a real open question: TCP SYN attribution uses
the connection table keyed by 4-tuple (R1, validated E7); UDP datagrams have no
SYN-equivalent, so correlating a query to a process requires the UDP table
(`GetExtendedUdpTable`), which is racier (queries are one-shot). **This needs
an elevated experiment to decide** whether WinDivert can cleanly capture,
rewrite, and re-inject UDP 53 without a capture/re-injection loop (the spike's
E4b loop-avoidance result was for TCP reinjection only).

## 3. Priority — Phase 8 is the next correctness/security priority

- CLAUDE.md priority order places **DNS behavior (#6) above the GUI (#8)** and
  the project explicitly says "Do not claim 'DNS leak protection' unless it has
  actually been tested."
- The ferry today **fails this property** for the dominant real-world path
  (apps that resolve locally). This is a correctness/security gap, not a
  feature gap: a user who expects "this app's traffic goes through the proxy"
  is wrong about DNS — the queries go direct and reveal the names to the local
  resolver/observer.
- Until option (a) is implemented and tested, the README and UI must not claim
  DNS-leak protection.

## 4. What must be decided by an elevated experiment (not by reasoning)

### E8-a result (2026-08-21, elevated run)

`spikes/WinDivertSpike/Experiment8a.cs` (run via `.\run-spike.ps1 -Experiment --e8a`):

| Question | Result |
|---|---|
| Capture outbound UDP 53 (`outbound and ip and udp and udp.DstPort == 53 and not loopback`) | **WORKS** — captured `192.168.100.10:<ephemeral> → 192.168.100.1:53`, DNS id echoed, `outbound=True` |
| Per-process UDP attribution via `GetExtendedUdpTable` | **WORKS** — resolved a UDP 53 socket to the owning PID |
| Reinject crafted reply inbound (E5b pattern: Outbound cleared, IfIdx/SubIfIdx preserved, Impostor=0, helper checksums) | **WORKS** — `WinDivertSend` succeeded, no re-capture loop observed |
| **Client acceptance** — `Resolve-DnsName` returns the crafted A record (192.0.2.1) without the real network | **NOT PROVEN (INCONCLUSIVE)** — returned `''`; the client's resolver did not accept the reply |

**Finding:** capture, attribution, injection, and loop-avoidance all work. The
blocker is **crafted-reply acceptance** — the client resolver rejected the
spoofed reply. Most plausible hypotheses (unproven, need the next experiment):

1. The crafted reply's **question section** must be a byte-exact copy of the
   query's (including EDNS0 OPT RR and label encoding). The current
   reconstruction may not match.
2. The client socket may have timed out during processing (the experiment held
   the query for ~1s while crafting; DNS retries were observed system-wide).
3. The reply's source IP/port or UDP checksum may not satisfy the resolver's
   expectations.

**Gate:** production DNS code is NOT started until the client-acceptance
question is proven by a follow-up experiment (E8-b: forward the actual query
bytes untouched and echo the reply with only the source swapped, eliminating
the reconstruction variable; keep the client socket alive while crafting).

### E8-b result (2026-08-21, elevated run) — **PASS**

`spikes/WinDivertSpike/Experiment8b.cs` (run directly, `--e8b`):

```
[captured query]  192.168.100.10:58073 -> 192.168.100.1:53 len=57 (id=0xDFA2)
[test-server]     received 29 bytes (DNS payload stripped of IP+UDP headers)
[test-server]     sent 45 bytes (id echoed, QR=1, RA=1)
[injected reply]  192.168.100.1:53 -> 192.168.100.10:58073 len=73 (DNS 45 bytes)
[E] UDP 53 packets observed: 1   ← no loop
[client acceptance] Resolve-DnsName returned: '192.0.2.1'
[classification] PASS
```

The client resolver accepted the reinjected reply (192.0.2.1 can only come
from the injected reply — a real resolver never answers with TEST-NET). The
**DNS-leak-closing approach is feasible for non-DoH apps.** Bugs found and
fixed along the way: the first E8-b run forwarded the WHOLE captured packet
(IP+UDP headers included), so the test server saw qdcount=0 and could not
build a reply; the fix strips IP+UDP headers before forwarding (commit
`6128b47`).

**Remaining unvalidated component:** the SOCKS5 UDP ASSOCIATE leg (client →
real proxy over UDP, RFC 1928 §7). E8-b used a local plain-UDP test server,
not the SOCKS5 relay. This is the only piece between the experiment and
production; it is implemented and tested independently (Step 1), then
validated by the E8-c elevated experiment (full chain: real query → capture →
UDP ASSOCIATE to a UDP-ASSOCIATE-capable test SOCKS5 server → reinject →
client acceptance).



Per the handoff guardrails (verify by running the test, not by reasoning):

1. **Can WinDivert capture outbound UDP 53 cleanly** (filter
   `outbound and udp and udp.DstPort == 53`) without disturbing the system
   resolver, and **re-inject a rewritten UDP reply** without re-capture (the
   Impostor/loop-mitigation semantics for UDP differ from TCP)?
2. **Can per-process UDP attribution work** via `GetExtendedUdpTable`
   (race: query sent → row visible → we capture the datagram), fast enough for
   the rule decision?
3. **Can a SOCKS5 UDP ASSOCIATE leg** relay the query to the proxy's resolver
   and return the reply with correct source spoofing? — **OPEN** (the only
   unvalidated component; E8-b proved the forward-and-echo via plain UDP, not
   via SOCKS5 UDP ASSOCIATE). Implemented and tested independently (Step 1:
   `Socks5UdpAssociateClient` + extended `Socks5TestServer`), then validated
   by E8-c.

These are experiment-shaped questions. The doc records them as open; nothing is
assumed.

## 5. Recommended path (pending the experiments)

1. **E8-a:** elevated UDP-53 capture/reinject experiment (WinDivert UDP loop
   avoidance + UDP table attribution) — decides feasibility.
2. If feasible: SOCKS5 **UDP ASSOCIATE** client leg (RFC 1928 §7) + ferry UDP
   relay, matching the TCP ferry's structure (unit tests with a local
   SOCKS5 test server, then an elevated E2E with a real resolver).
3. Document DoH/DoT as an unavoidable residual leak; never claim otherwise.
4. Optionally: domain-ATYP CONNECT for the (rare) apps that pass hostnames.

## 6. Explicit non-goals for Phase 8

- No UDP tunneling of arbitrary UDP (that is R6 / a separate phase).
- No interception of DoH/DoT (impossible at packet level; document only).
- No claim of leak protection until option (a) is implemented and tested.

## 7. Decision

This is a design document only. Implementation is deliberately deferred. The
next step is the user's choice:

- **(a)** implement the chosen DNS approach (starting with the E8-a elevated
  experiment), or
- **(b)** run the live-app smoke test (`docs/LIVE_APP_SMOKE_TEST.md`) with a
  real SOCKS5 proxy first, or
- **(c)** proceed to Phase 9 (IPv6).
