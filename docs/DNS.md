# DNS Handling

## Overview

Open NetRoute intercepts **all plaintext DNS system-wide** and relays it through the configured SOCKS5 proxy. While the relay is running, plaintext DNS cannot leave the machine directly.

DNS traffic is handled separately from the main TCP proxying path, on both of its transports:

```text
Application
    │
    │ UDP/53 (IPv4 or IPv6)   or   TCP/53 (truncated-answer fallback)
    ▼
WinDivert  (outbound-only capture: 2 handles for UDP/53 + 2 for TCP/53, one per address family)
    │
    ▼
DNS relay
    │
    ├── UDP/53 ──► SOCKS5 UDP ASSOCIATE ──┐
    │                                     ▼
    └── TCP/53 ──► SOCKS5 CONNECT ────► DNS server
                                          │
                                          ▼
                                     DNS response
                                          │
                                          ▼
                                      relay
                                          │
                                          ▼
                              WinDivert injection (inbound)
                                          │
                                          ▼
                                    Application
```

Separately, a PASSIVE observer runs alongside. It changes no routing — a SNIFF-mode handle copies packets and lets the real ones continue:

```text
outbound TCP/443 ──► SNIFF handle ──► read ClientHello SNI ──► "which app resolved via DoH, and to which resolver"
```

> **What is guaranteed:** plaintext DNS on port 53 — over UDP and TCP, IPv4 and IPv6 — is captured system-wide and relayed through the proxy. Queries are dropped rather than sent directly when they cannot be relayed (fail-closed).
>
> **What is not guaranteed:** encrypted DNS (DoH, DoT, DoQ) and application-specific resolvers on non-standard ports. Those are not relayable without TLS interception, which Open NetRoute does not perform. DoH endpoints on TCP/443 *are* identified and named (see [Encrypted DNS Detection](#encrypted-dns-detection-diagnostic)), but nothing is blocked.

## DNS Traffic Flow

### Plaintext DNS over UDP (IPv4 and IPv6)

1. `WinDivertOpen` with `outbound and ip and udp and udp.DstPort == 53 and not loopback`.
2. A second handle with `outbound and ipv6 and udp and udp.DstPort == 53 and not loopback` captures the IPv6 equivalent, so DNS over IPv6 transport cannot bypass the relay. The handles are separate because a WinDivert filter expression cannot mix `ip` and `ipv6`.
3. The IPv4 or IPv6 + UDP headers are parsed (`UdpPacketParser.TryParse` / `TryParseUdp6`) and the DNS payload is extracted **unchanged**. Reconstructing the question section was proven to be rejected by the client's resolver, so the payload is forwarded byte-for-byte.
4. The payload is wrapped in an RFC 1928 datagram and sent to the proxy's relay endpoint (`Socks5UdpAssociateClient`).
5. The reply is unwrapped, correlated by the DNS transaction ID, and re-injected **inbound** — spoofed to appear to come from the original DNS server the client addressed — with checksums computed by `WinDivertHelperCalcChecksums`.
6. Process attribution (`GetExtendedUdpTable`, v4 and v6 tables) is **diagnostic only**. It never gates interception.

### Plaintext DNS over TCP

Windows falls back to TCP/53 when a UDP answer is truncated, and some resolvers are TCP-only. The UDP leg cannot see that traffic, so the TCP ferry treats destination port 53 as a **forced-proxy port** when the DNS relay is enabled: the connection is ferried through the active proxy through the ordinary SOCKS5 CONNECT path, system-wide and regardless of the App Rules.

The override is deliberate and unconditional. A `Direct` app rule, or no matching rule at all, must not be able to let plaintext DNS escape. If the proxy is unreachable the connection fails; it never falls back to a direct connection.

**Both address families.** TCP/53 is captured on IPv4 and IPv6. A filter expression cannot mix `ip` and `ipv6`, so the IPv6 leg is a second WinDivert handle (`outbound and ipv6 and tcp and tcp.DstPort == 53 and not loopback`) owned by the TCP ferry. Failing to open it is not fatal — a v4-only host legitimately has no IPv6 stack — but it is always traced, and on a dual-stack host it means DNS over TCP+IPv6 is a real exposure.

The IPv6 leg required family-correct packet handling throughout, because the original code assumed a 20-byte IPv4 header everywhere:

| Site | IPv4-only assumption | Consequence if unchanged |
|---|---|---|
| `TcpPacketParser.IpHeaderLength` | `(packet[0] & 0x0F) * 4` | Returns **0** for IPv6 (that nibble is traffic class / flow label), pointing every payload offset at the IP header |
| `TcpPacketBuilder` | fixed 20-byte header, TCP at offset 20 | Emits an invalid packet for an IPv6 tuple; the client's stack rejects it |
| `ApplyGameModeDscp` | DSCP in the TOS byte at offset 1 | Writes into the flow label instead of the traffic class |
| `FlowState` / injection | one capture handle | A handle only admits packets its own layer/filter accepts, so an IPv6 flow cannot be answered through the IPv4 handle |

A flow now records the handle its SYN arrived on (`FlowState.SendHandle`) and every injection toward that flow — SYN-ACK, data, ACK, FIN, RST — goes through it.

### Fail-closed behavior

Every failure mode drops the query instead of releasing it directly:

| Situation | Behavior |
|---|---|
| Packet too short to be a DNS query | dropped |
| Header parse fails (including IPv6 packets with extension headers) | dropped |
| UDP ASSOCIATE not established (proxy lacks UDP support) | dropped, status surfaced in the UI, retried every 15 s |
| Relay timeout or error | dropped; the client's resolver retries |
| Reply injection fails | the client's resolver retries |

Dropping means the lookup fails. That is the intended trade-off for a privacy feature: a failed query is visible and retryable, whereas a leaked query is silent.

The Windows resolver cache is flushed when the relay starts and again when it stops (`DnsFlushResolverCache`). Without the flush, names resolved **before** START would be served from the local cache without any query to intercept — a leak test run immediately after START could show those stale answers.

## Process Scope

Windows DNS traffic is generated by the Windows DNS Client service (`dnscache`) rather than directly by the originating application. A DNS request therefore often appears to originate from a system networking component.

This is why interception is system-wide rather than per-application. A per-process gate would almost never match the selecting application and the queries would leak. DNS queries are low-volume, so relaying all of them is the same trade-off tools like Proxifier make.

## Resolver Override

Relayed queries are sent to the configured resolver (`1.1.1.1` by default), which keeps the user's configured — typically ISP — resolver out of the path. A leak test then shows the public resolver rather than the ISP.

IPv4 and IPv6 literals are both accepted. A query is sent to the override of its own address family: an IPv6 query to a v6 override, an IPv4 query to a v4 override. Loopback overrides are rejected. Leaving the setting empty is transparent mode, where each query is relayed to the server the client originally addressed.

## Tested Behavior

Automated tests cover the parts that can be verified without a live proxy:

* IPv4 filter shape (`UdpDnsFerry.BuildFilter`), with and without the STUN ports;
* IPv6 filter shape (`UdpDnsFerry.BuildFilterV6`) — outbound-only, `ipv6`, port 53, no loopback;
* IPv6/UDP parse and build round trip, including the extension-header rejection;
* IPv6/TCP parse and build round trip (`TcpIpv6Tests`): the 40-byte header, the v6 address offsets, payload placement after the header, SYN options, the control packets, and that the IPv4 layout is byte-for-byte unchanged;
* **the relay-target rule** (`UdpDnsRelayTargetTests`): DNS redirects to the override, and every STUN port keeps its original destination — the regression that kept WebRTC leaking;
* **the STUN disposition rule**: blocking beats relaying, because dropping is the only outcome that cannot fail open into a direct candidate;
* **the two legs stay independent**: blocking WebRTC alone never captures DNS, and relaying STUN alone never does either;
* **STUN content detection** (`StunMessageTests`): address-discovery messages are detected on any port, while QUIC, short payloads, a bad cookie, a bad type-bit pattern, and TURN media are all left alone — the negative cases matter because a false positive silently discards traffic the user needed;
* **only one component owns STUN**: with blocking on, the DNS/STUN ferry must not also capture the STUN ports, since two diverting handles on one datagram is a race rather than redundancy;
* the STUN port set on BOTH address families (`BuildFilterV6(relayStun: true)`) — the IPv6-DNS-only regression that made STUN relaying silently ineffective on dual-stack hosts;
* the TCP ferry's forced-port set — default empty, `{ 53 }` when the DNS relay is on, and never any other port;
* resolver-override validation — both address families accepted, non-literals and loopback rejected, empty allowed;
* the SNI ClientHello parser and its classification (`DnsSniInspectorTests`): hostname extraction, truncated/malformed input rejected without throwing, exact-match-only behaviour, and that ordinary web hostnames are never flagged.

The core relay mechanism (capture, forward through UDP ASSOCIATE, reinject inbound, no observed processing loop) was validated by the E8-a/E8-b spike experiments and by live manual testing.

The core relay mechanism (capture, forward through UDP ASSOCIATE, reinject inbound, no observed processing loop) was validated by the E8-a/E8-b spike experiments and by live manual testing.

## Encrypted DNS Detection (diagnostic)

Open NetRoute cannot relay encrypted DNS — the queries are inside TLS. It can, however, **name** the encrypted resolver in use, which turns "my leak test shows resolvers I don't recognize" into an actionable fact.

`DnsSniInspector` opens a WinDivert handle in **SNIFF mode** (`SNIFF | RECEIVE_ONLY`) on `outbound and ip and tcp and tcp.DstPort == 443 and not loopback` and reads the TLS ClientHello's SNI extension (RFC 6066 §3). The ClientHello is sent in the clear by design — the server hostname must be readable before session keys exist — so no decryption is involved and no content is inspected.

**It cannot affect routing.** A sniff handle *copies* each matching packet to this process and lets the real packet continue untouched. It cannot consume, delay, reorder, inject or drop anything, so it cannot be the cause of a leak and cannot break the tunnel. It runs only while the DNS relay is on, and its failure costs visibility, never connectivity.

When a connection to a known public resolver endpoint is seen, the log and the Data Usage tab name the process, the destination and the resolver:

```text
[Sni] ENCRYPTED DNS (DoH) detected: chrome.exe (192.168.1.5:51234 -> 104.16.248.1:443)
      resolving via https://chrome.cloudflare-dns.com/ — this resolver is NOT relayed through the proxy.
```

### Honest limits of this detection

These are real blind spots, not edge cases to be waved away:

| Limit | Effect |
|---|---|
| **Encrypted ClientHello (ECH)** | The hostname is genuinely unreadable without keys. Counted as a **blind spot** and surfaced, so the gap is visible instead of silently missing. A zero here does not prove there is no DoH. |
| **DoH over QUIC / HTTP3** | QUIC does not use a TLS-over-TCP ClientHello. UDP/443 DoH is **not observable** by this inspector. |
| **Self-hosted DoH** | A resolver on an arbitrary hostname is not in the known list. Its SNI *is* read and traced, but it is not classified as a resolver. |
| **Only TCP** | QUIC (§ above) and any non-TLS payload on 443 are not classified. |

Matching is **exact hostname** only — never a substring, suffix or "strip `www.`" match. Looser matching is actively harmful here: `www.cloudflare.com` is ordinary web traffic, and for a user whose proxy egress is Cloudflare a suffix match would report every page load as a leak. A false positive trains the user to ignore the warning, which is worse than missing a leak. The list therefore contains resolver endpoints only, never a CDN or hosting range.

### Reading the counters

The Data Usage tab shows the relay's counters and the observer's result:

```text
Active · captured 412 · relayed 410 · replies 410 · failed 2 · dropped 0 · IPv4+IPv6
Encrypted-DNS observer: 87 TLS handshake(s) seen · 3 to a known encrypted resolver · 0 unreadable
```

* `relayed` close to `captured` → the plaintext relay is working.
* `> 0 to a known encrypted resolver` → at least one app resolved names through an encrypted channel this app cannot relay. **That is not automatically a plaintext leak**: if the resolver is itself Cloudflare or Google and its traffic goes through the proxy, the leak test will show those resolvers while your exit IP is still hidden.
* `N unreadable` → N ClientHellos could not be classified (ECH, or a truncated capture). Reported so the blind spot is knowable. Only handshake records are counted here — ordinary uploads and ACKs on 443 are ignored, so this is not a proxy for "traffic volume".

`TLS handshake(s) seen` counts ClientHello records, not distinct TCP connections: a ClientHello retransmitted after a timeout is counted again. It is a volume indicator.

Detection is a **diagnostic, not a block**. Nothing is dropped or altered by the inspector.

## DNS Leak Limitations

Encrypted DNS remains out of scope **as a relay path**, because it cannot be relayed at the packet layer:

### DNS-over-HTTPS

DoH sends DNS queries inside an HTTPS request. The query is encrypted, so a UDP/53 interception mechanism cannot identify it. An application using DoH resolves through its own encrypted resolver, and the resolver sees the query — not the local DNS path.

### DNS-over-TLS and DNS-over-QUIC

DoT wraps DNS in a TLS connection and DoQ carries it over QUIC. Neither exposes a plaintext UDP/53 request. Both bypass the relay.

### Other sources of apparent exposure

* applications shipping a custom resolver protocol on a non-standard port;
* Encrypted ClientHello, which hides the resolver hostname from the observer (counted and surfaced as a blind spot, not silently missed);
* DoH over QUIC/HTTP3 on UDP/443, which carries no TLS-over-TCP ClientHello;
* specialized leak tests that probe for DNS resolvers in ways unrelated to the system's plaintext DNS path;
* traffic generated outside the interception scope.

For this reason, Open NetRoute is described as providing **system-wide plaintext DNS relay with no direct-path fallback**, not as blocking every possible DNS exposure.

## WebRTC, STUN, QUIC, and Other UDP

DNS protection does not prevent other forms of network exposure:

* **WebRTC may use STUN to discover the public address.** Two mutually exclusive options in Settings, working **very differently**:

  | Option | How STUN is recognised | Reliability | Cost |
  |---|---|---|---|
  | **Block WebRTC** (recommended) | **By content, on any port** — the RFC 5389 magic cookie | **Cannot fail open** — needs no proxy UDP support, and does not depend on which port the STUN server uses | **Browser video calls stop working.** With no reachable STUN server WebRTC has no server-reflexive candidate, so Meet / Zoom-in-browser / Discord calls cannot connect |
  | Relay STUN | **By port** — a fixed list, relayed through the proxy so WebRTC reports the proxy's address | Depends on the proxy supporting SOCKS5 **UDP ASSOCIATE**, *and* on the STUN server using a listed port | Keeps video calls working; an unlisted port or a failed relay still leaks |

  Blocking wins when both are enabled — of the two, dropping is the only one that cannot fail open into a direct candidate.

  ##### Blocking matches STUN by content, not by port

  This is the fix for a reported leak, and the distinction matters. Blocking used to filter on **destination port** (`3478/3479`, `5348/5349`, `19302`–`19309`). That is a guess about where STUN servers listen, and it was wrong: the port travels inside the WebRTC server URI, so a server may use any port — and the browserleaks.com WebRTC test uses a non-standard one. The filter matched nothing, nothing was dropped, and the page reported a server-reflexive candidate carrying the real address while the setting read "on".

  Blocking now drops any outbound UDP datagram whose payload is a STUN **address-discovery** message, identified by the RFC 5389 §6 magic cookie `0x2112A442` at offset 4, with the RFC's two-high-bits-zero requirement on the message type. **The port is not consulted at all**, so it does not matter which port a STUN server chose.

  Two deliberate boundaries:

  * **Media is not address discovery.** TURN Data / ChannelData are *not* dropped. Once a relay candidate has been learned, blocking the media that follows changes nothing about disclosure, and dropping it would break a call that is otherwise working.
  * **Cost is real.** Content matching means copying broad UDP traffic into this process to inspect four bytes, proportional to UDP volume. This is why it runs only when WebRTC blocking is enabled and is never a side effect of DNS relaying. Its capture loop is deliberately synchronous and await-free — if the queue overflows while this loop is descheduled, WinDivert drops packets at the driver, which for a broad filter would affect unrelated traffic.

  Both address families are handled. A missing IPv6 handle is a real exposure rather than a cosmetic gap — browsers prefer IPv6 for STUN — so the Data Usage tab says so explicitly when the IPv4 handle is up but the IPv6 one is not.

  ##### What blocking still does not cover

  Blocking STUN removes WebRTC's ability to discover the public address, and the dropped counter on the Data Usage tab proves it is matching. It is **not** proof that no leak path exists:

  * **TURN over TCP/TLS** (port 443, 5349) is TCP, so it is outside a UDP content match. A TURN relay obtained over TCP still reveals the address.
  * **TCP STUN** is likewise not covered.
  * A non-browser application may obtain the public address by other means.

  Those transports are Phase 2. The honest summary: blocking STUN by content closes the leak path that a browser actually exercises, and closes it regardless of port — but "WebRTC is fully blocked" is a stronger claim than this feature makes.

  ##### Verifying that blocking is actually running

  Read the **dropped counter**, not the checkbox. A setting that reads "on" while nothing matches looks exactly like a working setting, which is how a port-matched implementation stayed invisible while leaking.

  | Observation | Meaning |
  |---|---|
  | `[WebRTC] STUN blocking ACTIVE — … ANY port` | The handle is open and matching by content |
  | `blocked STUN datagram #N` with a rising counter | Working. This is the proof |
  | `ACTIVE` but counter stuck at 0 | The block is not matching — the leak is a transport it does not cover |
  | `STUN blocking could not start` | The handle failed; WebRTC is **not** protected and the log says so |
  | No `[WebRTC]` line at all | Blocking was not applied at START — check that the setting reached the engine |

  Absence of the `[WebRTC]` prefix entirely is itself the finding: these components log the moment they open a handle, so a complete lack of lines means they never ran rather than that they ran and matched nothing.

  ##### Relaying, by contrast, is port-based

  Relayed STUN keeps its **original destination**. It is deliberately *not* subject to the DNS resolver override: redirecting STUN to `1.1.1.1:19302` guarantees no reply, so the injection times out and the client silently keeps its direct STUN — i.e. its real IP. That bug made the feature self-sabotaging while reporting itself as enabled, and it is now covered by tests.

  STUN is captured on **both address families** when relaying. The IPv6 handle originally carried DNS only, on the incorrect assumption that STUN is IPv4-only. Browsers resolve AAAA records and then prefer IPv6 for the same STUN server, so on any dual-stack host every STUN request left the IPv4 handle and went out the IPv6 NIC directly — reporting the real address while the setting appeared to be working. Both handles now carry the same port set.

  The relay port set (`3478/3479`, `5348/5349`, `19302`–`19309`) is a **default, not a guarantee**, which is the main reason blocking is the recommended option. Traffic outside the set still leaks, and the UI reports the capture/relay/failure counters so "captured nothing" is distinguishable from "relaying is off".

  ##### How the two interact

  Only one component may own a given packet: two diverting handles matching the same datagram is a race over who re-injects it, not redundancy. Blocking is handled by its own dedicated handle, and the DNS/STUN ferry captures STUN **only when relaying it**. Both options are **independent of the DNS relay**, so WebRTC protection works with DNS relaying off. Coupling them (as an earlier revision did, behind a single `if (Dns.Enabled)`) made the STUN checkbox silently inert whenever the DNS relay was off: the setting read "on" while the UDP capture handles were never opened. The Data Usage tab reports the three states — blocked, relaying, unprotected — separately, and reports blocking as active only when a handle is genuinely open.
* QUIC carries application traffic over UDP without a traditional TCP connection — including DoH over HTTP/3, which is why QUIC-based encrypted DNS is invisible to the SNI observer.
* Applications may use custom UDP protocols or establish direct connections outside the handled patterns.

These are separate from DNS and need their own handling if complete traffic privacy is the goal.

## Scope

* **Intercepted and relayed:** plaintext DNS on UDP/53 and TCP/53, IPv4 and IPv6, system-wide.
* **Fail-closed:** unparsable packets, relay failures, and relay unavailability all drop the query rather than sending it directly.
* **Cache-safe:** the Windows resolver cache is flushed at START and STOP.
* **Observed and named:** DoH endpoints on TCP/443 are identified by their ClientHello SNI. Nothing is blocked or altered.
* **Not intercepted:** DoH, DoT, DoQ, DoH-over-QUIC, and custom resolvers on non-standard ports.
* **Not equivalent to:** a full-system VPN DNS isolation mechanism.

## Troubleshooting

If an application appears to bypass the DNS relay:

1. **Check the Data Usage tab's DNS block first.** `relayed` close to `captured` means plaintext DNS is being relayed; `> 0 to a known encrypted resolver` names the app and the resolver that bypassed it.
2. Check whether it uses plaintext DNS at all — a DoH-configured browser never touches UDP/53.
3. Check for a custom resolver on a non-standard port.
4. Confirm the relay is Active: the status line reports a probe result at START, and the Debug log shows each relayed query. A query line reads `relaying via proxy to 1.1.1.1:53 (resolver override: 203.0.113.53 -> 1.1.1.1)` — both addresses are logged, so you can see what the app asked for *and* what it actually got.
5. Look for `relay FAILED` or `dropped (fail-closed)` entries — these mean the query was **blocked, not leaked**, and usually point at a proxy without UDP support.
6. Check for `IPv6 capture unavailable` — on a dual-stack host this means IPv6 DNS could not be captured and is a genuine exposure.
7. A failed lookup takes a couple of seconds (relay timeout plus the client's own retries), which is normal.

### Reading a leak-test result

A leak test lists the resolvers that answered, which is not the same thing as the resolvers that leaked your IP. With the relay active:

* **The configured override's operators appearing (Cloudflare/Google) is the relay working.** If your override is `8.8.8.8`, any Cloudflare entry in the result came from a path that bypassed the relay entirely — the SNI observer will name it.
* **Your ISP's resolvers appearing means plaintext DNS escaped** somewhere: the IPv6 TCP/53 gap (now closed), Windows' own encrypted DNS, or a browser's secure-DNS setting.
* **A WebRTC entry means STUN/ICE escaped.** Read the WebRTC line on the Data Usage tab first: `BLOCKING` with a non-zero dropped count means the listed ports are handled and the leak is TURN or an unlisted STUN port; `relaying` with 0 captured means the STUN server used a port outside the set; `unprotected` means neither option is on. A correct local IP alongside a leaked public IP is expected — the local candidate is always available and is not the leak.

## Future Improvements

* optional blocking of known encrypted-DNS endpoints (forces fallback to relayed plaintext DNS, at the cost of breaking those endpoints);
* broader resolver attribution for diagnostics;
* more comprehensive leak testing across applications and Windows configurations.
