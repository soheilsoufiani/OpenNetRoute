# Architecture Research — Process-Based SOCKS5 Routing for Windows

**Status:** Research / analysis only — no implementation
**Date:** 2026-08-20 (revised to align with `CLAUDE.md`)
**Authoritative project instructions:** `CLAUDE.md`
**Reference material analyzed:** [TunnelX](https://github.com/MaxiFan/TunnelX) — TunnelX v2.1.2, GPL-3.0-or-later (upstream repository; no local copy is kept in this repo)

> This document is the output of a research phase. It contains **no application implementation code**, makes **no final architecture commitments**, and **does not copy** any TunnelX source. It distinguishes, throughout, between: **what we learned from TunnelX**, **what we independently propose**, **what is confirmed**, **what is still uncertain**, and **what needs to be tested experimentally**.

---

## 1. Project Goal

Build an open-source Windows desktop application that routes traffic from selected Windows applications through a user-configured SOCKS5 proxy — a lightweight, transparent, user-friendly alternative to applications such as Proxifier.

Requirements (from `CLAUDE.md`):

- Windows 10/11, x64.
- SOCKS5 proxy configured by the user (host, port, optional username/password).
- Per-application rules (executable name / path) with proxy-vs-direct decision.
- **TCP only** for the first routing engine. No UDP tunneling, no DNS interception initially.
- **Process-based traffic selection** — the user must NOT need to configure proxy settings inside each application.
- Simple WPF GUI, tray, structured logging, JSON config.
- Testing: xUnit; integration tests against a **local SOCKS5 test server** (no real external proxy required).
- Distribution: open-source, **MIT license for our code** (per `CLAUDE.md` "Open Source" section).

**Stack (fixed by `CLAUDE.md`):** C# / .NET 10 / WPF / WinDivert / SOCKS5 / xUnit / Microsoft.Extensions.Logging / Microsoft.Extensions.DependencyInjection / JSON config / dotnet CLI / GitHub Actions.

**Scope guardrail:** The "Current Priority" section fixes the order: correct SOCKS5 → correct process identification → correct WinDivert interception → correct TCP routing → correct rules → DNS behavior → IPv6 behavior → GUI → packaging → docs. A simple GUI over a reliable networking core is explicitly preferred.

---

## 2. What We Learned From TunnelX

### 2.1 What TunnelX is

TunnelX is a mature (~15k LOC, dozens of service classes) Windows **split-tunneling client** that routes selected apps / selected destinations / or the whole system through various VPN cores (L2TP/IPsec, OpenVPN, WireGuard, V2Ray/Xray via sing-box/xray, SOCKS5/HTTP proxy profiles) while keeping local and excluded destinations on the normal network path. The traffic engine we analyzed lives in `AppTunnel/Services/TrafficRouterService.*.cs` (a set of partial classes) plus supporting services.

### 2.2 How TunnelX uses WinDivert

- **WinDivert 2.x**, P/Invoked directly (`Services/Interop/WinDivertInterop.cs`): `WinDivertOpen`, `WinDivertRecv`, `WinDivertSend`, `WinDivertClose`, `WinDivertSetParam`, `WinDivertHelperCalcChecksums`. The `WINDIVERT_ADDRESS` is an 80-byte struct with a packed `LayerEventFlags` uint64 and a union of Network / Flow / Socket fields.
- Layers used: **Network (0)** for packet capture/rewrite/drop and **Flow (2)** for connection tracking.
- Queue tuning via `WinDivertSetParam`: queue length (packets), queue time (ms), queue size (bytes) — raised to absorb bursts.
- The FLOW layer is opened in **SNIFF + RECV_ONLY** mode (flags 0x5) because the flow layer is observe-only; it cannot block connections.
- WinDivert error codes are mapped to actionable messages (driver missing, access denied, invalid filter syntax, blocked driver, driver signature enforcement, service not installed, version mismatch).
- Filters use a literal IP for the VPN server (hostnames make `WinDivertOpen` fail), and a defensive `0.0.0.0` sentinel keeps filters syntactically valid when DNS fails.

### 2.3 How process-based filtering is implemented in TunnelX

Three mechanisms, layered:

1. **FLOW layer `Flow_ProcessId`** (primary) — `TrafficRouterService.FlowTracking.cs` opens a FLOW-layer handle; each `FLOW_ESTABLISHED` event carries the owning **ProcessId directly in the WinDivert address**. This is kernel-provided and authoritative, but fires *after* the connection is established, so it cannot make the first-packet routing decision.
2. **Extended TCP/UDP tables** (fallback at packet time) — `ConnectionProcessCache.cs` / `ConnectionProcessCacheV6.cs` poll `GetExtendedTcpTable` / `GetExtendedUdpTable` (`AF_INET=2`, `AF_INET6=23`, `OwnerPidAll`) at ~300–500 ms, building `(localPort, protocol) → owningPid`, then PID → executable name. Used to classify packets whose tuple is known.
3. **Parent-process walk** — `ResolveTargetOwner` walks up to 8 ancestor hops via `NtQueryInformationProcess`/`PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId` so sockets owned by children (`msedgewebview2.exe` under `WhatsApp.Root.exe`) are attributed to the selected parent.

PID → name and PID → parent caches are cleared periodically (~30 s) to handle **PID reuse**.

### 2.4 How TCP connections are identified and redirected (TunnelX)

- FLOW-layer events identify connections and, for selected apps, TunnelX installs a **`/32` host route** for the destination IP **via the VPN adapter** (`EnsureHostRouteViaVpn`). After that, **Windows itself routes the connection through the VPN** — no per-packet rewriting in the steady state.
- Packet-level handles cover the gaps:
  - `NetworkOutboundLoop` rewrites the **source IP** of first-flight packets to the VPN IP and reinjects on the VPN interface with `IfIdx`/`SubIfIdx` set (needed because sockets that called `connect()` before a route existed stay bound to the physical IP, and Windows **strong-host** enforcement drops them on the VPN interface). This is source-NAT.
  - `NetworkInboundLoop` does **reverse-NAT**: rewrites the destination of inbound VPN packets back to the original physical IP and sets `IfIdx` to the physical interface so the app's original socket receives the reply.
  - A `NAT table` (`ConcurrentDictionary<(proto, srcPort, dstIp), NatEntry>`) remembers original source IP, physical ifIdx, process name, and last-seen. The destination IP is included in the key to survive source-port-reuse collisions.
- Routing decisions re-check per-packet: excluded destinations pass through, included destinations always tunnel, otherwise the process must match a target.

### 2.5 How proxy connections are handled in TunnelX

- TunnelX's `Socks5Server.cs` / `MixedProxyServer.cs` **serve** a local SOCKS5/HTTP proxy (bound to loopback, outbound sockets **bound to the VPN local IP**). It supports SOCKS5 CONNECT (no-auth) + HTTP CONNECT, with `ReadExactAsync`/`PumpAsync` relay, 15 s connect timeout, a one-time retry on `NetworkUnreachable`/`HostUnreachable`, and benign-cancel handling. Domain resolution uses an in-process `DnsResolverCache` with DoH fallback.
- This is the **opposite role** to ours: TunnelX is a SOCKS5 *server*; we need a SOCKS5 *client*. But the wire protocol, timeouts, and relay patterns are directly informative.

### 2.6 Packet reinjection and loop prevention (TunnelX)

- Reinjection is via `WinDivertSend` on the same handle, with `WinDivertHelperCalcChecksums` after any rewrite, and the address's `IfIdx`/`SubIfIdx` set to steer the packet to the desired interface.
- Loop prevention relies on **filter exclusions** (loopback, VPN server IP/port, own local traffic) plus **direction asymmetry**: capture is `outbound`; the reverse-NAT loop rewrites *inbound* VPN packets, and the leak-guard drops *outbound* packets that escaped policy. FLOW filtering excludes `remoteAddr != <vpnServerIp>`.
- A leak-guard handle actively drops packets that exit a non-VPN interface with a VPN source IP (i.e., that escaped the split policy) and may re-install the host route for retransmits.

### 2.7 How DNS is handled in TunnelX

- Packet-level **DNS redirect**: for selected apps, port-53 UDP/TCP to private/system resolvers is rewritten to a public resolver (`8.8.8.8`/`1.1.1.1`) and egressed through the tunnel; the response's source IP is **spoofed back** to the original resolver so the app accepts it.
- `DnsResolverCache`: in-process IPv4 cache (2 min TTL, 20 s negative), DoH fallback (1.1.1.1/1.0.0.1), with bind-to-tunnel for tunnel-only lookups (INCLUDE lists).
- `TrafficRouterService.DnsRuleLearning.cs`: reads DNS question hosts from UDP payloads, parses A answers, matches domain-suffix rules to apply include/exclude at IP granularity.
- System DNS servers are auto-excluded so general traffic uses the physical path.

### 2.8 How IPv4/IPv6 are handled in TunnelX

- IPv4 is the primary path (host routes, NAT, filters all IPv4-first).
- IPv6 for selected apps: a Network-layer `IPv6BlockLoop` captures `outbound and ipv6 and (tcp or udp)`, resolves the owner via the AF_INET6 TCP/UDP tables, and **drops** selected apps' IPv6 packets, then injects a crafted **inbound TCP RST** so Chrome/Edge's Happy Eyeballs immediately falls back to IPv4 instead of stalling on a timeout. UDP IPv6 is silently dropped.
- IPv6 host routes are not added; IPv6 is treated as "not tunnelable" and forced to IPv4 fallback.

### 2.9 Windows APIs used by TunnelX (relevant subset)

| API | Purpose in TunnelX | Our use |
|---|---|---|
| `GetExtendedTcpTable` / `GetExtendedUdpTable` (`iphlpapi.dll`) | connection → owning PID (IPv4 + IPv6) | **Yes** — process→connection mapping |
| `NtQueryInformationProcess` (`ntdll.dll`) + `PROCESS_BASIC_INFORMATION` | parent PID for child-process attribution | **Yes** — parent walk |
| `Process.GetProcessById` / `MainModule` | PID → executable name | **Yes** |
| `WindowsPrincipal.IsInRole(Administrator)` | elevation check | **Yes** |
| `WinDivert*` (`WinDivert.dll`) | capture/inject/filter | **Yes** |
| `CreateIpForwardEntry` / `DeleteIpForwardEntry` (`iphlpapi.dll`) + `route.exe` | /32 host routes via VPN adapter | **No** — we do not touch the routing table |
| `NativeLibrary.SetDllImportResolver` | load WinDivert from writable dir | **Yes** — deployment pattern |

### 2.10 Administrator privileges (TunnelX)

- `app.manifest` declares `requireAdministrator`; `TunnelPrerequisiteService` re-checks elevation at startup and maps WinDivert error 5 ("Access denied") to a clear "run as Administrator" message.
- Route management, WinDivert, and packet interception all require elevation.
- `CLAUDE.md` adds an important refinement for us: detect and *report* insufficient permissions clearly, and **avoid requiring admin for functionality that doesn't need it** (e.g., config, process enumeration, SOCKS5 client).

### 2.11 What we learned about lifecycle/cleanup

- Single-instance mutex + bring-to-front event.
- `ProcessExit` / `UnhandledException` handlers run cleanup (kill orphaned engines, remove VPN profiles, delete temp configs).
- `TunnelXCleanupService` kills leftover sing-box/xray/openvpn/wireguard processes and deletes temp configs.
- Stop path: cancel CTS, close WinDivert handles (this unblocks blocked `WinDivertRecv` calls), await worker loops, remove routes, clear NAT/caches.

---

## 3. What We Independently Propose (and why TunnelX's architecture does not carry over)

### 3.1 The central finding

TunnelX's traffic engine assumes the tunnel is a **routable interface** (a VPN/TUN adapter). Its core trick — install a `/32` host route to the VPN adapter and let Windows forward the connection — is what makes split routing cheap and per-connection.

**A SOCKS5 proxy is not a routable interface.** There is no OS route "to a proxy": the destination IP must be carried *inside* a SOCKS5 handshake over a separate TCP stream. Therefore **TunnelX's route-based engine cannot be adapted to our SOCKS5-only goal.** We keep the *ideas* (FLOW-layer process IDs, TCP-table PID lookup, parent walking, PID-reuse hygiene, IPv6 block+RST, DNS redirect patterns, loop filters, lifecycle discipline) but not the routing machinery.

### 3.2 Proposed architecture (provisional, to be validated by spikes)

A single elevated WPF process hosting a **user-space transparent TCP ferry** driven by WinDivert. **The OS routing table is never modified** — this is the key simplification over TunnelX and what makes clean shutdown nearly trivial.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MyProxy (elevated WPF app)                       │
│                                                                          │
│  ┌──────────────┐   ┌───────────────────┐   ┌────────────────────────┐  │
│  │ WinDivert    │   │ Interception      │   │ Process Router         │  │
│  │ Capture Loop │──▶│ (packet parse,    │──▶│ (SYN decision:         │  │
│  │ NETWORK L4   │   │ flow table,       │   │  selected → hold       │  │
│  │ outbound     │   │ seq-offset ferry) │   │  else reinject)        │  │
│  └──────────────┘   └───────────────────┘   └───────────┬────────────┘  │
│                                                        │ selected       │
│                                                            ▼            │
│  ┌──────────────┐   ┌───────────────────┐   ┌────────────────────────┐  │
│  │ Injected     │◀──│ Ferry / Relay     │◀──│ SOCKS5 Client          │  │
│  │ inbound      │   │ (payload pump +   │   │ (greet, auth, CONNECT,  │  │
│  │ packets      │   │  handshake relay) │   │  IPv4/domain/IPv6)      │  │
│  └──────────────┘   └───────────────────┘   └────────────────────────┘  │
│        ▲                                             │                  │
│        └─────────────────────────────────────────────┼────┐             │
└──────────────────────────────────────────────────────┼────┼─────────────┘
                                                       ▼    ▼
                                   ┌──────────────────────────────┐
                                   │  User-configured SOCKS5       │
                                   │  proxy server (remote)        │
                                   └──────────────────────────────┘
```

This maps cleanly onto the `CLAUDE.md` module layout:

| Project | Responsibility (from `CLAUDE.md`) | Maps to our architecture |
|---|---|---|
| `src/ProxyApp` | WPF UI, tray, settings | GUI shell; **no networking code**; talks to services via interfaces |
| `src/ProxyApp.Core` | Config models, rule models, routing decisions, validation, interfaces | `ProxyConfiguration`, `ApplicationRule`, routing decision logic, result/error types |
| `src/ProxyApp.Network` | SOCKS5 protocol, TCP handling, auth, timeouts, cancellation | **SOCKS5 client** (greet, no-auth/user-pass, CONNECT IPv4/domain/IPv6) + upstream socket lifecycle |
| `src/ProxyApp.WinDivert` | Capture, injection, filtering, connection interception | WinDivert interop wrapper, packet codec, capture loop, flow table, ferry, IPv6 block loop |
| `src/ProxyApp.Processes` | Process enumeration, IDs, names, mapping connections→processes | TCP-table poller, PID→name cache, parent walk — isolated behind interfaces |

Architecture rules from `CLAUDE.md` are honored: UI never touches WinDivert/SOCKS5/packets; WinDivert and process code isolated behind interfaces; networking components support `CancellationToken`; no over-engineering.

### 3.3 Proposed TCP → SOCKS5 model (the "ferry")

Recommended: **transparent TCP ferry with per-connection sequence-offset translation** — the model demonstrated by WinDivert's own `DivertTCPconn` sample and the conceptual ancestor of `redsocks` on Linux. Rationale: it uses WinDivert alone, requires **no routing-table changes**, keeps retransmission/windowing in the kernel (no user-space TCP stack), and leaves no residue on shutdown.

Per-connection lifecycle:

```
Client app                    MyProxy                     SOCKS5 server
   │  SYN (dst=dIP:dP)            │                            │
   │────────────────────────────▶│ (captured, held)            │
   │                             │──── SOCKS5 greet/auth ────▶│
   │                             │──── CONNECT dIP:dP ────────▶│
   │                             │◀── success ────────────────│
   │                             │── TCP SYN (our socket) ───▶│
   │                             │◀── SYN-ACK (ISN_R) ────────│
   │◀── SYN-ACK (seq=ISN_R,      │                            │
   │     ack=ISN_C+1) ───────────│                            │
   │  ACK + payload(seq=ISN_C+1) │                            │
   │────────────────────────────▶│ payload → write socket ───▶│
   │                             │◀── payload (seq=ISN_R+k) ──│
   │◀── pkt(seq=ISN_C+k,         │                            │
   │     ack=ISN_R+…) ───────────│                            │
   │  FIN ──────────────────────▶│ Shutdown(Send) ───────────▶│
   │◀── FIN ─────────────────────│◀── FIN ────────────────────│
```

Design points we commit to (proposal, not yet proven):

- **Hold, don't forward, the client SYN** while the SOCKS5 CONNECT completes. The client retransmits only if we stall > ~1 s; a slow proxy is a risk (see §8 R4).
- **Present the real upstream ISN** in the relayed SYN-ACK. Client ACKs are then already correct, leaving one scalar offset Δ per flow for data/ACK translation.
- **Ferry only payload bytes.** Pure ACKs/keepalives are dropped client→proxy; our own socket's ACKs are kernel-handled. Minimizes header surgery.
- **Timeout/retry** on SOCKS5 CONNECT (e.g., 15 s), benign-cancel handling, one-time retry on `NetworkUnreachable`/`HostUnreachable`.
- **Failure semantics:** SOCKS5 failure → crafted RST to client → app sees `ECONNREFUSED`, not a hang.
- **Cleanup:** per-flow idle timeout and cancellation token; all flows torn down and handles closed on shutdown.

**Documented fallback (if the ferry proves too hard):** rewrite the destination to `127.0.0.1:<localport>` and accept connections on loopback, correlating by source port. This avoids sequence translation but has no `SO_ORIGINAL_DST` equivalent on Windows — recovering the true destination is fragile (port reuse, multiple sockets, apps that inspect their peer). Kept as a documented fallback only.

**Rejected alternatives:**
- **WFP (Windows Filtering Platform) callout driver** (Proxifier's approach) — requires shipping a kernel driver; far beyond WinDivert's user-mode complexity.
- **Wintun/TUN + user-space IP stack (tun2socks/sing-box model)** — robust and proven, but replaces WinDivert with another native component and drags in a full IP/TCP stack.

### 3.4 Proposed DNS strategy

**Phase 6+ / first routing engine (confirmed per `CLAUDE.md`):** leave system DNS in place. Selected apps resolve names normally; the ferry forwards the resolved IP via SOCKS5 CONNECT. Consequences to document, not hide:
- Functionally correct for virtually all TCP apps.
- **Known privacy gap:** selected apps' local DNS queries are visible on the local network (a DNS leak). `CLAUDE.md` Phase 8 explicitly says: "Do not claim 'DNS leak protection' unless it has actually been tested."
- Optional, later: intercept selected-app UDP/53 and answer via the tunnel (SOCKS5 UDP ASSOCIATE or DoH over the proxy), plus correlate `domain → IP` to issue SOCKS5 CONNECT with ATYP=3. This is a **later** phase, not v1.

### 3.5 Proposed IPv4/IPv6 strategy

- **IPv4: first-class.** All interception, flow tables, and SOCKS5 CONNECTs are IPv4.
- **IPv6 (Phase 9):** decide explicitly and document. Recommended option: block selected-app IPv6 at the network layer and inject a crafted inbound TCP RST so Happy Eyeballs falls back to IPv4 fast (TunnelX proves this works). Non-selected IPv6 untouched. SOCKS5 ATYP=4 (IPv6 destination) is out of v1 scope.
- `CLAUDE.md` Phase 9 requires deciding, documenting, and testing: supported / proxied / disabled / rules-applied-to-IPv6. Never silently assume IPv6 behaves like IPv4.

---

## 4. Components We Do NOT Need (from TunnelX)

Large parts of TunnelX exist to support its multi-VPN-core, full-route, geo/history/UI feature set. Not needed for our SOCKS5-only app:

- **All tunnel providers** — `L2tpTunnelProvider`, `VpnService`, `OpenVpnTunnelProvider`, `WireGuardTunnelProvider`, `V2RayTunnelProvider`, `XrayTunnelProvider`, `TunnelProviderFactory`, `ITunnelProvider`. We have no VPN.
- **sing-box / xray-core / wintun** — native engine execution, config generation, `NativeEngineSupport`, `V2RayEndpointHelper`, `V2RayWebSocketHelper`, `WireGuardConfigParser`, `WireGuardHandshakeDiagnostics`.
- **Full-route mode**, **include/exclude destination lists**, the entire `DestinationParsing` / `IncludeDestinations` / `ExcludeDestinations` / `RefreshDestinationLists` machinery, `DnsRuleLearning` domain rules, `IpGeoLookupService`, exit-IP/flag lookups, `HistoryService`, traffic counters/dashboard.
- **The host-route engine** — `EnsureHostRouteViaVpn`, `TryRemoveHostRoute`, `ScheduleDelayedRouteRemoval`, `_addedRoutes`, `route.exe` management, `IpHelperInterop`. *Not needed because our ferry model never touches the routing table — which also means we never leave stale routes behind.*
- **The local VPN-bound SOCKS5/HTTP mixed proxy** — TunnelX *serves* a local proxy; we are a *client* to a remote SOCKS5.
- **Leak-guard / source-NAT for a VPN IP** — no VPN IP exists in our design. Loop prevention is simpler (see §6).
- **Localization** (Persian/English, RTL/LTR), themes, donation/Telegram/update-checker services, `GitHubReleaseChecker`, `ChangelogService`, `Socks5LatencyProbe`, L2TP/VPN-profile cleanup, `ConnectionPingSupport`, `LocalPortReservation`, most of the WPF view/view-model layer.

---

## 5. Confirmed Findings

| # | Finding | Status |
|---|---|---|
| C1 | WinDivert is the correct user-mode packet-interception mechanism on Windows 10/11; its FLOW layer exposes `Flow_ProcessId` directly. | **Confirmed** from TunnelX + WinDivert docs (still verify with a live spike) |
| C2 | `GetExtendedTcpTable`/`GetExtendedUdpTable` (OwnerPid) can map connections → owning PID; IPv6 uses AF_INET6 tables. | **Confirmed** (TunnelX; documented Windows API) |
| C3 | A single SYN packet cannot be attributed to a process *from the packet alone*; correlation with connection tables is required. (`CLAUDE.md` Phase 5 states this explicitly.) | **Confirmed** |
| C4 | SOCKS5 wire protocol: greeting → method selection (no-auth / user-pass) → CONNECT (ATYP IPv4/domain/IPv6) → reply. | **Confirmed** (RFC 1928 + TunnelX server code) |
| C5 | WinDivert requires Administrator for packet interception; error 5 = access denied; driver must be present/loadable. | **Confirmed** (TunnelX + WinDivert docs) |
| C6 | The OS routing table cannot express "route to a SOCKS5 proxy." A transparent proxy must be implemented at the connection level in user space. | **Confirmed** (networking principle) |
| C7 | We will **not** use TunnelX's route-based engine, host routes, VPN NAT, or any VPN-provider code. | **Confirmed decision** |
| C8 | License: TunnelX is GPL-3.0-or-later; WinDivert is dual LGPL-3.0-or-later / GPL-2.0. Our code will be MIT (per `CLAUDE.md`). | **Confirmed** (see §7) |
| C9 | The app must clearly detect/report insufficient admin privileges and not fail silently. | **Confirmed** (from `CLAUDE.md`) |

---

## 6. Loop Prevention (proposed)

Layered, structural:

1. **Direction asymmetry (primary):** the capture filter is `outbound`; every packet we *craft* and inject is marked **inbound** (outbound bit cleared, `IfIdx`/`SubIfIdx` = client's interface). WinDivert will not re-hand us our own injections. Same trick TunnelX's reverse-NAT path relies on.
2. **Filter-level excludes (reduce load/risk):** exclude `loopback`, the resolved proxy server IP, and (as an optimization only) the configured proxy port.
3. **Upstream-socket recognition (correctness):** maintain the set of live upstream sockets by local `(IP, port)`; any captured packet whose source matches an upstream socket is reinjected unchanged immediately — our SOCKS5 stream is never consumed by the ferry. This is precise regardless of which proxy port/address the user configured.
4. **Process-identity backstop:** if a packet's owning process resolves to our own executable (or its children), reinject unchanged.
5. **Never modify the routing table** — no route-based loop to leak into.
6. `CLAUDE.md` Phase 4 requires: *"The application must never accidentally create an infinite capture/injection loop"* and *"all injected packets must be distinguishable from intercepted packets when necessary."* The design above satisfies both (inbound-marking + upstream-socket set).

**Needs experimental testing:** the exact behavior of injected packets on Wi-Fi vs. Ethernet interfaces, and whether inbound-marked injections are ever re-presented to an outbound filter on the same handle.

---

## 7. License Analysis

**TunnelX (reference):**
- TunnelX is **GPL-3.0-or-later** — see the [upstream LICENSE](https://github.com/MaxiFan/TunnelX/blob/master/LICENSE).
- Its bundled third-party components keep their own licenses (`THIRD_PARTY_NOTICES.md`): WinDivert (LGPL-3.0-or-later or GPL-2.0), sing-box (GPL-3.0-or-later), xray-core (MPL-2.0), Wintun (WireGuard license terms), CommunityToolkit.Mvvm (MIT), .NET/WPF (MIT), Vazirmatn font (SIL OFL 1.1).

**What this means for our project:**
- **We may reuse:** ideas, architecture observations, and documented behaviors described in this document. Facts about WinDivert's API, the SOCKS5 protocol, and Windows IP Helper APIs are governed by their own licenses/documentation, not by TunnelX's GPL.
- **We must not:** incorporate, adapt, or mechanically port TunnelX's code into our repo; copy its file structure/class implementations; or embed its GPL-licensed source into a non-GPL project. If any portion of TunnelX source were ever reused, the derivative would fall under GPL-3.0-or-later — which we avoid by independent implementation.
- **Our code:** per `CLAUDE.md`, **MIT** (permissive default). Third-party dependencies must have licenses compatible with MIT.
- **WinDivert redistribution:** if we ship `WinDivert.dll`/`WinDivert64.sys`, we must (a) use the official signed binaries, (b) retain their license/copyright notices, and (c) satisfy the LGPL/GPL notices for the DLL/driver. We should document this in our own `THIRD_PARTY_NOTICES.md`. The LGPL dual-license also means the user may choose GPL-2.0 terms — either way, notice obligations apply.
- **Independent-implementation baseline:** Windows API documentation (WinDivert docs / `DivertTCPconn` sample concepts, `GetExtendedTcpTable`, `NtQueryInformationProcess`), SOCKS5 RFC 1928, and general networking principles. Any similarity to TunnelX should be at the level of "same well-known technique," not "same code."

**Confirmed:** we will document dependencies and their licenses (`CLAUDE.md` "Open Source" section) and will not copy source without checking license/attribution.

---

## 8. Technical Risks and Unknowns

| # | Risk / unknown | Impact | Needs testing? | Mitigation plan |
|---|---|---|---|---|
| R1 | **SYN-before-PID race** — first captured SYN before the socket row appears in `GetExtendedTcpTable`. | Silent leak or mis-route of a selected app's first connection. | **Yes — measure race window in a spike** | Cached `(localPort)→PID` refresher; double-query; optional short hold; FLOW-layer correction for counters; **fail-to-direct default**. |
| R2 | **Seq-offset translation vs. real TCP options** — timestamps (TSval/TSecr), window scaling, SACK, MSS across the ferry. | Corrupted streams / stalls if options mismatch. | **Yes — validate with a real client** | Decide TS policy (translate by Δ or strip); pass window-scale consistently; clamp MSS; extensive unit + real-server tests. |
| R3 | **Crafted inbound-packet injection ABI** — injected SYN-ACK/data accepted by a real client socket on the client's interface. | Packets dropped by client stack if injection is subtly wrong. | **Yes — first spike** | Validate on physical NIC and Wi-Fi before building the ferry. |
| R4 | **Holding the client SYN during SOCKS5 connect** — slow/failed proxy. | Client SYN retransmit storms / timeouts. | **Yes** | Hold < ~1 s expected; crafted RST on failure; retry-once for unreachable; document proxy-latency behavior. |
| R5 | **DNS leak in first engine** — selected apps' system DNS visible locally. | Privacy gap. | **Yes — document, don't claim protection** | Explicitly documented; DNS interception is a later phase (per `CLAUDE.md`). |
| R6 | **QUIC / UDP/443 bypass** by selected browsers. | Selected app bypasses proxy over UDP. | **Yes** | v1 is TCP-only; decide & document whether to drop selected-app UDP/443 (force HTTP/2) or accept the bypass. |
| R7 | **IPv6** — block-only proposal; AAAA lookups may still succeed locally. | Partial leak / behavior surprises. | **Yes** | Block + RST; empty-AAAA in a later DNS phase. |
| R8 | **PID reuse** — stale cached name attributed to a recycled PID. | Wrong app attributed → wrong routing. | **Yes** | Periodic invalidation (~30 s), selection-change invalidation, short-lived PID→name cache. |
| R9 | **Elevation boundary** — non-elevated selected apps observable; higher-integrity processes not. | Some processes can't be classified. | — | Document; classify-as-direct for unobservable PIDs. |
| R10 | **WinDivert driver in CI** — install/load on GitHub Actions runners. | CI can't run integration tests. | **Yes** | Elevate runner, install driver as a setup step; keep unit tests driver-free so CI never fully blocks. |
| R11 | **Performance** — per-packet user-space copies. | Throughput ceiling. | **Yes — measure early** | Queue-param tuning, allocation-free hot path, batch reads; acceptable for a lightweight tool. |
| R12 | **Apps that introspect their peer address** or bind specific local IPs. | Breakage for a small class of apps. | — | Transparent ferry preserves peer address (client still sees real dst); document exceptions. |
| R13 | **Crash residue** — in-flight flows at crash time. | Orphan sockets until OS reaps; no routing residue by design. | — | `ProcessExit`/unhandled-exception handlers close upstreams; OS cleans the rest; single-instance guard. |
| R14 | **License/redistribution of WinDivert binaries** (LGPL-3.0 / GPL-2.0 dual). | Distribution obligations. | — | Official signed driver + retained notices + `THIRD_PARTY_NOTICES.md`. |

---

## 9. Recommended Development Phases

Ordered per `CLAUDE.md`'s phase list and de-risked (R1–R3 spike first). The exact project names come from `CLAUDE.md`:

1. **Phase 0 — Repository & architecture:** `.gitignore`, solution, projects (`src/ProxyApp`, `ProxyApp.Core`, `ProxyApp.Network`, `ProxyApp.WinDivert`, `ProxyApp.Processes`), test projects (`ProxyApp.Core.Tests`, `ProxyApp.Network.Tests`, `ProxyApp.IntegrationTests`), README, LICENSE (MIT), initial docs. `dotnet build` and `dotnet test` must succeed. **No packet interception yet.**
2. **Phase 1 — Configuration:** `ProxyConfiguration` (host, port, username, password, auth type), `ApplicationRule` (executable path/name, enabled, proxy mode). Document password-storage security implications; prefer Windows credential storage if practical.
3. **Phase 2 — SOCKS5 client:** TCP CONNECT, IPv4/IPv6/domain, no-auth + user-pass, timeouts, cancellation, disposal. Unit tests: negotiation, auth, invalid credentials, domain/IPv4/IPv6 destination, rejection, timeout, cancellation, malformed responses. **Must be independently testable before proceeding.**
4. **Phase 3 — Process discovery:** enumerate processes (PID, name, path); handle access-denied, terminating processes, missing paths, 32/64-bit. UI list like `Chrome / chrome.exe / C:\...\chrome.exe`. **Do not redirect traffic yet.**
5. **Phase 4 — WinDivert integration:** Open/Close/Receive/Send/Filtering/Cancellation/error reporting behind a clean interface. Prove safe capture+log in a controlled environment. **Never create an infinite capture/injection loop; injected packets distinguishable from intercepted.** Do NOT implement SOCKS5 routing yet.
6. **Phase 5 — Process-to-connection mapping:** determine owning process from `(PID, local IP, local port, remote IP, remote port, TCP state, IPv4/IPv6)` via Windows APIs; correlate packets with connection tables; document race conditions.
7. **Phase 6 — TCP redirection engine (ferry):** selected process → TCP connection → SOCKS5 proxy → destination. TCP CONNECT only. No UDP, no transparent UDP, **no DNS interception yet.** Keep it simple and observable.
8. **Phase 7 — Application rules:** `chrome.exe → Proxy`, `firefox.exe → Proxy`, `game.exe → Direct`; executable path + name; enabled/disabled; proxy/direct mode; document precedence/evaluation order.
9. **Phase 8 — DNS:** explicitly design DNS behavior; avoid unintentional leakage when the destination is supposed to use the proxy; analyze local DNS, remote DNS through SOCKS5 domain resolution, IPv4/IPv6, apps that do their own DNS, DoH, DoT. **Never claim DNS leak protection unless actually tested.**
10. **Phase 9 — IPv6:** explicitly test; decide supported / proxied / disabled / rules behavior; never silently assume IPv6 behaves like IPv4.
11. **Phase 10 — GUI:** WPF only after networking core is functional; simple main screen (proxy config, apps list, refresh, status, START/STOP); responsive, never block UI thread.
12. **Phase 11 — Tray:** minimize to tray, start/stop, status, exit, optional auto-start (not mandatory).
13. **Phase 12 — Logging:** structured (Microsoft.Extensions.Logging); log startup, config validation, proxy attempts, SOCKS5 negotiation, failures, process matching, rule decisions, WinDivert errors, shutdown. Never log passwords/credentials/authentication secrets.

---

## 10. Experimental Tests to Run Before/During Implementation

These convert the "uncertain" items into confirmed/denied decisions:

1. **WinDivert spike (Phase 4/6):** capture a real SYN from a known client (e.g., `curl.exe`); inject a crafted SYN-ACK; confirm the client accepts it and the connection proceeds. Repeat on Ethernet and Wi-Fi. *(R2/R3)*
2. **Attribution latency:** for a synthetic burst of short-lived connections, measure how often the first SYN is (not) present in `GetExtendedTcpTable`; calibrate the cache/double-query strategy. *(R1)*
3. **TCP option behavior:** connect through the ferry to a local test server; verify data integrity with TS/WS/SACK enabled and disabled; confirm which options must be stripped/clamped. *(R2)*
4. **Injection distinguishability:** verify inbound-marked injections are never re-presented to the outbound capture loop on the same handle. *(R3/R6 loop prevention)*
5. **SOCKS5 edge cases:** malformed replies, server closing mid-negotiation, slow CONNECT (simulate with the local test server), IPv6 destination. *(Phase 2)*
6. **PID-reuse simulation:** rapidly spawn/terminate a same-named process and confirm the cache invalidates and routing stays correct. *(R8)*
7. **CI feasibility:** WinDivert driver install/load on a GitHub Actions `windows-latest` runner. *(R10)*
8. **Cleanup:** kill the app mid-session; confirm no dangling upstream sockets, no routing changes, no leftover handles. *(R13)*

---

## 11. Summary

1. **TunnelX's traffic engine is VPN-interface-based** (FLOW-layer tracking + `/32` host routes + source-IP NAT). Its central technique cannot carry over to SOCKS5, because a SOCKS5 proxy is not a routable interface.
2. **The required model for our app is a user-space transparent TCP ferry** (capture SYN → decide by process → hold → establish SOCKS5 CONNECT → relay handshake with a single sequence offset → ferry payload bytes → inject replies inbound). This is the proven `DivertTCPconn`/`redsocks` family of designs and is the natural fit for a WinDivert-only, SOCKS5-only, no-routing-table-change tool.
3. **What TunnelX contributes to us is technique, not architecture:** FLOW-layer process IDs, extended-TCP-table PID lookup, parent-process walking for child sockets, PID-reuse cache hygiene, IPv6 block + RST injection, DNS redirect patterns (for a later phase), loop prevention by direction asymmetry, and admin/cleanup discipline.
4. **What TunnelX drags in that we must leave behind:** every VPN core, full-route and destination-rule engines, route-table GC machinery, traffic/geo/history dashboards, localization/theming, native engine management.
5. **The hard problems are real and identifiable:** SYN-time process attribution (R1), sequence/option translation across the ferry (R2), crafted-packet injection ABI (R3), DNS leaks (R5), QUIC/IPv6 bypass (R6/R7), PID-reuse races (R8). All have concrete mitigation plans and experimental tests.
6. **Legal posture is clean:** no TunnelX source is reused; our code is MIT; WinDivert redistribution obligations are manageable with the official signed driver plus retained notices.

### Uncertainties to resolve before implementation begins

1. **Can we reliably attribute a captured SYN to its owning process at packet time?** Measure the `GetExtendedTcpTable` race window with a spike; confirm the cache + double-query strategy covers typical first-packet latency. **(R1)**
2. **Does relay-with-offset survive real TCP option negotiation (timestamps, window scaling, SACK, MSS)?** Decide and validate TS policy and option pass-through in the Phase 4 spike. **(R2)**
3. **Will crafted inbound SYN-ACK/data packets be accepted by a real client socket when injected with the client's interface `IfIdx` and an inbound flag?** Validate on both a physical NIC and Wi-Fi before building the full ferry. **(R3)**
4. **Is holding the client SYN for a SOCKS5 connect acceptable** for real-world proxy latencies, including slow or failing proxies? **(R4)**
5. **v1 scope decisions:** QUIC (drop selected-app UDP/443 or accept the bypass) and the documented DNS leak (accept now, fix in a later phase). **(R5/R6)**
6. **IPv6 policy:** block selected-app IPv6 + RST is the recommendation; confirm no selected app breaks worse with IPv6 blocked than with it leaking. **(R7)**
7. **CI feasibility:** verify WinDivert driver install/load on GitHub Actions `windows-latest` so integration tests are sustainable. **(R10)**
8. **WinDivert binary provenance and licensing** for redistribution (official signed pair, exact version, retained notices). **(R14)**

---

*This document will be kept in `docs/` and updated as the experimental tests resolve the uncertainties above. No application source code was written; no dependencies were installed; no source files were modified.*
