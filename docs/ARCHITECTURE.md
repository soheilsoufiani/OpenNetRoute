# Open NetRoute Architecture

## Overview

Open NetRoute is a Windows desktop application that routes traffic from selected applications through a user-configured SOCKS5 proxy while leaving non-selected applications on their normal network path.

The application does not create a VPN interface and does not modify the Windows routing table. Instead, it uses WinDivert to observe and intercept selected network traffic and a user-space forwarding layer to relay that traffic through the configured SOCKS5 proxy.

The architecture is designed around application-level routing rather than system-wide routing.

## High-Level Architecture

The main traffic path is:

```text
Selected Application
        │
        ▼
    WinDivert
        │
        ▼
Process / Flow Attribution
        │
        ▼
Traffic Router
        │
        ▼
User-Space TCP/UDP Ferry
        │
        ▼
   SOCKS5 Proxy
        │
        ▼
     Internet
```

Traffic from applications that are not selected for proxying is allowed to continue through the normal Windows networking stack.

## Core Components

### WinDivert Capture

WinDivert provides user-space packet capture and reinjection on Windows.

Open NetRoute uses WinDivert to:

* capture relevant outbound traffic;
* inspect packet metadata;
* associate traffic with the originating process where possible;
* selectively intercept traffic that should be proxied;
* reinject packets when required.

The application requires elevated privileges because packet interception and reinjection through WinDivert require administrator-level access.

## Process Attribution

Open NetRoute needs to determine which application owns a network flow before deciding whether that flow should be proxied.

For TCP connections, process attribution can be obtained from Windows networking information such as the extended TCP table. The implementation also accounts for the fact that process ownership information may not be immediately available at the exact moment a packet is observed.

The routing decision is therefore based on the application/process associated with the connection rather than only on the destination address.

## TCP Proxying

Selected TCP connections are handled by a user-space ferry.

At a high level:

1. An outbound connection attempt is captured.
2. The originating process is identified.
3. The application routing rules determine whether the connection should be proxied.
4. A SOCKS5 connection is established to the configured proxy.
5. The local TCP flow and the SOCKS5 connection are bridged in user space.
6. Data received from the proxy is injected back toward the originating application.
7. Data from the application is forwarded through the SOCKS5 connection.

The implementation performs the required TCP sequence handling when packets are intercepted and reconstructed.

This approach avoids requiring the SOCKS5 proxy to behave like a network gateway or Windows routing interface.

## SOCKS5

Open NetRoute communicates with the configured proxy using the SOCKS5 protocol.

The proxy connection supports the normal SOCKS5 connection flow:

```text
Open NetRoute
      │
      ├── SOCKS5 negotiation
      │
      ├── Authentication, when configured
      │
      └── CONNECT target
               │
               ▼
          SOCKS5 Proxy
               │
               ▼
            Target
```

The SOCKS5 proxy remains external to Open NetRoute. Open NetRoute is responsible for translating selected local application traffic into SOCKS5 connections.

## UDP and DNS

Plaintext DNS is handled separately from the TCP ferry, and is intercepted on **both** of its transports:

| Transport | Capture | Relayed via |
|---|---|---|
| UDP/53, IPv4 | `outbound and ip and udp and udp.DstPort == 53` | SOCKS5 UDP ASSOCIATE |
| UDP/53, IPv6 | `outbound and ipv6 and udp and udp.DstPort == 53` | SOCKS5 UDP ASSOCIATE |
| TCP/53, IPv4 | the TCP ferry's capture filter, with port 53 as a forced-proxy port | SOCKS5 CONNECT |
| TCP/53, IPv6 | a second TCP-ferry handle, `outbound and ipv6 and tcp and tcp.DstPort == 53` | SOCKS5 CONNECT |

Each address family needs its own handle because a WinDivert filter expression cannot mix `ip` and `ipv6`. The TCP leg exists because Windows falls back to TCP/53 for truncated answers and some resolvers are TCP-only; the UDP leg alone would leave those queries on the direct path.

The IPv6 TCP handle is scoped to DNS only. The general TCP ferry stays IPv4-only — extending IPv6 capture to all traffic would change routing for every selected application, which is a separate decision. Because a WinDivert handle only admits packets its own layer and filter accept, each flow records the handle its SYN arrived on (`FlowState.SendHandle`) and every injection toward that flow goes through it.

Both legs are **system-wide**. Windows generates app DNS in the DNS Client service (`svchost`, `dnscache`), so a per-application gate would never match the selecting process.

The DNS path is approximately:

```text
Application
    │
    ▼
Plaintext DNS query (UDP/53 or TCP/53, IPv4 or IPv6)
    │
    ▼
WinDivert
    │
    ▼
DNS relay
    │
    ▼
SOCKS5 (UDP ASSOCIATE or CONNECT)
    │
    ▼
Configured DNS server
    │
    ▼
DNS response
    │
    ▼
Application
```

Relay failures are **fail-closed**: an unparsable packet, an unavailable association, or a timeout all drop the query instead of releasing it directly. The Windows resolver cache is flushed at START and STOP so pre-START answers cannot be served without interception.

### Encrypted DNS: observed, not relayed

A separate **passive** component, `DnsSniInspector`, opens a handle in `SNIFF | RECEIVE_ONLY` mode on outbound TCP/443 and reads the TLS ClientHello's SNI extension. That hostname is sent in the clear by design (RFC 6066 §3 — the server name must be readable before session keys exist), so no decryption is involved.

Sniff mode is what makes it safe: the handle **copies** matching packets and lets the real ones continue. It cannot consume, delay, reorder, inject or drop, so it cannot affect routing, cannot break the tunnel, and cannot itself cause a leak. It runs only while the DNS relay is on, and its failure costs visibility rather than connectivity.

When a connection to a known resolver endpoint is seen, the log and the Data Usage tab name the process, destination and resolver. This turns "the leak test lists resolvers I don't recognize" into a specific fact. It is a diagnostic — nothing is blocked.

Its limits are real: Encrypted ClientHello hides the hostname entirely (counted and surfaced as a blind spot), and DoH over QUIC/HTTP3 carries no TLS-over-TCP ClientHello at all. Hostname matching is exact-only, because a suffix match would flag `www.cloudflare.com` as a leak — and for a user whose proxy egress is Cloudflare that would report every page load as a problem.

What remains outside interception is encrypted DNS (DoH/DoT/DoQ) and custom resolvers on non-standard ports — these cannot be relayed without TLS interception.

### WebRTC/STUN: blocked by content, relayed by port

A third, deliberately separate component, `StunBlocker`, exists because **matching STUN by port does not work**. The port travels inside the WebRTC server URI, so a STUN server may listen anywhere; a port list looks correct, matches nothing, and silently leaks. `StunMessage.IsStun` instead identifies a STUN address-discovery message by the RFC 5389 §6 magic cookie `0x2112A442` at offset 4, plus the spec's two-high-bits-zero requirement on the message type. The port is never consulted.

Its filter is therefore much broader than the ferry's — outbound UDP excluding loopback and port 53 — which has a real cost: broad UDP traffic is copied into the process to inspect four bytes. Two consequences shape the design:

* **It is a separate handle, never a leg of the DNS ferry.** Two diverting handles matching one datagram is a race over who re-injects it, not redundancy. Only one component may own a given packet, so the ferry captures STUN *only* when relaying it, and the blocker's filter excludes port 53 so it cannot collide with the DNS relay.
* **Its capture loop is synchronous and await-free.** If the queue overflows while this loop is descheduled, WinDivert drops packets at the driver — which for a broad filter would affect unrelated traffic, not just WebRTC.

Media is deliberately not blocked: TURN Data / ChannelData reveal nothing once the relay candidate is known, and dropping them would break a working call without improving privacy. What blocking does not cover is TURN over **TCP/TLS**, since a UDP content match cannot see it.

See [DNS.md](DNS.md) for the current DNS and WebRTC behavior and known limitations.

## Traffic Isolation

Open NetRoute does not route every application through the proxy by default.

The intended model is:

```text
Selected Application
        │
        └──► SOCKS5 Proxy ──► Internet

Other Applications
        │
        └──► Normal Windows Network Path ──► Internet
```

This allows the user to selectively proxy applications while leaving unrelated system traffic untouched.

## Loop Prevention

Packet interception and reinjection require careful loop handling.

Open NetRoute distinguishes traffic that should be processed from traffic that has already been generated or reinjected by the application.

The design relies on packet direction, capture filtering, connection state, and process/flow information to prevent intercepted traffic from continuously re-entering the proxying path.

## WinDivert Validation

The WinDivert-based architecture has been validated through standalone experiments and integration work.

The important validated capabilities include:

* opening a WinDivert capture handle;
* capturing real outbound TCP traffic;
* reading relevant packet fields;
* obtaining process attribution for TCP flows;
* reinjecting captured packets;
* avoiding packet-level reinjection loops in the tested scenarios;
* accepting crafted TCP SYN-ACK packets from a real Windows client;
* relaying bidirectional TCP application data;
* performing process attribution during connection establishment;
* tolerating short delays while process attribution becomes available;
* capturing and relaying DNS UDP traffic through the SOCKS5 UDP path.

These tests establish the feasibility of the core interception and forwarding approach. They do not imply that every Windows networking scenario or every application protocol is fully supported.

## Network Scope

The current architecture is primarily focused on application-level TCP routing with additional UDP/DNS handling.

Protocols and scenarios that require separate handling include:

* IPv6 traffic;
* QUIC;
* arbitrary UDP applications;
* DNS-over-HTTPS (DoH);
* DNS-over-TLS (DoT);
* applications that implement their own encrypted or custom DNS resolution;
* networking paths that bypass the traffic patterns handled by Open NetRoute.

Support for these cases should be considered separately from the core TCP/SOCKS5 architecture.

## Why No Routing Table Is Used

A SOCKS5 proxy is not a normal IP router.

Adding a route such as:

```text
Destination Network
        │
        ▼
SOCKS5 Proxy
```

does not work in the same way as routing traffic through a VPN or gateway because a SOCKS5 proxy expects application-level protocol requests rather than raw IP packets.

Open NetRoute therefore keeps the routing decision in user space and converts selected application connections into SOCKS5 connections.

## Security and Privilege Considerations

Because Open NetRoute intercepts and reinjects network packets, it requires elevated Windows privileges.

The application should be treated as a privileged networking component.

Important considerations include:

* WinDivert requires administrator privileges for the relevant operations.
* The application can observe network metadata for intercepted traffic.
* Proxy credentials must be protected appropriately.
* Persistent sensitive configuration should not be stored as plain text where protected storage is available.
* Firewall, antivirus, and endpoint-security software may inspect or restrict WinDivert-based applications.

## Current Architectural Limitations

The architecture should not be interpreted as a universal VPN replacement.

Known limitations include:

* protocol-specific handling is required;
* IPv6 coverage is not equivalent to IPv4 coverage for general traffic, though plaintext DNS is intercepted on both families;
* QUIC and arbitrary UDP traffic require additional handling;
* some applications use networking mechanisms that are difficult to attribute or intercept reliably;
* encrypted DNS (DoH/DoT/DoQ) and custom resolvers on non-standard ports are outside interception — plaintext DNS has no direct-path fallback, but encrypted DNS cannot be observed without TLS interception;
* WebRTC blocking closes the UDP STUN discovery path on any port, but not TURN over TCP/TLS or TCP STUN, which are outside a UDP content match — a TURN relay obtained over TCP can still report the address;
* settings sections must be explicitly carried from the UI into the engine's runtime configuration — a section silently reverted to its default looks identical to a feature that is working but idle, which is why this is enforced by test rather than by convention;
* endpoint behavior can vary across Windows versions, applications, firewall configurations, and security software.

## Design Goal

The primary design goal is straightforward:

> Route selected Windows applications through a SOCKS5 proxy without requiring a VPN interface or changing the system routing table.

The architecture favors application-level control, explicit traffic interception, and a user-space proxying layer over system-wide network redirection.
