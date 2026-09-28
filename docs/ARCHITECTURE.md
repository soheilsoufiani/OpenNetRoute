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

UDP traffic is handled separately from the TCP ferry.

For DNS traffic, Open NetRoute can capture UDP DNS requests and forward them through the SOCKS5 proxy using SOCKS5 UDP ASSOCIATE. Responses are then injected back toward the requesting application.

The DNS path is approximately:

```text
Application
    │
    ▼
UDP DNS Query
    │
    ▼
WinDivert
    │
    ▼
DNS Relay
    │
    ▼
SOCKS5 UDP ASSOCIATE
    │
    ▼
Configured DNS Server
    │
    ▼
DNS Response
    │
    ▼
Application
```

DNS relay is implemented, but it should not be considered a guarantee of completely leak-proof DNS protection. Some specialized DNS leak-testing scenarios can still identify DNS-related exposure depending on the application and protocol being used.

See [DNS.md](DNS.md) for the current DNS behavior and known limitations.

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
* IPv6 coverage is not equivalent to IPv4 coverage;
* DoH and DoT can bypass traditional DNS interception;
* QUIC and arbitrary UDP traffic require additional handling;
* some applications use networking mechanisms that are difficult to attribute or intercept reliably;
* DNS relay does not guarantee complete protection against every possible DNS leak scenario;
* endpoint behavior can vary across Windows versions, applications, firewall configurations, and security software.

## Design Goal

The primary design goal is straightforward:

> Route selected Windows applications through a SOCKS5 proxy without requiring a VPN interface or changing the system routing table.

The architecture favors application-level control, explicit traffic interception, and a user-space proxying layer over system-wide network redirection.
