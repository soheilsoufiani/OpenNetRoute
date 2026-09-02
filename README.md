# Open NetRoute

An open-source Windows desktop application that routes the traffic of selected
applications through a user-configured **SOCKS5 proxy**, while leaving all other
applications on the normal network path. A lightweight, transparent alternative
to tools such as Proxifier.

**Status: pre-beta (v0.0.1).** The networking core (WinDivert interception →
SOCKS5 ferry) and the WPF GUI are implemented and covered by 278 automated
tests. DNS interception, tray integration, and release packaging are still
pending — see [Limitations](#limitations-please-read) for the honest picture.

## Features

- **Per-application SOCKS5 routing** — TCP connections of selected apps are
  routed through the proxy; all other traffic is untouched.
- **Proxy profiles** — multiple SOCKS5 servers, paste
  `socks5://user:pass@host:port` URIs, one-click connection test (ping), sort
  by latency.
- **Application rules** — match by executable name or full path; add from the
  running-process list, from disk (`.exe` picker), or as **folder bundles**.
- **In-app debug window** — bounded, real-time connection event log with
  per-connection summaries and health statistics.
- **Theme** — system / light / dark.
- **Robust settings persistence** — atomic JSON writes, corruption
  quarantine, DPAPI-encrypted proxy passwords (details below).

## How it works (high level)

1. On START the app opens a WinDivert **network-layer** handle with the capture
   filter `outbound and ip and tcp and not loopback` (IPv4 TCP only).
2. Each captured SYN is attributed to its owning process via the Windows TCP
   connection table (cached, refreshed at most once per ~50 ms window); the
   rule set then decides **proxy** or **direct**.
3. *Proxy* connections: a user-space "ferry" answers the client's SYN with a
   crafted SYN-ACK **immediately** (the application's handshake completes with
   ~zero added latency) while the real **SOCKS5 CONNECT** to the configured
   proxy runs **in parallel**; once connected, bytes are relayed with a
   byte-level exactly-once guarantee between app and proxy.
4. *Direct* traffic is re-injected unchanged. Loopback is never captured, so
   pointing a profile at a **local SOCKS5 proxy** (v2ray/Xray/sing-box inbound)
   cannot create an interception loop.

The full design analysis behind this approach is in
`docs/ARCHITECTURE_RESEARCH.md`.

## Requirements

- Windows 10 / 11 (x64)
- .NET 10 (SDK to build; runtime to run)
- **Administrator privileges** to start routing (WinDivert loads a kernel
  driver; everything else — configuration, process enumeration, the SOCKS5
  client — works without elevation)

Stack: C# / .NET 10, WPF, WinDivert, SOCKS5, xUnit, JSON settings.

## Installation

No packaged releases yet. Build from source (below) and run the resulting
`ProxyApp.exe` **as Administrator**. The build deploys `WinDivert.dll` and
`WinDivert64.sys` next to the executable automatically — keep the files
together.

## Usage

1. **Proxies tab** — create a profile or paste a `socks5://` URI, test it,
   pick the fastest. The selected profile is used on START.
2. **Applications tab** — add rules from running processes, by browsing for an
   executable, or as a folder bundle; toggle individual rules on/off.
3. Press **START**; the status bar shows the engine state, and the **Debug**
   window shows per-connection events live.
4. Press **STOP** to tear all ferry flows down and return to the normal
   network path.

## SOCKS5 configuration

- Host + port, optional username/password (RFC 1929) or no authentication
  (RFC 1928 method negotiation).
- Profiles can be imported by pasting a standard
  `socks5://user:pass@host:port` URI (missing port defaults to 1080).
- Passwords are **encrypted at rest with Windows DPAPI** (`CurrentUser`
  scope): only the same Windows user account can decrypt them, and no
  plaintext password ever touches disk or log output — log lines show a masked
  URI (`socks5://user:***@host:port`).
- A local SOCKS5 inbound (`127.0.0.1` from v2ray/Xray/sing-box) is a valid
  profile; the ferry never captures loopback traffic.

## Application rules

- Match by **executable name** (`chrome.exe`) or by **full executable path**;
  a rule may carry either or both.
- Rules are evaluated **in list order** — the **first enabled rule that
  matches wins**; disabled rules are skipped and never block later rules.
- **No match → Direct**: the traffic passes through untouched.

## Administrator requirements

The application manifest runs the process `asInvoker` on purpose — Windows
will not auto-elevate it; launch it explicitly as Administrator. If routing is
started without elevation, the WinDivert open fails and the app reports the
exact error with a human explanation (e.g. `ERROR_FILE_NOT_FOUND` → the
`WinDivert64.sys` driver was not found, `ERROR_SERVICE_DOES_NOT_EXIST` → the
driver service is not installed) instead of failing silently.

## Settings storage

All settings (proxy profiles, selected profile, application rules, bundle
assignments, theme and accent, connection-test preference, window placement)
are persisted as JSON to:

```
%APPDATA%\OpenNetRoute\settings.json
```

- Coming from the previous **MyProxy** build? The old `%APPDATA%\MyProxy\settings.json`
  is copied to the new location automatically on first start (the old file is
  kept as a backup and never deleted).
- Writes are **atomic** (temp file + replace); a crash mid-save cannot corrupt
  the file. A damaged file is quarantined (`*.corrupt-*`) and the app starts
  with defaults — data stays recoverable by hand.
- Proxy **passwords are encrypted at rest with Windows DPAPI**
  (`CurrentUser` scope): only the same Windows user account can decrypt them,
  and no plaintext password ever touches disk or log output. Log lines show a
  masked URI (`socks5://user:***@host:port`).
- The full state is flushed on close; edits during the session are saved
  incrementally (immediately for structural changes such as adding or deleting
  a profile, debounced while typing).

## Limitations (please read)

- **TCP only.** UDP, QUIC/HTTP-3, and ICMP are never captured. QUIC-capable
  applications (modern browsers) can send some traffic **direct** over UDP
  443, bypassing the proxy.
- **DNS leaks.** The ferry intercepts TCP SYNs whose destination is already an
  IP literal. Applications that resolve hostnames themselves — the dominant
  case — query the system resolver **directly**, outside the tunnel. **Do not
  assume any DNS-leak protection.** The design for closing this gap is in
  `docs/DNS-DESIGN.md` (implementation pending).
- **IPv4 only.** The capture filter matches IPv4; outbound IPv6 TCP bypasses
  the ferry entirely and goes direct. (The SOCKS5 client itself is
  IPv6-capable and tested against IPv6 destinations.)
- **DoH / DoT** (DNS over HTTPS/TLS) cannot be intercepted by design.
- **No tray** — the main window must keep running.
- Antivirus products occasionally flag WinDivert-based tools; the bundled
  binaries are the unmodified official WinDivert build.
- No installer yet; a folder copy of the build output is the distribution.

## Development status (Phase checklist)

- [x] Phase 0 — Solution, project structure, test projects, MIT license
- [x] Phase 1 — Configuration models + validation + `socks5://` URI parsing
- [x] Phase 2 — SOCKS5 client (RFC 1928 CONNECT; no-auth + RFC 1929
      username/password; IPv4/IPv6/domain destinations; timeouts; cancellation)
- [x] Phase 3 — Process discovery (cached Windows TCP table)
- [x] Phase 4 — WinDivert integration (spike-validated; actionable error mapping)
- [x] Phase 5 — Process-to-connection mapping (SYN-time attribution)
- [x] Phase 6 — TCP redirection engine (ferry; parallel CONNECT; exactly-once relay)
- [x] Phase 7 — Application rules (first-enabled-match-wins engine)
- [ ] Phase 8 — DNS behavior (**design only** — leaks today; see `docs/DNS-DESIGN.md`)
- [ ] Phase 9 — IPv6 behavior (interception is IPv4-only today)
- [x] Phase 10 — WPF GUI (profiles, rules, bundles, debug window, themes)
- [ ] Phase 11 — Tray application
- [ ] Phase 12 — Logging (in progress: in-app debug window with bounded event
      log and per-connection summaries; broader structured logging pending)

## Building from source

Prerequisite: a **.NET 10 SDK**.

```bash
dotnet restore
dotnet build
dotnet test
```

All 278 tests pass; the end-to-end ferry tests that need the WinDivert driver
**skip gracefully** in a non-elevated shell — run the suite from an elevated
shell to execute them for real. They use a local SOCKS5 test server, never an
external proxy, and clean up after themselves. For a manual end-to-end check
against a real proxy, follow `docs/LIVE_APP_SMOKE_TEST.md`.

## Project structure

```
src/
    ProxyApp/            WPF application shell (UI only; no networking code)
    ProxyApp.Core/       Platform-independent logic (config, rules, validation, persistence)
    ProxyApp.Network/    SOCKS5 protocol and TCP connection handling
    ProxyApp.WinDivert/  WinDivert integration + the TCP ferry (capture, injection)
    ProxyApp.Processes/  Windows process enumeration and connection mapping
tests/
    ProxyApp.Core.Tests/          Configuration, rules, persistence, URI parsing
    ProxyApp.Network.Tests/       SOCKS5 negotiation, auth, CONNECT, timeouts
    ProxyApp.IntegrationTests/    Ferry end-to-end against a local SOCKS5 server
docs/
    ARCHITECTURE_RESEARCH.md      Full design analysis of the ferry approach
    DNS-DESIGN.md                 Phase 8 DNS design (status: leaks, design only)
    WINDIVERT_SPIKE.md            Driver feasibility experiments and results
    LIVE_APP_SMOKE_TEST.md        Manual end-to-end smoke-test script
spikes/
    WinDivertSpike/               Standalone experiments that validated the design
references/
    TunnelX/                      Reference material only — GPL-3.0-or-later; NOT copied or ported
```

## License

MIT — see [LICENSE](LICENSE).

Third-party components:

- **WinDivert** (`WinDivert.dll`, `WinDivert64.sys`) is dual-licensed
  LGPL-3.0-or-later / GPL-2.0; the binaries are used unmodified and WinDivert's
  license notices must be retained when the binaries are redistributed.
- The `references/TunnelX/` tree is third-party GPL material kept for study
  only; no code is copied or ported from it.