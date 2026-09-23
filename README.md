![[Open NetRoute Logo](www.photopea.com/g/LmBrjEzS)
# Open NetRoute

An open-source Windows desktop application that routes the traffic of selected
applications through a user-configured **SOCKS5 proxy**, while leaving all other
applications on the normal network path. A lightweight, transparent alternative
to tools such as Proxifier.

**Status: pre-beta (v0.0.1).** The networking core (WinDivert interception →
SOCKS5 ferry), the WPF GUI, and the tray integration are implemented and
covered by 308 automated tests. DNS interception and release packaging are
still pending — see [Limitations](#limitations-please-read) for the honest
picture.

## Features

- **Per-application SOCKS5 routing** — TCP connections of selected apps are
  routed through the proxy; all other traffic is untouched.
- **IP/domain destination rules** — route or stay direct by destination IPv4
  (optional port) or domain (DNS-resolved); evaluated before the app rules.
- **DNS relay (closes the DNS leak)** — outbound DNS (UDP 53) is relayed
  through the proxy's UDP ASSOCIATE leg to a public resolver of your choice
  (Cloudflare/Google/Quad9/transparent); optional STUN relay so WebRTC reports
  the proxy's IP. Needs a UDP-capable proxy.
- **Data Usage tab** — live up/down speed (bytes/s, once a second) and a
  cumulative per-configuration history (uploaded / downloaded / total),
  persisted across restarts.
- **Tunnel optimization** — automatic MTU (interface MTU + don't-fragment
  probes adapt the advertised MSS) and Game Mode (DSCP EF marking + MSS 1360).
- **Application rules with icons** — each rule row shows the executable's own
  icon behind its name (a neutral placeholder for name-only rules).
- **Proxy profiles** — multiple SOCKS5 servers, paste
  `socks5://user:pass@host:port` URIs, one-click connection test (ping), sort
  by latency.
- **Application rules** — match by executable name or full path; add from the
  running-process list, from disk (`.exe` picker), or as **folder bundles**.
- **In-app debug window** — bounded, real-time connection event log with
  per-connection summaries and health statistics.
- **Tray icon** — start/stop routing from the notification area, live status
  with a green "routing" badge, close/minimize to tray, and optional
  start-with-Windows (per-user auto-start).
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
- .NET 10 — **SDK** to build, **Desktop Runtime (x64)** to run
- **Administrator privileges** to start routing (WinDivert loads a kernel
  driver; everything else — configuration, process enumeration, the SOCKS5
  client — works without elevation)

Stack: C# / .NET 10, WPF, WinDivert, SOCKS5, xUnit, JSON settings.

## Installation

No packaged releases yet. Build a distributable folder from source:

```bash
dotnet publish src/ProxyApp -c Release -r win-x64 --self-contained false -o dist/ProxyApp
```

This writes a ready-to-copy `dist\ProxyApp` folder — `ProxyApp.exe` plus the
runtime files, with `WinDivert.dll` and `WinDivert64.sys` deployed next to it
automatically (keep the files together). The output requires the **.NET 10
Desktop Runtime (x64)** on the machine where it runs. Launch `ProxyApp.exe`
**as Administrator**.

## Usage

1. **Proxies tab** — create a profile or paste a `socks5://` URI, test it,
   pick the fastest. The selected profile is used on START.
2. **Applications tab** — add rules from running processes, by browsing for an
   executable, or as a folder bundle; toggle individual rules on/off.
3. Press **START**; the status bar shows the engine state, and the **Debug**
   window shows per-connection events live.
4. Press **STOP** to tear all ferry flows down and return to the normal
   network path.

## Tray & startup

- The **notification-area icon** mirrors the engine state: a tooltip and menu
  line show *Stopped* / *Routing via \<profile\>*, and a green badge is drawn
  on the icon while routing. Left-click (or **Open**) brings the window back.
- The tray menu can **start/stop routing** — the same validated start/stop
  path as the window toggle; when the window is hidden the outcome is
  announced with a balloon notification instead of the status bar.
- The Settings tab controls the behavior:
  - **Enable tray icon** (default: on). Turning it off removes the icon;
    close-to-tray and minimize-to-tray are then disabled too, so the window
    can never become unreachable.
  - **Close button minimizes to tray** (default: on) — the ✕ button hides the
    window and the engine keeps routing; exit lives in the tray menu. Set it
    to *Exit* if you prefer the classic behavior.
  - **Minimize button hides to tray** (default: on) — same idea for the
    minimize button.
  - **Start minimized to tray** (default: off) — the next launch begins
    hidden in the notification area with a balloon notice.
- **Auto-start with Windows** registers the executable (quoted path) under
  `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` for the **current user
  only** — no admin rights, no services, no scheduled tasks. The checkbox
  mirrors the registry (the single source of truth); a failed registry write
  is reported as an error and never silently ignored.

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
- **Per-rule proxy**: each rule can pin one of the saved proxy profiles
  (the PROXY column for exe rules, "Via proxy" in the bundle details for
  folders). *Default* means the active proxy selected on the Proxies tab.
  A pin whose profile was deleted or is disabled falls back to the active
  proxy (visible in the log), never drops the connection.

## Administrator requirements

The application manifest runs the process `asInvoker` on purpose — Windows
will not auto-elevate it; launch it explicitly as Administrator. If routing is
started without elevation, the WinDivert open fails and the app reports the
exact error with a human explanation (e.g. `ERROR_FILE_NOT_FOUND` → the
`WinDivert64.sys` driver was not found, `ERROR_SERVICE_DOES_NOT_EXIST` → the
driver service is not installed) instead of failing silently.

## Settings storage

All settings (proxy profiles, selected profile, application rules, bundle
assignments, theme and accent, connection-test preference, tray preferences,
window placement) are persisted as JSON to:

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
- The **auto-start registration is NOT stored here** — the HKCU `Run` value is
  the single source of truth for that setting (see [Tray & startup](#tray--startup)).

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
- [x] Phase 11 — Tray application (icon + menu with Open / Start-Stop / status
  / Exit, close- and minimize-to-tray, start-minimized, per-user auto-start)
- [ ] Phase 12 — Logging (in progress: in-app debug window with bounded event
      log and per-connection summaries; broader structured logging pending)

## Building from source

Prerequisite: a **.NET 10 SDK**.

```bash
dotnet restore
dotnet build
dotnet test
```

For a distributable Release build, use the publish command from
[Installation](#installation).

All 308 tests pass; the end-to-end ferry tests that need the WinDivert driver
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
    DNS-DESIGN.md                 Phase 8 DNS analysis, experiments, and status
    WINDIVERT_SPIKE.md            Driver feasibility experiments and results
    LIVE_APP_SMOKE_TEST.md        Manual end-to-end smoke-test script
spikes/
    WinDivertSpike/               Standalone experiments that validated the design
```

## Acknowledgments

- [TunnelX](https://github.com/MaxiFan/TunnelX) (GPL-3.0-or-later) — studied
  as reference material during the design phase; several tunnel-optimization
  ideas (automatic MTU, DNS caching/stale-serving, Game-Mode packet tuning)
  were inspired by its behavior. **No source code was copied or ported** —
  this project implements everything independently for a SOCKS5-ferry
  architecture, under MIT.

## License

MIT — see [LICENSE](LICENSE).

Third-party components:

- **WinDivert** (`WinDivert.dll`, `WinDivert64.sys`) is dual-licensed
  LGPL-3.0-or-later / GPL-2.0; the binaries are used unmodified and WinDivert's
  license notices must be retained when the binaries are redistributed.
- [TunnelX](https://github.com/MaxiFan/TunnelX) is third-party GPL material
  consulted for study only; no code is copied or ported from it.
- **Icons8** — the edit and share (copy) toolbar icons are based on icons from
  [Icons8](https://icons8.com); used under the Icons8 license, which requires
  this attribution. The remaining UI icons are original path geometry.
