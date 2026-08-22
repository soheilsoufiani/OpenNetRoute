# Live App Smoke Test (elevated)

Verifies the production path: **app UI → ProxyEngine → TcpFerry → WinDivert →
SOCKS5 → real proxied connection**. The in-app Start → ProxyEngine → TcpFerry
path has never been confirmed against real traffic; this is the manual check.

## Requirements

- Windows 10/11, the WinDivert driver installed (WinDivert64.sys service)
- The WinDivert.dll user-mode library beside the app (deployed automatically
  by `ProxyApp.WinDivert.csproj` from the repository's `references/TunnelX` tree)
- A reachable SOCKS5 proxy (the test in `TcpFerryEndToEndTests` uses a local
  one; for this smoke test any reachable SOCKS5 server works, e.g. a VPS or
  local `ssh -D`)

## Steps

1. **Build** (Debug, from the repo root):

   ```bash
   dotnet build
   ```

2. **Run the app as Administrator.** The WinDivert capture handle requires
   elevation. Launch the built exe from an elevated shell:

   ```powershell
   # Elevated PowerShell
   cd C:\Users\aghai\Workspace\MyProxy
   .\src\ProxyApp\bin\Debug\net10.0-windows\ProxyApp.exe
   ```

   (Alternatively right-click the exe → "Run as administrator".)

3. **Configure the SOCKS5 proxy** in the app: Host, Port, optional
   Username/Password. Use a proxy you control and can observe.

4. **Select an application to route**: click the checkbox next to a real app
   (e.g. `curl.exe` or a browser) in the Applications list. Leave everything
   else unchecked (Direct).

5. **Click START.** The status should change to "Status: Running". If WinDivert
   cannot be opened (not elevated, driver missing), the status shows the
   actionable error instead — no silent failure.

6. **Generate traffic from the selected app** to a destination reachable only
   through the proxy, or observe the proxy's logs. For a deterministic check
   with curl:

   ```powershell
   # From a normal (non-elevated) shell, with curl.exe selected in the app:
   curl -s -o NUL --max-time 10 http://<destination-reachable-through-proxy>/
   ```

   The proxy server's logs should show a CONNECT for that destination, and the
   request must succeed.

7. **Confirm a non-selected app is untouched**: run the same curl from a
   process NOT selected in the app — its traffic must go direct (no CONNECT on
   the proxy; it either succeeds directly or fails if the destination is
   proxy-only). This is the no-leakage check.

8. **Click STOP.** The status returns to "Status: Stopped". Repeat steps 5–6
   once more to confirm a clean restart (no leftover WinDivert handle).

## Expected results

| Check | Expected |
|---|---|
| App launches elevated | Window opens; process list populates (sorted by name) |
| START with valid config | Status: Running; no error |
| START without elevation / missing driver | Actionable error in status (e.g. "requires Administrator privileges") |
| Selected app traffic | Proxy logs show CONNECT; request succeeds |
| Non-selected app traffic | No CONNECT on the proxy (direct) |
| STOP | Status: Stopped; restart works |

## Expected latency

The ferry's SYN hold timeout (the delay between capturing a connection's SYN
and injecting the crafted SYN-ACK) is **100ms** — the value validated by the
elevated E2E tests. A browser opening many concurrent connections should see
a **quick first byte** (approximately one round-trip to the proxy plus the
hold, not the original 600ms-per-connection default). If a page feels
noticeably slower than a direct proxy configuration, that is a
performance/correctness regression to report, not expected behavior.

## Known limitations

- Settings are not persisted across launches (no JSON save/load yet).
- This smoke test requires a real SOCKS5 proxy you can observe; the automated
  elevated tests use a local loopback test proxy instead.
- The app UI does not yet show per-flow status or logs (Phase 12).
