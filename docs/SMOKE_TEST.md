# Open NetRoute Smoke Test

## Purpose

This document describes a basic end-to-end smoke test for Open NetRoute on Windows.

The goal is to verify that:

* Open NetRoute starts correctly;
* a selected application is routed through the configured SOCKS5 proxy;
* non-selected applications continue to use their normal network path;
* DNS handling behaves as expected;
* stopping Open NetRoute restores normal networking;
* restarting the application does not leave stale capture state behind.

This is a practical Beta validation procedure, not a complete compatibility or security test suite.

## Requirements

Before starting, make sure you have:

* Windows 10 or Windows 11;
* administrator privileges;
* a working SOCKS5 proxy;
* a reachable Internet connection;
* Open NetRoute built or published successfully.

For development builds, make sure the required .NET runtime/SDK and WinDivert components are available according to the project's build configuration.

## 1. Start Open NetRoute

1. Launch Open NetRoute with administrator privileges.
2. Confirm that the application starts without an error.
3. Confirm that the main window is responsive.
4. Confirm that the proxy configuration is available.
5. Enter or select a known-working SOCKS5 proxy.

If the application provides a connection or configuration status indicator, confirm that the configured values are accepted.

## 2. Select an Application

Choose a simple test application whose network behavior is easy to verify.

Suitable examples include:

* a web browser;
* `curl`;
* another application that makes ordinary TCP connections.

Add the application to the list of applications that should use the proxy.

Do not begin the test with multiple applications. Testing one selected application first makes failures easier to diagnose.

## 3. Start Traffic Interception

Start the Open NetRoute routing/interception function.

Confirm that:

* no startup error is displayed;
* the application remains responsive;
* the selected application can still be launched or used;
* no unexpected system-wide network outage occurs.

## 4. Verify Selected Application Traffic

Use the selected application to access a known Internet destination.

Verify that the connection succeeds.

Then verify from the destination side, or by another appropriate external test, that the traffic is using the SOCKS5 proxy rather than the normal local network path.

For an HTTP request, for example, compare the externally visible source IP with the expected proxy address.

The important result is:

```text
Selected Application
        │
        ▼
Open NetRoute
        │
        ▼
SOCKS5 Proxy
        │
        ▼
Internet
```

## 5. Verify a Non-Selected Application

Open a second application that is not configured for proxying.

Generate normal network traffic from that application.

Verify that it continues to use the normal Windows network path.

The expected behavior is:

```text
Selected Application   ──► SOCKS5 Proxy ──► Internet

Non-Selected Application ──► Normal Path ──► Internet
```

This test is important because Open NetRoute is intended to provide selective application routing rather than automatically proxying all system traffic.

## 6. Verify DNS Behavior

Perform a DNS lookup from the selected application.

Confirm that normal DNS resolution still works.

Where possible, use an external DNS or leak-testing service to inspect the observed DNS path.

With the DNS relay enabled, all **plaintext** DNS (UDP/53 and TCP/53, IPv4 and IPv6) is relayed system-wide and never sent directly. If a leak test shows your ISP's resolver, the app is most likely using **encrypted DNS** (DoH, DoT, DoQ) or a custom resolver on a non-standard port — those are indistinguishable from ordinary HTTPS/TLS and are outside the interception scope.

Confirm the relay is actually active before drawing conclusions:

* the status line should report the DNS relay as active, not failed;
* the Debug log should show each relayed query and the resolver it was sent to;
* a `dropped (fail-closed)` entry means the query was blocked, not leaked — usually a proxy without UDP support.

## 7. Verify Internet Access After Multiple Requests

Generate several requests from the selected application.

For example:

* open multiple web pages;
* perform several DNS lookups;
* download a small resource;
* make repeated connections to the same destination.

Watch for:

* connection failures;
* unexpected disconnects;
* repeated connection attempts;
* application hangs;
* significant delays.

The goal is to verify that the proxy path remains stable during normal repeated use.

## 8. Stop Open NetRoute

Stop traffic interception from the application.

Then test both applications again.

Verify that:

* the previously selected application can access the Internet normally;
* the non-selected application still works;
* no connections remain permanently blocked;
* DNS resolution continues to work;
* the application does not leave the system in a broken networking state.

## 9. Restart Test

Restart Open NetRoute and repeat the basic routing test.

Verify that:

* the application starts normally;
* the proxy configuration is still available;
* traffic interception can be enabled again;
* the selected application can be proxied again;
* stopping the application does not cause persistent network problems.

A successful restart test is particularly useful for identifying stale WinDivert handles, unfinished forwarding sessions, or other lifecycle problems.

## 10. DNS Relay and Encrypted-DNS Detection

Run with the DNS relay enabled in `Settings` › DNS.

### 10.1 Plaintext relay works

Browse normally, then check the **Data Usage** tab's DNS block and the Debug log.

Verify that:

* `relayed` rises and stays close to `captured`;
* log lines appear per query, naming both the original destination and the relay target: `relaying via proxy to 1.1.1.1:53 (resolver override: 203.0.113.53 -> 1.1.1.1)`;
* DNS resolution still works in every application, including after the cache flush at START.

### 10.2 Leak test

Run your preferred DNS leak test.

Verify that:

* the resolvers shown are the one configured in Settings (not your ISP) — this is the relay working;
* the IP address shown is the proxy's, not yours;
* if your ISP's resolvers appear, the observer in 10.3 names the path that produced them.

Note: a resolver appearing in the result is **not** by itself a leak — what matters is whether your real address is exposed. If your proxy egress and your resolver are the same provider, the two are indistinguishable in the result.

### 10.3 Encrypted-DNS detection

Open a site that uses DoH (or set Chrome's secure DNS to a public resolver), then check the log and the Data Usage tab.

Verify that:

* a line names the process, destination and resolver: `ENCRYPTED DNS (DoH) detected: chrome.exe (...) resolving via https://.../`;
* the Data Usage tab shows the detection and the observer's counters;
* **the connection still works** — the observer is passive and must not change routing. If enabling it breaks browsing, that is a bug, not expected behaviour.

### 10.4 Fail-closed behaviour

Expect lookups to fail (a couple of seconds, with client retries) when the relay cannot serve them — for example with a proxy that does not support UDP ASSOCIATE.

Verify that:

* failures appear as `relay FAILED` or `dropped (fail-closed)`, i.e. the query was **blocked, not leaked**;
* nothing is sent directly as a fallback;
* turning the relay off restores normal system DNS.

### 10.5 WebRTC / STUN — blocking

Enable **Block WebRTC** in Settings › DNS, restart, and run a WebRTC leak test.

Verify that:

* the log contains `[WebRTC] STUN blocking ACTIVE — matched by message content on ANY port`;
* `[WebRTC] blocked STUN datagram #N ... content-matched` lines appear — the dropped counter is the only proof the block matched anything, so a run showing zero drops has **not** tested the feature;
* the Data Usage tab shows `WebRTC: BLOCKING` with a non-zero dropped count;
* if the Data Usage tab shows `IPv6 blocking is OFF`, IPv6 STUN is unprotected regardless of the counter — browsers prefer IPv6, so this is a real exposure, not a cosmetic note;
* **in-browser video calls stop working.** That is the intended trade-off, not a regression — with no reachable STUN server WebRTC has no server-reflexive candidate. Confirm it is stated as expected somewhere visible, because it is the most surprising consequence of the setting.

The honest limit to check, and the reason this test exists at all: the earlier port-matched implementation showed the setting as "on", dropped **nothing**, and the page still reported the real address. If the dropped counter is zero while the leak test shows a `srflx` candidate with the real IP, the block is not matching — do not accept the checkbox state as evidence.

### 10.6 WebRTC / STUN — relaying

Disable blocking, enable STUN relaying, restart, and re-run the test.

Verify that:

* STUN lines appear with their **original destination** — a line showing STUN sent to the DNS resolver's address would be the regression this feature previously had;
* the public address shown is the proxy's;
* if the Data Usage tab reports 0 captured or any failures, relaying is not working for that server — the STUN server used a port outside the relayed set — and blocking should be used instead.

Also verify the honest limits: TURN over **TCP/TLS** and TCP STUN are outside both options (relaying is port-matched; blocking matches UDP STUN by content). So a leak can still appear over those transports, and that is expected at this stage.

## 11. Basic Failure Tests

For a more useful Beta smoke test, also test a few failure conditions.

### Invalid Proxy

Configure an invalid or unreachable SOCKS5 proxy.

Expected behavior:

* Open NetRoute should report the connection problem clearly;
* the application should not appear to have a working proxy connection when the proxy is unavailable;
* the failure should not permanently break unrelated applications.

### Stop During Active Traffic

Start a download or repeated network request and stop Open NetRoute while traffic is active.

Verify that:

* Open NetRoute shuts down cleanly;
* active interception does not remain indefinitely;
* the system network stack returns to normal operation.

### Start and Stop Repeatedly

Start and stop the routing function several times.

Watch for:

* increasing resource usage;
* stale connections;
* inability to start again;
* duplicate traffic;
* persistent network failures.

## Expected Result

A successful smoke test should demonstrate the following:

| Test                     | Expected Result                                                                    |
| ------------------------ | ---------------------------------------------------------------------------------- |
| Application startup      | Open NetRoute starts normally                                                      |
| Proxy configuration      | SOCKS5 configuration is accepted                                                   |
| Selected application     | Traffic is routed through the proxy                                                |
| Non-selected application | Traffic remains on the normal path                                                 |
| DNS resolution           | DNS continues to function                                                          |
| DNS privacy              | Plaintext DNS (UDP/TCP 53, IPv4 and IPv6) is relayed and never sent directly; encrypted DNS (DoH/DoT/DoQ) is outside scope |
| Repeated traffic         | Connections remain usable                                                          |
| Stop                     | Normal networking is restored                                                      |
| Restart                  | Routing can be enabled again                                                       |
| Invalid proxy            | Failure is handled without permanently breaking unrelated traffic                  |
| Repeated start/stop      | No persistent capture state or networking failure remains                          |

## What This Test Does Not Prove

Passing this smoke test does not prove full compatibility with every Windows application or network protocol.

It does not comprehensively validate:

* all IPv4 traffic;
* all IPv6 traffic;
* QUIC;
* arbitrary UDP applications;
* encrypted DNS (DoH, DoT, DoQ) — DoH on TCP/443 is detected and named, but it is neither blocked nor relayed, and DoH over QUIC/HTTP3 and Encrypted ClientHello are not observable at all;
* custom resolvers on non-standard ports;
* complete WebRTC/STUN coverage — relayed STUN works, but TURN, non-listed ICE ports and STUN over IPv6 remain outside the relayed set;
* every firewall or antivirus configuration;
* every Windows version;
* every SOCKS5 server implementation.

Those scenarios require dedicated testing.

## Reporting a Failure

When reporting a smoke-test failure, include:

* Windows version;
* Open NetRoute version or build;
* application being tested;
* whether the application was selected for proxying;
* proxy type and relevant configuration details without exposing credentials;
* whether the problem affects TCP, UDP, DNS, or another protocol;
* the exact steps required to reproduce the problem;
* relevant application logs or error messages.

Do not include proxy passwords, private keys, or other sensitive credentials in bug reports.
