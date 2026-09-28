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

Do not interpret a successful ordinary DNS lookup as proof that there are no DNS leaks.

Open NetRoute includes an implemented DNS relay, but complete leak-proof DNS protection is not guaranteed. Some specialized DNS leak tests may still detect DNS exposure depending on the application, Windows configuration, and protocol being used.

Applications using DoH, DoT, custom resolvers, or other encrypted DNS mechanisms may behave differently from applications using traditional UDP/53 DNS.

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

## 10. Basic Failure Tests

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
| DNS privacy              | DNS relay operates where supported, but complete leak prevention is not guaranteed |
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
* DoH;
* DoT;
* WebRTC/STUN behavior;
* every DNS leak scenario;
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
