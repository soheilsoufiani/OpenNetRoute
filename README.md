![Open NetRoute Banner](https://github.com/soheilsoufiani/OpenNetRoute/blob/main/icons/banner.webp)
# Open NetRoute [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/) [![WPF](https://img.shields.io/badge/framework-WPF-blue.svg)](https://www.cmarix.com/our-services.html)

**Selective application routing for Windows through SOCKS5 proxies.**
[Watch the Open NetRoute video preview](docs/video-preview.mp4)

Open NetRoute is a Windows desktop application that lets you route selected applications through a SOCKS5 proxy while leaving other applications on their normal network connection.

Instead of changing the Windows routing table or creating a VPN interface, Open NetRoute uses **WinDivert** and a user-space forwarding layer to intercept and route selected application traffic.

Here's [Installation](README.md#installation) and [Quick Start](README.md#quick-start) Guide
> **Beta:** Open NetRoute is currently in active Beta development. The core application-routing and SOCKS5 forwarding functionality is implemented, but some network protocols and edge cases remain outside the current scope.

## Features

### 🎯 Per-Application Proxy Routing

Choose which applications should use your SOCKS5 proxy.

You can add applications by:

* Running processes
* Executable files
* Application folders

Non-selected applications can continue using the normal Windows network path.

### 🌐 IP & Domain Rules

Create destination-based routing rules using:

* IP addresses
* IP ranges
* Domains
* Destination ports

This allows routing behavior to be refined beyond simple application selection.

### 🔐 SOCKS5 Proxy Profiles

Create and manage multiple SOCKS5 proxy configurations.

Proxy profiles can be tested before use, making it easier to verify connectivity and configuration.

### 📡 DNS Relay

Open NetRoute intercepts **all plaintext DNS system-wide** and relays it through the configured proxy, on both of DNS's transports and both address families:

* **UDP 53 over IPv4 and IPv6** — relayed via SOCKS5 UDP ASSOCIATE
* **TCP 53 over IPv4 and IPv6** — the fallback transport for truncated answers, relayed via SOCKS5 CONNECT

Every query is dropped rather than sent directly if it cannot be relayed (**fail-closed**), and the Windows resolver cache is flushed at START and STOP so pre-START answers cannot bypass the relay. A query that fails takes a moment to retry; that is the intended trade-off versus a silent leak.

**Encrypted DNS is not relayed, but it is watched.** A passive observer reads the hostname from the TLS ClientHello on outbound TCP/443 (sent in the clear by design) and names the app and resolver doing the encrypted resolving. It opens its handle in sniff mode, so it only copies packets and cannot affect your connection. The Data Usage tab shows its counters, and detections appear in the log while you are still on the leak-test page.

Not observable: DoH over QUIC/HTTP3, Encrypted ClientHello (reported as an "unreadable" blind spot), and custom resolvers on non-standard ports. Only well-known resolver hostnames are classified, so a zero count means "nothing known was seen", not "nothing is leaking".

**WebRTC:** STUN is handled by one of two mutually exclusive settings, and they recognise it in different ways:

- **Block WebRTC** (recommended) — STUN requests are dropped locally, over IPv4 and IPv6. STUN is matched by its **message content, not by port**, so it does not matter which port the WebRTC server uses. It cannot fail open and needs no UDP support from your proxy. The cost is real: **in-browser video calls stop working.**
- **Relay STUN** — keeps video calls working by relaying STUN through the proxy, but matches by **port** (3478/3479, 5348/5349, 19302–19309) and needs the proxy to support SOCKS5 UDP ASSOCIATE.

Both work whether or not the DNS relay is on. Neither covers TURN over TCP/TLS, so treat this as strong protection rather than proof. Watch the dropped counter on the Data Usage tab: if it reads zero, nothing was matched.

See [DNS documentation](docs/DNS.md) for details.

### 📊 Data Usage

Track traffic usage for proxy configurations, including:

* Upload traffic
* Download traffic
* Total traffic
* Current-session statistics
* Historical usage
* One-click reset of the recorded history and counters

### ⚡ Tunnel Optimization

Open NetRoute provides networking optimization options such as:

* Automatic MTU handling
* Game Mode
* DNS resolver preferences
* Connection-related optimizations

These settings are designed to help adapt the proxy tunnel to different network environments.

### 🖥️ Windows Tray Integration

Open NetRoute can run in the Windows system tray.

Available options include:

* Start with Windows
* Minimize to tray
* Hide the window when closed
* Restore the application from the tray

### 🎨 Desktop UI

The application provides a native Windows desktop interface for managing:

* Proxy profiles
* Application rules
* IP/domain rules
* Traffic statistics
* DNS behavior
* Network optimization
* Startup and tray behavior
* Appearance

## How It Works

Open NetRoute does not create a VPN connection and does not change the Windows routing table.

Instead, it watches network traffic and checks which application the traffic belongs to.

When traffic belongs to an application that you selected, Open NetRoute sends it through your SOCKS5 proxy.

The basic flow looks like this:

```text
Selected Application
        |
        v
    Open NetRoute
        |
        v
     SOCKS5 Proxy
        |
        v
      Internet
````

Applications that are not selected can continue using the normal Windows network connection.

For more technical information, see [Architecture](docs/ARCHITECTURE.md).

## Installation
### **Current build only supports Windows 10/11 x64**

There are two ways to install Open NetRoute.

### Option 1: Download from GitHub Releases page

The easiest way to use Open NetRoute is to download the latest version from the [GitHub Releases page](https://github.com/soheilsoufiani/OpenNetRoute/releases).

Go to the Releases section of the repository and download the latest Windows build.

After extracting the files:

1. Open the Open NetRoute folder.
2. Find the Open NetRoute executable.
3. Right-click it.
4. Select `Run as administrator`.
5. Configure your SOCKS5 proxy.
6. Add the applications you want to route.
7. Press `START`.

Open NetRoute needs to be **run as administrator** because it needs access to Windows network traffic through WinDivert.

> Always download releases from the official repository.

### Option 2: Build From Source

If you prefer to build Open NetRoute yourself, you can clone the repository and build it with the .NET SDK.

Requirements:

* Windows 10 or Windows 11
* .NET 10 SDK
* .NET 10 Desktop Runtime
* Administrator access

Clone the repository:

```bash
git clone https://github.com/soheilsoufiani/OpenNetRoute.git
cd OpenNetRoute
```

Build the project:

```bash
dotnet build
```

To create a Release build:

```bash
dotnet publish -c Release
```

After building the application, run Open NetRoute with:

`Right click -> Run as administrator`

## Quick Start

### 1. Add a Proxy

Open the `Proxies` tab.

Create a new SOCKS5 proxy profile and enter your proxy information.

You can use `Test Ping` or the proxy test option to check the connection.

### 2. Add an Application

Open the `App Rules` tab.

Add the application you want to route through the proxy.

You can select:

* A running application
* An `.exe` file
* An application folder

### 3. Add IP or Domain Rules

If you need more control, open `IP/Domain Rules`.

Add any IP addresses, domains, or ports that you want to handle with your routing rules.

### 4. Check DNS Settings

Open `Settings` and check the DNS section.

If you want Open NetRoute to relay plaintext DNS through the proxy, enable the DNS relay option and choose your preferred DNS resolver.

Encrypted DNS (DoH/DoT/DoQ) is not covered — see [DNS and Privacy](#dns-and-privacy).

### 5. Start Open NetRoute

Press the green `START` button.

The selected applications will now use the configured proxy.

### 6. Check Your Traffic

Open `Data Usage` to see the current traffic and traffic history.

You can also use the `Debug` option if you need to investigate a connection problem.

## DNS and Privacy

Open NetRoute relays **all plaintext DNS** through the proxy, system-wide, on both transports and both address families (UDP/53 and TCP/53, IPv4 and IPv6). While the relay runs, plaintext DNS has no direct path out of the machine — a query that cannot be relayed is dropped, never sent directly.

```text
Application
     |
     v
Plaintext DNS Query (UDP/53 or TCP/53)
     |
     v
Open NetRoute  --fail-closed--> dropped if it cannot be relayed
     |
     v
SOCKS5 Proxy (UDP ASSOCIATE / CONNECT)
     |
     v
DNS Server
```

Because a relayed query never goes out directly, the user's configured (typically ISP) resolver stays out of the path. Leak tests show the resolver you configured in Settings instead.

What the relay cannot cover is **encrypted DNS**:

* DNS over HTTPS (port 443)
* DNS over TLS (port 853)
* DNS over QUIC
* custom application resolvers on non-standard ports

These cannot be *relayed* without TLS interception, so a browser or app configured for secure DNS resolves through its own encrypted resolver. Everything on the plaintext path is relayed.

### Finding out what bypasses the relay

A leak test lists resolvers that answered, which is not the same thing as resolvers that leaked your address. So while the relay is running, Open NetRoute **watches** encrypted DNS on TCP/443 and tells you who is using it.

A passive observer reads the hostname from the TLS ClientHello — which is sent in the clear by design, since the server name must be readable before the session keys exist. It opens its capture handle in sniff mode, so it **copies** packets and lets the real ones continue: it cannot consume, delay or drop anything, and cannot affect your connection.

When an app resolves through DoH, the log and the Data Usage tab name it:

```text
[Sni] ENCRYPTED DNS (DoH) detected: chrome.exe (192.168.1.5:51234 -> 104.16.248.1:443)
      resolving via https://chrome.cloudflare-dns.com/ — this resolver is NOT relayed through the proxy.
```

Its limits are worth stating plainly: Encrypted ClientHello hides the hostname (counted and shown as an "unreadable" blind spot rather than silently missed), DoH over QUIC/HTTP3 carries no TLS-over-TCP ClientHello at all, and only well-known resolver hostnames are classified. So a zero count means "nothing known was seen", not "nothing is leaking".

For more information, see [DNS.md](docs/DNS.md).

## Limitations

Open NetRoute is still a Beta project and is not a complete VPN replacement.

Some known limitations are:

* Some IPv6 traffic may require additional handling. Plaintext DNS is covered on both address families; general IPv6 TCP routing is IPv4-only by design.
* QUIC traffic is different from normal TCP traffic and may not be handled in the same way.
* Some UDP applications may need additional support.
* DNS over HTTPS, DNS over TLS and DNS over QUIC are encrypted, so they cannot be relayed as plaintext DNS — a browser or app using secure DNS resolves through its own encrypted resolver. DoH on TCP/443 is detected and named, but nothing is blocked.
* WebRTC is not fully blocked. "Block WebRTC" drops STUN address-discovery messages over UDP, matched by message content rather than port, so the port a WebRTC server chooses does not matter. What it does **not** cover: **TURN over TCP or TLS** (443, 5349) and TCP STUN, because those are TCP and outside a UDP match. A TURN relay obtained over TCP can still report your address. "Relay STUN" is weaker still — it matches a fixed port list. Neither option is proof that WebRTC cannot leak, and browser video calls do not work while blocking is on.
* Some applications use their own networking or DNS systems.
* Windows services can sometimes create network traffic separately from the application that requested it.
* Antivirus and firewall software may interfere with WinDivert.
* Network behavior can be different between applications and Windows configurations.

For more technical details, see [Architecture](docs/ARCHITECTURE.md).

## Testing

Open NetRoute includes automated tests for parts of the application.

For a simple manual test of the complete application, see [Smoke Test](docs/SMOKE_TEST.md).

The smoke test covers:

* Starting the application
* Configuring a SOCKS5 proxy
* Routing a selected application
* Checking a non-selected application
* DNS behavior
* Starting and stopping the tunnel
* Restarting the application
* Handling an unavailable proxy

## Development Note

Open NetRoute was entirely vibe coded.

The project was built through an iterative process of using AI-assisted development, testing the result, finding problems, and improving the implementation step by step.

The project is still maintained and tested as a normal software project, with the application code, tests, documentation, and experimental work kept separate.

## Reference

**Inspired by:** The development of Open NetRoute was informed by studying [TunnelX](https://github.com/MaxiFan/TunnelX?utm_source=chatgpt.com) and its approach to Windows traffic interception and application-level routing. Open NetRoute is an independent implementation.

## Contributing

Bug reports, testing feedback, and contributions are welcome.

When reporting a problem, please include:

* Windows version
* Open NetRoute version
* Application being routed
* SOCKS5 proxy type
* The protocol involved, if known
* Steps to reproduce the problem
* Relevant error messages or logs

Please do not include proxy passwords, private keys, or other sensitive information in issues or pull requests.

## License

Open NetRoute is licensed under the MIT License.

See [LICENSE](LICENSE) for the full license text.

Open NetRoute also uses third-party components that have their own licenses and terms.

## Documentation

* [Architecture](docs/ARCHITECTURE.md)
* [DNS](docs/DNS.md)
* [Smoke Test](docs/SMOKE_TEST.md)

## Disclaimer

Open NetRoute is provided as-is during the Beta stage.

Network behavior can be different depending on the application, Windows version, firewall, antivirus software, proxy server, and network configuration.

If you use Open NetRoute for privacy or security purposes, make sure to test the behavior that is important to you before relying on it.

