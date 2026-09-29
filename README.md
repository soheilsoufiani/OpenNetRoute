![Open NetRoute Banner](https://github.com/soheilsoufiani/OpenNetRoute/blob/main/icons/banner.webp)
# Open NetRoute [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![.NET](https://img.shields.io/badge/.NET-10.0-purple.svg)](https://dotnet.microsoft.com/) [![WPF](https://img.shields.io/badge/framework-WPF-blue.svg)](https://www.cmarix.com/our-services.html)

**Selective application routing for Windows through SOCKS5 proxies.**

Open NetRoute is a Windows desktop application that lets you route selected applications through a SOCKS5 proxy while leaving other applications on their normal network connection.

Instead of changing the Windows routing table or creating a VPN interface, Open NetRoute uses **WinDivert** and a user-space forwarding layer to intercept and route selected application traffic.

Here's [Installation](main#installation) and [Quick Start](main#quick-start) Guide
> **Beta:** Open NetRoute is currently in active Beta development. The core application-routing and SOCKS5 forwarding functionality is implemented, but some network protocols and edge cases remain outside the current scope.

## Video Preview

A short video showing Open NetRoute in action will be available here.

[![Open NetRoute Video Preview](docs/images/video-preview.png)](VIDEO_URL)

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

Open NetRoute includes an implemented DNS relay designed to send supported DNS traffic through the configured proxy.

The DNS path uses **SOCKS5 UDP ASSOCIATE** and can relay traditional UDP/53 DNS queries and responses.

DNS relay improves DNS privacy for supported traffic, but it should **not** be considered a guarantee of completely leak-proof DNS protection.

Some applications and protocols can bypass traditional DNS interception, including:

* DNS-over-HTTPS (DoH)
* DNS-over-TLS (DoT)
* Custom application resolvers
* Some system-level DNS behavior
* Other encrypted or application-specific networking mechanisms

See [DNS documentation](docs/DNS.md) for details.

### 📊 Data Usage

Track traffic usage for proxy configurations, including:

* Upload traffic
* Download traffic
* Total traffic
* Current-session statistics
* Historical usage

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

There are two ways to install Open NetRoute.

### Option 1: Download the Beta Release

The easiest way to use Open NetRoute is to download the latest Beta from the GitHub Releases page.

Go to the Releases section of the repository and download the latest Windows build.

After extracting the files:

1. Open the Open NetRoute folder.
2. Find the Open NetRoute executable.
3. Right-click it.
4. Select `Run as administrator`.
5. Configure your SOCKS5 proxy.
6. Add the applications you want to route.
7. Press `START`.

Open NetRoute needs to be run as administrator because it needs access to Windows network traffic through WinDivert.

> Always download releases from the official Open NetRoute repository.

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

If you want Open NetRoute to relay supported DNS requests through the proxy, enable the DNS relay option and choose your preferred DNS resolver.

Keep in mind that DNS relay does not cover every type of DNS traffic.

### 5. Start Open NetRoute

Press the green `START` button.

The selected applications will now use the configured proxy.

### 6. Check Your Traffic

Open `Data Usage` to see the current traffic and traffic history.

You can also use the `Debug` option if you need to investigate a connection problem.

## DNS and Privacy

Open NetRoute includes DNS relay support for traditional DNS traffic.

The basic flow is:

```text
Application
     |
     v
DNS Request
     |
     v
Open NetRoute
     |
     v
SOCKS5 Proxy
     |
     v
DNS Server
```

This can help prevent supported DNS requests from going directly through the normal DNS path.

However, Open NetRoute does not currently promise 100% DNS leak protection.

Some applications and services use different ways to resolve DNS, including:

* DNS over HTTPS
* DNS over TLS
* Their own DNS resolver
* Other encrypted DNS methods

Some specialized DNS leak tests may still detect DNS exposure.

For more information, see [DNS.md](docs/DNS.md).

## Limitations

Open NetRoute is still a Beta project and is not a complete VPN replacement.

Some known limitations are:

* Some IPv6 traffic may require additional handling.
* QUIC traffic is different from normal TCP traffic and may not be handled in the same way.
* Some UDP applications may need additional support.
* DNS over HTTPS and DNS over TLS are not automatically handled by the DNS relay.
* Some applications use their own networking or DNS systems.
* DNS relay does not guarantee complete DNS leak protection.
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

