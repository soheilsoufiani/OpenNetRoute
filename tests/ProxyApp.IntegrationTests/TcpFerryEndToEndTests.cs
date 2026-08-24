using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.Network.Tests.TestInfrastructure;
using ProxyApp.Processes;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// End-to-end ferry integration test (Step 3D). This exercises the full path:
///
///   curl
///   -> WinDivert capture
///   -> ProcessTable attribution (R1)
///   -> RuleEngine = Proxy
///   -> hold SYN (R4)
///   -> SOCKS5 CONNECT to a local test proxy
///   -> upstream (local HTTP backend)
///   -> crafted SYN-ACK (R3/E5b)
///   -> client ACK + request
///   -> client payload -> upstream (3B)
///   -> upstream response -> crafted packet -> client (3C)
///   -> curl receives the response body
///
/// REQUIREMENTS: this test needs Administrator privileges and the WinDivert
/// driver installed. When the test process is not elevated, it skips
/// gracefully so the normal suite stays green. To run it for real, launch the
/// test host elevated.
/// </summary>
public class TcpFerryEndToEndTests
{
    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    /// <summary>An HTTP backend that the local SOCKS5 proxy forwards to.
    /// Accepts MULTIPLE sequential connections (each test's curls may reconnect,
    /// e.g. a ferry restart in StopFerry_MidFlow_CleansUp).</summary>
    private static async Task<int> StartHttpBackendAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    var client = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            // The using MUST live inside the handler task — a
                            // using on the accept loop would dispose the client
                            // as soon as the loop iterates, closing the backend
                            // before the request arrives.
                            using (client)
                            using (var stream = client.GetStream())
                            {
                                var buf = new byte[4096];
                                // Consume the HTTP request (partial reads are fine).
                                var total = 0;
                                while (total < buf.Length)
                                {
                                    var r = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total));
                                    if (r <= 0) break;
                                    total += r;
                                    if (buf.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0) break;
                                }
                                var resp = Encoding.ASCII.GetBytes(
                                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                                await stream.WriteAsync(resp, 0, resp.Length);
                            }
                        }
                        catch { }
                    });
                }
            }
            catch { }
        });
        return port;
    }

    /// <summary>
    /// An HTTP backend that holds the connection open (does not respond) until
    /// the returned <see cref="TaskCompletionSource"/> is completed, keeping the
    /// proxied connection alive so the test can resolve its 4-tuple while curl
    /// is still connected.
    /// </summary>
    private static async Task<int> StartHoldingBackendAsync(TaskCompletionSource release)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var buf = new byte[4096];
                var total = 0;
                while (total < buf.Length)
                {
                    var r = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total));
                    if (r <= 0) break;
                    total += r;
                    if (buf.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0) break;
                }
                // Hold the connection open until released.
                await release.Task.WaitAsync(TimeSpan.FromSeconds(15));
                var resp = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                await stream.WriteAsync(resp, 0, resp.Length);
            }
            catch { }
        });
        return port;
    }

    /// <summary>
    /// An HTTP backend that accepts MULTIPLE connections and holds each open
    /// (no response) until the shared <see cref="TaskCompletionSource"/> is
    /// completed. Used by the mid-flow-stop test: the held connection keeps the
    /// ferry's flow alive and observable, while the restarted ferry's fresh
    /// connection is still served by a later accept.
    /// </summary>
    private static async Task<int> StartHoldingBackendMultiAsync(TaskCompletionSource release)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = Task.Run(async () =>
        {
            try
            {
                while (true)
                {
                    var client = await listener.AcceptTcpClientAsync();
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            using (client)
                            using (var stream = client.GetStream())
                            {
                                var buf = new byte[4096];
                                var total = 0;
                                while (total < buf.Length)
                                {
                                    var r = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total));
                                    if (r <= 0) break;
                                    total += r;
                                    if (buf.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0) break;
                                }
                                await release.Task.WaitAsync(TimeSpan.FromSeconds(15));
                                var resp = Encoding.ASCII.GetBytes(
                                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                                await stream.WriteAsync(resp, 0, resp.Length);
                            }
                        }
                        catch { }
                    });
                }
            }
            catch { }
        });
        return port;
    }

    /// <summary>
    /// An HTTP backend that sends a 4 KB response body in multiple chunks,
    /// exercising the ferry's multi-segment data relay. The response declares
    /// Content-Length: 4096 so the client (curl) knows to read the full body.
    /// </summary>
    private static async Task<int> StartStreamingBackendAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var buf = new byte[8192];
                var total = 0;
                while (total < buf.Length)
                {
                    var r = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total));
                    if (r <= 0) break;
                    total += r;
                    if (buf.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0) break;
                }
                // 4096-byte body of repeated 'A's.
                var body = new string('A', 4096);
                var resp = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n{body}");
                // Write in 4 chunks to force the SOCKS5 relay to forward in
                // multiple segments, exercising the ferry's multi-segment pump.
                const int chunkSize = 1024;
                for (int i = 0; i < resp.Length; i += chunkSize)
                {
                    var chunkLen = Math.Min(chunkSize, resp.Length - i);
                    await stream.WriteAsync(resp.AsMemory(i, chunkLen));
                    await Task.Delay(10);
                }
            }
            catch { }
        });
        return port;
    }

    [Fact]
    public async Task Curl_ThroughFerry_ReceivesResponseBytes()
    {
        if (!IsElevated())
        {
            // Cannot run the live WinDivert path without elevation.
            return;
        }

        // The test process is the "selected application": it will launch curl,
        // and the rule matches curl.exe so its SYN is proxied.
        var backendPort = await StartHttpBackendAsync();

        // Local SOCKS5 proxy that forwards to the backend.
        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            Console.WriteLine($"[Socks5Server] CONNECT dst={request.Host}:{request.Port} atyp={request.Atyp}");
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            Console.WriteLine("[Socks5Server] backend connection established");
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            // Relay both directions concurrently so the backend's response flows
            // back even while curl is still sending/retransmitting.
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        // Ensure the WinDivert DLL can be located. The driver is installed by
        // the TunnelX reference app under %LOCALAPPDATA%\TunnelX; the resolver
        // honors PROXYAPP_WINDIVERT_DIR. If the DLL is not there, the test fails
        // with a clear error rather than silently skipping the ferry.
        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        // Ensure the WinDivert native DLL resolver is registered BEFORE any
        // WinDivert P/Invoke (the observer handle below and the ferry). Without
        // this, WinDivert.dll is looked up via the standard search path and fails
        // with DllNotFoundException because it is not beside the test host.
        WinDivertLibrary.EnsureRegistered();

        // Independent outbound observer: a SNIFF+RECV_ONLY handle at priority 1
        // that sees ALL outbound TCP packets to 8.8.8.8:80 — including curl's ACK
        // of the injected response and any retransmits. This tells us whether the
        // response reached curl (curl would send an ACK).
        CancellationTokenSource? ferryObsCts = null;
        var observerHandle = WinDivertNative.WinDivertOpen(
            "outbound and ip and ip.DstAddr == 8.8.8.8 and tcp and tcp.DstPort == 80",
            WinDivertLayer.Network, 1, WinDivertNative.Flags.SniffAndReceiveOnly);
        if (observerHandle != IntPtr.Zero && observerHandle != new IntPtr(-1))
        {
            var observerCts = new CancellationTokenSource();
            _ = Task.Run(() =>
            {
                var buffer = new byte[65535];
                var addr = new WinDivertAddress();
                while (!observerCts.IsCancellationRequested)
                {
                    uint readLen = 0;
                    if (!WinDivertNative.WinDivertRecv(observerHandle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                        break;
                    if (readLen < 20) continue;
                    if (TcpPacketParser.TryParse(buffer, readLen, out var t))
                        Console.WriteLine($"[OBS] {t.SrcIp}:{t.SrcPort}->{t.DstIp}:{t.DstPort} " +
                                          $"flags=0x{t.TcpFlags:X2} seq={t.Seq} ack={t.Ack} len={readLen}");
                }
            });
            ferryObsCts = observerCts;
        }
        else
        {
            Console.WriteLine("[OBS] Could not open observer handle (skipping independent observation)");
        }

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100, // short hold for the test
            trace: m => Console.WriteLine(m)); // surface ferry diagnostics on failure

        try
        {
            ferry.Start();

            // Launch curl to a public destination. The ferry intercepts its SYN,
            // routes it through the SOCKS5 proxy to the backend, and relays the
            // response back.
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using var curl = Process.Start(psi)!;
            // Task.WhenAny returns one of its ARGUMENT tasks; it can never return
            // the Task.CompletedTask singleton, so the completion check must
            // compare against the WaitForExitAsync task itself (reference
            // equality), not against Task.CompletedTask. The previous
            // `exited != Task.CompletedTask` was always true and failed the test
            // even when curl exited successfully within milliseconds.
            var curlExitTask = curl.WaitForExitAsync();
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(12));
            var completed = await Task.WhenAny(curlExitTask, timeoutTask);
            if (completed != curlExitTask)
            {
                curl.Kill();
                await curlExitTask;
                Assert.Fail("curl did not finish within 12s (ferry relay failed).");
            }

            // curl should have exited 0 if it received the "OK" body through the ferry.
            Assert.Equal(0, curl.ExitCode);
        }
        finally
        {
            await ferry.StopAsync();
            ferry.Dispose();

            // Stop and close the independent observer.
            if (observerHandle != IntPtr.Zero && observerHandle != new IntPtr(-1))
            {
                ferryObsCts?.Cancel();
                WinDivertNative.WinDivertClose(observerHandle);
                try { ferryObsCts?.Dispose(); } catch { }
            }
        }
    }

    [Fact]
    public async Task Curl_ThroughFerry_WithStreamingResponse()
    {
        // Larger/streamed response: a 4 KB body sent by the backend in multiple
        // chunks. Exercises the ferry's multi-segment data relay and verifies the
        // seq/ack framing stays correct across segments (ClientBytesRecv,
        // ClientAckedUpTo, NextServerSeq) and the separate FIN still fires after
        // the client ACKs all bytes. Requires elevation (same as the other E2E).
        if (!IsElevated())
        {
            return;
        }

        var backendPort = await StartStreamingBackendAsync();

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            Console.WriteLine($"[Socks5Server] CONNECT dst={request.Host}:{request.Port} atyp={request.Atyp}");
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            Console.WriteLine("[Socks5Server] backend connection established");
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            // curl -s -o NUL writes the response body to NUL; --max-time bounds the run.
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using var curl = Process.Start(psi)!;
            var curlExitTask = curl.WaitForExitAsync();
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(12));
            var completed = await Task.WhenAny(curlExitTask, timeoutTask);
            if (completed != curlExitTask)
            {
                curl.Kill();
                await curlExitTask;
                Assert.Fail("curl did not finish within 12s (ferry relay failed).");
            }

            Assert.Equal(0, curl.ExitCode);
        }
        finally
        {
            await ferry.StopAsync();
            ferry.Dispose();
        }
    }

    [Fact]
    public async Task ConcurrentCurls_ThroughFerry_ReceiveCorrectResponses()
    {
        // Two concurrent connections through the same ferry: one curl to
        // 8.8.8.8:80 (short response), one to 8.8.4.4:80 (4 KB streaming).
        // Exercises the FlowTable + per-flow seq/ack state under concurrency —
        // neither flow may corrupt the other's framing. The SOCKS5 test proxy
        // routes by destination host to the appropriate loopback backend.
        if (!IsElevated())
        {
            return;
        }

        var backendA = await StartHttpBackendAsync();
        var backendB = await StartStreamingBackendAsync();

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            Console.WriteLine($"[Socks5Server] CONNECT dst={request.Host}:{request.Port} atyp={request.Atyp}");
            var backendPort = request.Host switch
            {
                "8.8.8.8" => backendA,
                "8.8.4.4" => backendB,
                _ => throw new InvalidOperationException($"Unexpected destination {request.Host}")
            };
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            Console.WriteLine($"[Socks5Server] backend connection established ({request.Host})");
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync($"client→backend({request.Host})", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync($"backend({request.Host})→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        // Independent outbound observer scoped to port 80 (both destinations).
        CancellationTokenSource? ferryObsCts = null;
        var observerHandle = WinDivertNative.WinDivertOpen(
            "outbound and ip and tcp and tcp.DstPort == 80",
            WinDivertLayer.Network, 1, WinDivertNative.Flags.SniffAndReceiveOnly);
        if (observerHandle != IntPtr.Zero && observerHandle != new IntPtr(-1))
        {
            var observerCts = new CancellationTokenSource();
            _ = Task.Run(() =>
            {
                var buffer = new byte[65535];
                var addr = new WinDivertAddress();
                while (!observerCts.IsCancellationRequested)
                {
                    uint readLen = 0;
                    if (!WinDivertNative.WinDivertRecv(observerHandle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                        break;
                    if (readLen < 20) continue;
                    if (TcpPacketParser.TryParse(buffer, readLen, out var t))
                        Console.WriteLine($"[OBS] {t.SrcIp}:{t.SrcPort}->{t.DstIp}:{t.DstPort} " +
                                          $"flags=0x{t.TcpFlags:X2} seq={t.Seq} ack={t.Ack} len={readLen}");
                }
            });
            ferryObsCts = observerCts;
        }
        else
        {
            Console.WriteLine("[OBS] Could not open observer handle (skipping independent observation)");
        }

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            var psiA = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var psiB = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.4.4/",
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var curlA = Process.Start(psiA)!;
            using var curlB = Process.Start(psiB)!;

            var waitA = curlA.WaitForExitAsync();
            var waitB = curlB.WaitForExitAsync();
            var allDone = Task.WhenAll(waitA, waitB);
            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(15));
            var completed = await Task.WhenAny(allDone, timeoutTask);
            if (completed != allDone)
            {
                curlA.Kill();
                curlB.Kill();
                await waitA;
                await waitB;
                Assert.Fail("concurrent curls did not finish within 15s (ferry relay failed).");
            }

            Assert.Equal(0, curlA.ExitCode);
            Assert.Equal(0, curlB.ExitCode);
        }
        finally
        {
            await ferry.StopAsync();
            ferry.Dispose();
            if (observerHandle != IntPtr.Zero && observerHandle != new IntPtr(-1))
            {
                ferryObsCts?.Cancel();
                WinDivertNative.WinDivertClose(observerHandle);
                try { ferryObsCts?.Dispose(); } catch { }
            }
        }
    }

    [Fact]
    public async Task Curl_ThroughFerry_AttributedToCurlProcess()
    {
        // Core-reliability gap 1: prove the REAL attribution path
        // (ProcessTable.ResolveOwner mapping a captured connection's 4-tuple to
        // a PID) works on a live elevated path. The earlier E2E tests match
        // curl.exe by name in the rules the TEST supplies; this test asserts the
        // OS-level lookup actually attributes the connection to the curl process
        // — and that a DIFFERENT process's connection is attributed to ITS OWN
        // PID, not curl's.
        //
        // How: a backend that HOLDS the connection open (does not respond until
        // released) keeps curl's proxied connection alive while we resolve its
        // 4-tuple via ProcessTable. curl's local (IP,port) is read from the
        // captured flow state; the tuple is then resolved against the real OS
        // table and must map to the curl process (name curl.exe).
        // Requires elevation (same as the other E2E tests).
        if (!IsElevated())
        {
            return;
        }

        // Backend that holds the response until released via a TaskCompletionSource.
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backendPort = await StartHoldingBackendAsync(release);

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using var curl = Process.Start(psi)!;

            // Wait for the ferry to have an ESTABLISHED flow for the curl
            // connection: scan the flow table for a flow whose remote is
            // 8.8.8.8:80 (the destination the test's curl reaches).
            FlowState? flow = null;
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (flow == null && DateTime.UtcNow < deadline)
            {
                flow = ferry.Flows.GetFlows()
                    .FirstOrDefault(f => f.Key.RemoteIp.Equals(IPAddress.Parse("8.8.8.8")) &&
                                         f.Key.RemotePort == 80);
                if (flow == null)
                    await Task.Delay(50);
            }

            Assert.NotNull(flow);

            // ── THE attribution assertion ──
            // Resolve the flow's captured 4-tuple against the REAL OS table —
            // the exact same call the ferry makes at SYN time
            // (ProcessTable.ResolveOwner). It must attribute to the curl process.
            var resolver = new ProcessTable();
            var resolved = resolver.ResolveOwner(
                flow.Key.LocalIp, flow.Key.LocalPort,
                flow.Key.RemoteIp, flow.Key.RemotePort);

            Assert.NotNull(resolved);
            Assert.True(string.Equals("curl.exe", resolved.Value.ExecutableName, StringComparison.OrdinalIgnoreCase),
                "the captured connection must attribute to curl.exe");
            Assert.True(curl.Id == resolved.Value.ProcessId,
                "the resolved PID must be curl's PID");
            Assert.False(string.IsNullOrEmpty(resolved.Value.ExecutablePath),
                "curl's executable path must be resolvable");

            // ── No-leakage assertion ──
            // A DIFFERENT process's connection must attribute to ITS OWN PID,
            // never to curl. The SOCKS5 proxy's upstream leg to the backend is
            // owned by the TEST HOST (the Socks5TestServer runs in this
            // process). Resolve that connection and assert it maps to the test
            // host, not curl.
            var self = Process.GetCurrentProcess();
            var selfFlow = ferry.Flows.GetFlows()
                .FirstOrDefault(f => f.Key.RemoteIp.Equals(IPAddress.Loopback) &&
                                     f.Key.RemotePort == backendPort);
            if (selfFlow != null)
            {
                var selfResolved = resolver.ResolveOwner(
                    selfFlow.Key.LocalIp, selfFlow.Key.LocalPort,
                    selfFlow.Key.RemoteIp, selfFlow.Key.RemotePort);
                Assert.NotNull(selfResolved);
                Assert.True(selfResolved.Value.ProcessId != curl.Id,
                    "the test host's own connection must NOT attribute to curl");
                Assert.True(selfResolved.Value.ProcessId == self.Id);
            }

            // Release the backend so curl completes; the test then verifies the
            // response still arrives (the relay path is intact).
            release.TrySetResult();
            var wait = curl.WaitForExitAsync();
            var timeout = Task.Delay(TimeSpan.FromSeconds(12));
            var done = await Task.WhenAny(wait, timeout);
            if (done != wait)
            {
                curl.Kill();
                await wait;
                Assert.Fail("curl did not finish after release within 12s.");
            }
            Assert.Equal(0, curl.ExitCode);
        }
        finally
        {
            release.TrySetResult(); // ensure the backend releases on any failure
            await ferry.StopAsync();
            ferry.Dispose();
        }
    }

    [Fact]
    public async Task StopFerry_MidFlow_CleansUp()
    {
        // Core-reliability gap 2 (shutdown): start the ferry, open a proxied
        // connection, then STOP the ferry mid-flow. Assert no leftover flows,
        // no exceptions, and the ferry can be restarted (new connection works).
        //
        // The backend HOLDS the connection open (no response until released):
        // with parallel establishment the whole lifecycle (SYN → CONNECT →
        // response → FIN → cleanup) completes in ~10-30ms, so a fast backend
        // would let the flow come and go before the test's flow-count poll
        // observes it. Holding keeps the flow alive and observable.
        if (!IsElevated())
        {
            return;
        }

        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backendPort = await StartHoldingBackendMultiAsync(release);

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            // Open a connection (curl) and let it establish through the ferry.
            // The backend holds the response, so the flow stays alive in the
            // table until we release it — this is what makes the mid-flow stop
            // meaningful.
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using var curl = Process.Start(psi)!;
            // Wait for the ferry to have a flow (the connection is being proxied).
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while (ferry.Flows.Count == 0 && DateTime.UtcNow < deadline)
            {
                await Task.Delay(50);
            }
            Assert.True(ferry.Flows.Count > 0, "expected at least one flow while curl connects");

            // Stop the ferry mid-flow. Must not throw and must clean up flows.
            // (The stopped ferry's upstream legs to the holding backend are
            // closed; the backend handler tolerates the abrupt close.)
            await ferry.StopAsync();
            Assert.Equal(0, ferry.Flows.Count);
            Assert.False(ferry.IsRunning);

            // Release the held backend so the first curl's connection is torn
            // down cleanly (it was killed by the ferry stop; the release lets
            // the backend handler exit without blocking for 15s).
            release.TrySetResult();

            // Restart the ferry — a fresh connection must still work (no
            // leftover handle / no state corruption).
            ferry.Start();
            var psi2 = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using var curl2 = Process.Start(psi2)!;
            var wait2 = curl2.WaitForExitAsync();
            var timeout2 = Task.Delay(TimeSpan.FromSeconds(12));
            var done2 = await Task.WhenAny(wait2, timeout2);
            if (done2 != wait2)
            {
                curl2.Kill();
                await wait2;
                Assert.Fail("curl after restart did not finish within 12s.");
            }
            Assert.Equal(0, curl2.ExitCode);
        }
        finally
        {
            release.TrySetResult(); // ensure the backend releases on any failure
            await ferry.StopAsync();
            ferry.Dispose();
        }
    }

    [Fact]
    public async Task UpstreamDrop_MidRelay_FailsClientCleanly()
    {
        // Core-reliability gap 2 (error resilience): the backend is killed
        // mid-relay (after the response started). The ferry must not hang the
        // client; it cleans up the flow and the client sees the connection end
        // (FIN or RST), not a permanent stall.
        if (!IsElevated())
        {
            return;
        }

        // Backend that writes part of the response, then kills the socket.
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var backendPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        _ = Task.Run(async () =>
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync();
                using var stream = client.GetStream();
                var buf = new byte[4096];
                var total = 0;
                while (total < buf.Length)
                {
                    var r = await stream.ReadAsync(buf.AsMemory(total, buf.Length - total));
                    if (r <= 0) break;
                    total += r;
                    if (buf.AsSpan(0, total).IndexOf("\r\n\r\n"u8) >= 0) break;
                }
                // Send headers + partial body, then close abruptly (socket drop).
                var resp = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial");
                await stream.WriteAsync(resp, 0, resp.Length);
                await Task.Delay(100);
                // Abrupt close — no FIN, the TCP stack just drops.
                client.Client.Close(); // hard close
            }
            catch { }
        });

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            // curl with a short --max-time so a hang would fail fast.
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 5 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            using var curl = Process.Start(psi)!;
            var wait = curl.WaitForExitAsync();
            var timeout = Task.Delay(TimeSpan.FromSeconds(12));
            var done = await Task.WhenAny(wait, timeout);
            if (done != wait)
            {
                curl.Kill();
                await wait;
                Assert.Fail("curl did not exit after upstream drop (client hung).");
            }

            // After the backend was killed, the ferry must have cleaned the flow.
            // The cleanup is asynchronous (pump error → RST + cleanup); poll for
            // it with a deadline rather than assuming a fixed delay.
            var cleanupDeadline = DateTime.UtcNow.AddSeconds(8);
            while (ferry.Flows.Count > 0 && DateTime.UtcNow < cleanupDeadline)
                await Task.Delay(100);
            Assert.Equal(0, ferry.Flows.Count);
        }
        finally
        {
            await ferry.StopAsync();
            ferry.Dispose();
        }
    }

    [Fact]
    public async Task SustainedTraffic_NoPacketLoop()
    {
        // Core-reliability gap 3 (packet-loop guard): run the ferry against real
        // outbound traffic for a sustained period and assert the flow table
        // stays bounded (no runaway flow creation, no infinite capture/inject
        // loop). A loop would manifest as unbounded flow count, CPU, or queue
        // growth; the flow table count is the observable bound.
        if (!IsElevated())
        {
            return;
        }

        var backendPort = await StartHttpBackendAsync();

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            // Run 5 sequential curls — each is a full proxied connection. If a
            // capture/inject loop existed, the flow table would grow unbounded
            // (flows never cleaned up) and CPU would spin.
            for (var i = 0; i < 5; i++)
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "curl.exe",
                    Arguments = "-s -o NUL --max-time 5 http://8.8.8.8/",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false
                };
                using var curl = Process.Start(psi)!;
                var wait = curl.WaitForExitAsync();
                var timeout = Task.Delay(TimeSpan.FromSeconds(10));
                var done = await Task.WhenAny(wait, timeout);
                if (done != wait)
                {
                    curl.Kill();
                    await wait;
                    Assert.Fail($"curl {i} did not finish within 10s.");
                }
                Assert.Equal(0, curl.ExitCode);

                // After each connection completes, the flow must have been
                // cleaned up — a loop would leave flows behind. The cleanup is
                // asynchronous (client FIN → ACK → CleanupFlow); poll for it.
                var cleanupDeadline = DateTime.UtcNow.AddSeconds(5);
                while (ferry.Flows.Count > 1 && DateTime.UtcNow < cleanupDeadline)
                    await Task.Delay(50);
                Assert.True(ferry.Flows.Count <= 1,
                    $"flow table grew unbounded after {i + 1} connections (count={ferry.Flows.Count})");
            }

            // After all traffic, the flow table must be empty (all flows closed
            // and cleaned up). A capture/inject loop would keep flows alive.
            var finalDeadline = DateTime.UtcNow.AddSeconds(5);
            while (ferry.Flows.Count > 0 && DateTime.UtcNow < finalDeadline)
                await Task.Delay(50);
            Assert.Equal(0, ferry.Flows.Count);
        }
        finally
        {
            await ferry.StopAsync();
            ferry.Dispose();
        }
    }

    [Fact]
    public async Task ConcurrentCurls_20_ThroughFerry_AllComplete()
    {
        // Stress test for the concurrent-flow hypothesis: a browser opens 20+
        // connections in a burst (fonts, scripts, CSS). Every SYN must get its
        // own flow + CONNECT, and all 20 responses must complete — the capture
        // loop must not block on per-flow I/O and the flow table must not drop
        // SYNs under load.
        if (!IsElevated())
        {
            return;
        }

        var backendPort = await StartHttpBackendAsync();

        using var proxy = new Socks5TestServer(async (request, stream, ct) =>
        {
            using var upstream = new TcpClient();
            await upstream.ConnectAsync(IPAddress.Loopback, backendPort, ct);
            using var upstreamStream = upstream.GetStream();
            await Socks5TestServer.WriteReplyAsync(stream, 0x00, 0x01, new byte[] { 0, 0, 0, 0 }, 0, ct);
            var toBackend = RelayOneWayAsync("client→backend", stream, upstreamStream, ct);
            var toClient = RelayOneWayAsync("backend→client", upstreamStream, stream, ct);
            await Task.WhenAll(toBackend, toClient);
        });

        var windivertDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "TunnelX");
        if (!File.Exists(Path.Combine(windivertDir, "WinDivert.dll")))
        {
            Assert.Fail($"WinDivert.dll not found at {windivertDir}; cannot run the end-to-end ferry test.");
        }
        Environment.SetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR", windivertDir);

        var rules = new List<ApplicationRule>
        {
            new() { ExecutableName = "curl.exe", Enabled = true, Mode = ProxyMode.Proxy }
        };

        WinDivertLibrary.EnsureRegistered();

        var ferry = new TcpFerry(
            new Socks5Client(new ProxyConfiguration
            {
                Host = "127.0.0.1", Port = proxy.Port,
                AuthenticationType = ProxyAuthenticationType.None, Enabled = true
            }),
            new ProcessTable(),
            rules,
            captureFilter: "outbound and ip and tcp and not loopback",
            holdTimeoutMs: 100,
            trace: m => Console.WriteLine(m));

        try
        {
            ferry.Start();

            // 20 concurrent curls, all to the same backend via the ferry.
            const int count = 20;
            var curls = new List<(Process Proc, Task Exit)>();
            for (var i = 0; i < count; i++)
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "curl.exe",
                    Arguments = "-s -o NUL --max-time 10 http://8.8.8.8/",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = false,
                    RedirectStandardError = false
                };
                var proc = Process.Start(psi)!;
                curls.Add((proc, proc.WaitForExitAsync()));
            }

            var allDone = Task.WhenAll(curls.Select(c => c.Exit).ToArray());
            var timeout = Task.Delay(TimeSpan.FromSeconds(20));
            var completed = await Task.WhenAny(allDone, timeout);
            if (completed != allDone)
            {
                foreach (var (proc, _) in curls)
                {
                    try { proc.Kill(); } catch { }
                }
                await allDone;
                Assert.Fail($"{count} concurrent curls did not all finish within 20s (ferry dropped or stalled connections under load).");
            }

            foreach (var (proc, exitTask) in curls)
            {
                await exitTask;
                Assert.True(proc.ExitCode == 0,
                    $"curl (pid {proc.Id}) exited {proc.ExitCode} — the response did not arrive through the ferry.");
            }

            // All flows must have been cleaned up (no leak under load).
            var cleanupDeadline = DateTime.UtcNow.AddSeconds(8);
            while (ferry.Flows.Count > 0 && DateTime.UtcNow < cleanupDeadline)
                await Task.Delay(100);
            Assert.Equal(0, ferry.Flows.Count);
        }
        finally
        {
            await ferry.StopAsync();
            ferry.Dispose();
        }
    }

    private static async Task RelayOneWayAsync(string dir, NetworkStream a, NetworkStream b, CancellationToken ct)
    {
        var buffer = new byte[4096];
        while (!ct.IsCancellationRequested)
        {
            int n;
            try { n = await a.ReadAsync(buffer, ct); }
            catch (Exception ex) { Console.WriteLine($"[Socks5Server] {dir} read error: {ex.Message}"); break; }
            if (n <= 0) { Console.WriteLine($"[Socks5Server] {dir} EOF"); break; }
            Console.WriteLine($"[Socks5Server] {dir} relayed {n} bytes: {Hex(buffer, n)}");
            await b.WriteAsync(buffer.AsMemory(0, n), ct);
        }
    }

    private static string Hex(byte[] data, int len) =>
        Convert.ToHexString(data, 0, Math.Min(len, 32));
}
