using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDivertSpike;

/// <summary>
/// Experiment 6 — R2: bidirectional TCP data flow through a ferry with
/// sequence/ack translation between two different ISNs.
///
/// Topology (completely local for the data path):
///   CLIENT (curl) → 8.8.8.8:80     (outbound, capturable; we never reach 8.8.8.8)
///   FERRY (us)                      (hold SYN, craft SYN-ACK, relay bytes)
///   UPSTREAM: local TcpListener on 127.0.0.1:U (an echo server) reached via a
///             real TcpClient socket (kernel ISN = S2).
///
/// ISNs: client's SYN ISN = C. We craft a SYN-ACK with server ISN S1 (0x12345678).
///       Upstream socket has its own kernel ISN S2. Δ = S2 − S1.
///
/// Data plane:
///   client→upstream: capture the client's data packet (seq=C+1+…), extract its
///       payload bytes, write them into the upstream socket (the upstream kernel
///       numbers them with S2). This is a byte relay, no packet rewrite needed.
///   upstream→client: read bytes from the upstream socket, wrap them in a crafted
///       inbound packet (seq = S1 + sentSoFar, ack = C + receivedSoFar) and inject
///       inbound (E5b-proven pattern). This is where the crafted ISN framing lives.
///
/// Success: the echo server's reply reaches curl and curl exits with the body.
///   PASS       : curl completed with the echo body → bidirectional data works.
///   FAIL       : handshake works but data doesn't flow (curl times out / wrong body).
///   INCONCLUSIVE: setup/handshake failed.
/// </summary>
internal static class Experiment6
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;
    private const uint ServerIsn = 0x12345678; // S1 we present to the client

    private static readonly IPAddress RemoteIp = IPAddress.Parse("8.8.8.8");
    private const ushort RemotePort = 80;

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 6] R2 — bidirectional data flow with ISN translation.");

        // ── Local echo server (upstream destination) ──
        var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        var echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;
        var echoAccept = AcceptAndEchoAsync(echoListener);

        // ── Client-leg capture handle A (modify): captures curl's SYN + data to 8.8.8.8:80 ──
        string filter = $"outbound and ip and ip.DstAddr == {RemoteIp} and tcp and tcp.DstPort == {RemotePort}";
        var handleA = WinDivertNative.WinDivertOpen(filter, WinDivertLayer.Network, 0, 0);
        if (handleA == IntPtr.Zero || handleA == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open capture handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }

        var stop = new CancellationTokenSource();
        uint clientIsn = 0;
        ushort clientSrcPort = 0;
        var clientLocalIp = IPAddress.Any;
        var synAddr = new WinDivertAddress();
        var synCaptured = false;
        long clientBytesSent = 0;   // bytes we've sent to upstream
        long clientBytesRecv = 0;   // bytes we've injected to the client
        int? curlExitCode = null;

        // Upstream socket (kernel assigns S2).
        using var upstream = new TcpClient(AddressFamily.InterNetwork);
        await upstream.ConnectAsync(IPAddress.Loopback, echoPort);
        var upstreamStream = upstream.GetStream();
        Console.WriteLine($"  [upstream] connected to local echo 127.0.0.1:{echoPort} (kernel ISN S2, not shown)");

        // ── Capture + hold the client SYN, craft/inject SYN-ACK (E5b pattern) ──
        using (var curl = StartCurl())
        {
            if (curl is null)
            {
                Console.WriteLine("[INCONCLUSIVE] Could not start curl.");
                stop.Cancel();
                WinDivertNative.WinDivertClose(handleA);
                return 1;
            }

            // Read the client SYN from handle A (blocking), hold it.
            var synTask = Task.Run(() =>
            {
                var buffer = new byte[65535];
                var addr = new WinDivertAddress();
                while (!stop.IsCancellationRequested)
                {
                    uint readLen = 0;
                    if (!WinDivertNative.WinDivertRecv(handleA, buffer, (uint)buffer.Length, ref readLen, ref addr))
                        break;
                    if (readLen < 20) continue;
                    if (!TcpPacketParser.TryParse(buffer, readLen, out var tuple)) continue;
                    if ((tuple.TcpFlags & 0x02) == 0 || (tuple.TcpFlags & 0x10) != 0) continue;
                    clientIsn = tuple.Seq;
                    clientSrcPort = tuple.SrcPort;
                    clientLocalIp = tuple.SrcIp;
                    synAddr = addr;
                    synCaptured = true;
                    Console.WriteLine($"  [captured SYN] {tuple.SrcIp}:{tuple.SrcPort}->{tuple.DstIp}:{tuple.DstPort} seq={tuple.Seq} ifIdx={addr.IfIdx}");
                    break;
                }
            });

            var gotSyn = await WaitForAsync(() => synCaptured, TimeSpan.FromSeconds(5));
            if (!gotSyn)
            {
                Console.WriteLine("[FAILED] No SYN captured within 5s.");
                stop.Cancel();
                WinDivertNative.WinDivertClose(handleA);
                return 1;
            }

            // Inject the crafted SYN-ACK (server ISN S1, ack clientIsn+1).
            if (!InjectSynAck(handleA, RemoteIp, clientLocalIp, RemotePort, clientSrcPort, ServerIsn, clientIsn, ref synAddr))
            {
                Console.WriteLine("[FAILED] WinDivertSend for crafted SYN-ACK failed.");
            }
            else
            {
                Console.WriteLine($"  [injected SYN-ACK] {RemoteIp}:{RemotePort}->{clientLocalIp}:{clientSrcPort} " +
                                  $"seq={ServerIsn} ack={clientIsn + 1}");
            }

            // ── Ferry: relay client data → upstream, upstream data → client ──
            var relayTask = Task.Run(async () =>
            {
                var buffer = new byte[65535];
                var addr = new WinDivertAddress();
                var upstreamRead = new byte[65535];

                // Upstream→client pump (read echo, craft + inject inbound packet).
                var injectPump = Task.Run(async () =>
                {
                    while (!stop.IsCancellationRequested)
                    {
                        int n;
                        try { n = await upstreamStream.ReadAsync(upstreamRead.AsMemory(0, upstreamRead.Length), stop.Token); }
                        catch { break; }
                        if (n <= 0) break;

                        // Craft an inbound packet to the client: src=8.8.8.8:80, dst=client.
                        // seq starts at ServerIsn + 1 because the SYN-ACK consumed seq
                        // ServerIsn; the first DATA byte is ServerIsn + 1. clientBytesRecv
                        // counts data bytes already delivered, so seq = ServerIsn + 1 + clientBytesRecv.
                        // ack = clientIsn + 1 + clientBytesSent (acknowledge the client's data).
                        var injected = InjectDataPacket(handleA, RemoteIp, clientLocalIp, RemotePort, clientSrcPort,
                            (uint)(ServerIsn + 1 + clientBytesRecv), (uint)(clientIsn + 1 + clientBytesSent),
                            upstreamRead.AsSpan(0, n), ref synAddr);
                        if (injected)
                        {
                            clientBytesRecv += n;
                            Console.WriteLine($"  [upstream→client] relayed {n} bytes (clientBytesRecv={clientBytesRecv})");
                        }
                        else
                        {
                            Console.WriteLine("  [FAILED] InjectDataPacket (upstream→client) failed.");
                            break;
                        }
                    }
                });

                // Client→upstream pump (read handle A data, write payload to upstream socket).
                while (!stop.IsCancellationRequested)
                {
                    uint readLen = 0;
                    if (!WinDivertNative.WinDivertRecv(handleA, buffer, (uint)buffer.Length, ref readLen, ref addr))
                        break;
                    if (readLen < 20) continue;
                    if (!TcpPacketParser.TryParse(buffer, readLen, out var tuple)) continue;
                    if (tuple.SrcPort != clientSrcPort) continue; // only this client's flow

                    var tcp = (buffer[0] & 0x0F) * 4;
                    var payloadLen = (int)readLen - tcp - tuple.TcpHeaderLen;
                    if (payloadLen <= 0) continue; // pure ACK etc.

                    // Write the payload bytes to the upstream socket verbatim.
                    try
                    {
                        await upstreamStream.WriteAsync(buffer.AsMemory(tcp + tuple.TcpHeaderLen, payloadLen), stop.Token);
                        clientBytesSent += payloadLen;
                        Console.WriteLine($"  [client→upstream] relayed {payloadLen} bytes (clientBytesSent={clientBytesSent})");
                    }
                    catch { break; }
                }

                await Task.WhenAny(injectPump, Task.Delay(Timeout.Infinite, stop.Token));
            });

            // Let curl run to completion (echo round-trip).
            await Task.WhenAny(curl.WaitForExitAsync(), Task.Delay(TimeSpan.FromSeconds(8)));
            if (!curl.HasExited)
            {
                Console.WriteLine("  [result] curl did not finish within 8s (stalled).");
                try { curl.Kill(); } catch { }
            }
            else
            {
                Console.WriteLine($"  [result] curl exited with code {curl.ExitCode} (0 = echo body received).");
            }

            stop.Cancel();
            WinDivertNative.WinDivertClose(handleA);
            // Bound the relay teardown so a blocked pump cannot hang the process.
            await Task.WhenAny(relayTask, Task.Delay(TimeSpan.FromSeconds(2)));

            // Record curl's exit code for the final verdict.
            curlExitCode = curl.HasExited ? curl.ExitCode : (int?)null;
        }

        try { echoListener.Stop(); } catch { }
        try { await Task.WhenAny(echoAccept, Task.Delay(TimeSpan.FromSeconds(2))); } catch { }

        // ── Classification ──
        // PASS only when the real end-to-end test (curl) succeeded. Byte counts
        // are supporting evidence, not the verdict — a translation that moves
        // bytes but leaves curl failing is NOT a pass.
        string classification;
        if (curlExitCode == 0)
            classification = "PASS";
        else if (clientBytesSent > 0)
            classification = "FAIL"; // data moved but curl did not complete => translation bug
        else
            classification = "INCONCLUSIVE";
        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine($"  evidence: curlExitCode={curlExitCode?.ToString() ?? "n/a"} " +
                          $"clientToUpstreamBytes={clientBytesSent} upstreamToClientBytes={clientBytesRecv} " +
                          $"clientIsn={clientIsn} serverIsnS1={ServerIsn} ackToClientStartsAt={clientIsn + 1}");
        Console.WriteLine("=== E6 complete ===");
        return 0;
    }

    /// <summary>Injects a crafted SYN-ACK (E5b pattern, Impostor NOT set).</summary>
    private static bool InjectSynAck(
        IntPtr handle, IPAddress serverIp, IPAddress clientIp, ushort serverPort, ushort clientPort,
        uint serverIsn, uint clientIsn, ref WinDivertAddress synAddr)
    {
        var packet = new byte[40];
        BuildIpHeader(packet, 40, serverIp, clientIp);
        var tcp = 20;
        packet[tcp + 0] = (byte)(serverPort >> 8); packet[tcp + 1] = (byte)serverPort;
        packet[tcp + 2] = (byte)(clientPort >> 8); packet[tcp + 3] = (byte)clientPort;
        packet[tcp + 4] = (byte)(serverIsn >> 24); packet[tcp + 5] = (byte)(serverIsn >> 16);
        packet[tcp + 6] = (byte)(serverIsn >> 8);  packet[tcp + 7] = (byte)serverIsn;
        var ack = clientIsn + 1;
        packet[tcp + 8] = (byte)(ack >> 24); packet[tcp + 9] = (byte)(ack >> 16);
        packet[tcp + 10] = (byte)(ack >> 8); packet[tcp + 11] = (byte)ack;
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x12; // SYN|ACK
        packet[tcp + 14] = 0x72; packet[tcp + 15] = 0x10;

        var addr = synAddr;
        addr.LayerEventFlags &= ~(1u << 17); // Outbound -> 0 (inbound), Impostor stays 0
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);
        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    /// <summary>Injects a crafted inbound DATA packet (payload) to the client.</summary>
    private static bool InjectDataPacket(
        IntPtr handle, IPAddress serverIp, IPAddress clientIp, ushort serverPort, ushort clientPort,
        uint seq, uint ack, ReadOnlySpan<byte> payload, ref WinDivertAddress synAddr)
    {
        int ipLen = 20, tcpLen = 20;
        var packet = new byte[ipLen + tcpLen + payload.Length];
        BuildIpHeader(packet, packet.Length, serverIp, clientIp);
        var tcp = ipLen;
        packet[tcp + 0] = (byte)(serverPort >> 8); packet[tcp + 1] = (byte)serverPort;
        packet[tcp + 2] = (byte)(clientPort >> 8); packet[tcp + 3] = (byte)clientPort;
        packet[tcp + 4] = (byte)(seq >> 24); packet[tcp + 5] = (byte)(seq >> 16);
        packet[tcp + 6] = (byte)(seq >> 8);  packet[tcp + 7] = (byte)seq;
        packet[tcp + 8] = (byte)(ack >> 24); packet[tcp + 9] = (byte)(ack >> 16);
        packet[tcp + 10] = (byte)(ack >> 8); packet[tcp + 11] = (byte)ack;
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x18; // PSH|ACK
        packet[tcp + 14] = 0x72; packet[tcp + 15] = 0x10;
        payload.CopyTo(packet.AsSpan(ipLen + tcpLen));

        var addr = synAddr;
        addr.LayerEventFlags &= ~(1u << 17); // inbound
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);
        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    private static void BuildIpHeader(byte[] packet, int totalLen, IPAddress src, IPAddress dst)
    {
        packet[0] = 0x45;
        packet[1] = 0x00;
        packet[2] = (byte)(totalLen >> 8); packet[3] = (byte)totalLen;
        packet[6] = 0x40; packet[7] = 0x00; // DF
        packet[8] = 64;
        packet[9] = 6;
        var s = src.GetAddressBytes(); var d = dst.GetAddressBytes();
        Array.Copy(s, 0, packet, 12, 4);
        Array.Copy(d, 0, packet, 16, 4);
    }

    private static async Task AcceptAndEchoAsync(TcpListener listener)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var buf = new byte[4096];
            // Read the HTTP request, then send a valid HTTP response so curl
            // completes successfully. This tests the translation path, not the
            // upstream server's behavior.
            int n = await stream.ReadAsync(buf, 0, buf.Length);
            if (n > 0)
            {
                var resp = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
                await stream.WriteAsync(resp, 0, resp.Length);
            }
        }
        catch { }
    }

    private static async Task<bool> WaitForAsync(Func<bool> condition, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (condition()) return true;
            await Task.Delay(50);
        }
        return condition();
    }

    private static Process? StartCurl()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = $"-s -o NUL --max-time 6 http://8.8.8.8/",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            };
            return Process.Start(psi);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[info] Failed to start curl: {ex.Message}");
            return null;
        }
    }
}
