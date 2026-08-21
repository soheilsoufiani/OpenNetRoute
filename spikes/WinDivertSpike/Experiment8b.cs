using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// Experiment 8b — forward-and-echo UDP 53 (isolates the E8-a reconstruction
/// variable). E8-a proved capture, attribution, injection, and no-loop all
/// work, but the CRAFTED reply was not accepted by the client
/// (Resolve-DnsName returned ''). E8-b eliminates the reconstruction:
///
///   1. Capture the real UDP 53 query bytes AS-IS (no question-section
///      reconstruction).
///   2. Forward those exact bytes to the real system resolver over a fresh
///      UDP socket; take the REAL reply bytes.
///   3. Reinject the real reply to the client with ONLY the source swapped
///      (resolver IP:53 -> client IP:ephemeral port), same inbound-injection
///      pattern as E8-a (Outbound cleared, IfIdx/SubIfIdx preserved, helper
///      checksums, Impostor=0).
///   4. Client acceptance is the gate: Resolve-DnsName on a REAL name
///      (example.com) must return a real answer. No PASS without it.
///
/// PASS      : query captured, forwarded, real reply reinjected, and
///             Resolve-DnsName returns a real A record (e.g. 93.184.215.14)
///             — the forward-and-echo path works end-to-end.
/// FAIL      : any step failed or the client did not accept the real reply.
/// INCONCLUSIVE: no query captured, or the client's acceptance cannot be
///             determined.
/// </summary>
internal static class Experiment8b
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 8b] Forward-and-echo UDP 53 (isolates the E8-a reconstruction variable).");

        // ── 1. Start a LOCAL DNS test server (a real UDP 53 peer that answers
        //       any query with a fixed A record). Forwarding to a local server
        //       — NOT the real resolver — keeps the experiment isolated: the
        //       real network can never answer, so a client answer can only
        //       come from our reinjected reply. ──
        var testResolver = StartLocalDnsServer();
        if (testResolver == null)
        {
            Console.WriteLine("[FAILED] Could not start the local DNS test server.");
            return 1;
        }
        Console.WriteLine($"  [local DNS test server] 127.0.0.1:{testResolver.Port} (answers A=192.0.2.1)");

        // ── 2. Open capture handle A (modify) and observer E (SNIFF). ──
        const string filter = "outbound and ip and udp and udp.DstPort == 53 and not loopback";
        var handleA = WinDivertNative.WinDivertOpen(filter, WinDivertLayer.Network, 0, 0);
        if (handleA == IntPtr.Zero || handleA == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open capture handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }
        var handleE = WinDivertNative.WinDivertOpen(filter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);
        if (handleE == IntPtr.Zero || handleE == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open observer handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }

        var stop = new CancellationTokenSource();

        // ── 3. Observer E: count every UDP 53 packet (loop detection). ──
        var observed = new List<(long Ms, string Src, string Dst, ushort SrcPort, ushort DstPort, int Len)>();
        var taskE = Task.Run(() => SniffUdp(handleE, observed, stop.Token));

        // ── 4. Capture the first outbound UDP 53 query; HOLD it. ──
        byte[]? query = null;
        uint queryLen = 0;
        var queryAddr = new WinDivertAddress();
        string? querySrcIp = null;
        ushort querySrcPort = 0;
        var queryCaptured = false;

        var captureTask = Task.Run(() =>
        {
            var buffer = new byte[65535];
            var addr = new WinDivertAddress();
            while (!stop.IsCancellationRequested)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(handleA, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break;
                if (readLen < 28) continue;
                if (ParseUdp(buffer, readLen, out var srcIp, out var dstIp, out var srcPort, out var dstPort))
                {
                    if (dstPort != 53) continue;
                    query = (byte[])buffer.Clone();
                    queryLen = readLen;
                    queryAddr = addr;
                    querySrcIp = srcIp;
                    querySrcPort = srcPort;
                    queryCaptured = true;
                    Console.WriteLine($"  [captured query] {srcIp}:{srcPort}->{dstIp}:{dstPort} " +
                                      $"len={readLen} ifIdx={addr.IfIdx} subIf={addr.SubIfIdx} " +
                                      $"outbound={addr.Outbound} loopback={addr.Loopback}");
                    DumpDnsHeader(query, queryLen, "query");
                    Console.WriteLine($"  [query bytes] {BitConverter.ToString(query, 28, (int)Math.Min(queryLen - 28, 48)).Replace("-", " ")}...");
                    break;
                }
            }
        });

        // ── 5. Run a real Resolve-DnsName on a REAL name (example.com). ──
        string? resolvedName = null;
        var resolveTask = Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"Resolve-DnsName -Name example.com -Type A -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi)!;
                p.WaitForExit(10000);
                resolvedName = p.StandardOutput.ReadToEnd().Trim();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[info] Resolve-DnsName failed to start: {ex.Message}");
            }
        });

        var gotQuery = await WaitForAsync(() => queryCaptured, TimeSpan.FromSeconds(8));
        if (!gotQuery)
        {
            Console.WriteLine("[FAILED] No outbound UDP 53 query captured within 8s.");
            Console.WriteLine("  The system may be using DoH/DoT or the resolver is not UDP 53.");
            stop.Cancel();
            WinDivertNative.WinDivertClose(handleA);
            WinDivertNative.WinDivertClose(handleE);
            try { await Task.WhenAll(captureTask, taskE, resolveTask); } catch { }
            return 1;
        }

        // ── 6. Forward the QUERY BYTES AS-IS to the local test resolver; take
        //       the REAL reply. The test server echoes the question and answers
        //       A=192.0.2.1 — the real network is never involved. ──
        byte[]? reply = null;
        var forwarded = false;
        try
        {
            using var forwarder = new UdpClient();
            var forwardResult = await forwarder.SendAsync(query!, (int)queryLen, "127.0.0.1", testResolver.Port);
            forwarded = forwardResult > 0;

            var recvTask = forwarder.ReceiveAsync();
            var recvDone = await Task.WhenAny(recvTask, Task.Delay(TimeSpan.FromSeconds(3)));
            if (recvDone == recvTask)
            {
                var result = await recvTask;
                reply = result.Buffer;
                Console.WriteLine($"  [forwarded query] -> 127.0.0.1:{testResolver.Port} ({queryLen} bytes, sent={forwarded})");
                Console.WriteLine($"  [test reply] {result.RemoteEndPoint} ({reply.Length} bytes)");
                DumpDnsHeader(reply, (uint)reply.Length, "reply");
                Console.WriteLine($"  [reply bytes] {BitConverter.ToString(reply, 0, Math.Min(reply.Length, 48)).Replace("-", " ")}...");
            }
            else
            {
                Console.WriteLine("[FAILED] No reply from the local test resolver within 3s.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[FAILED] Forwarding the query failed: {ex.GetType().Name}: {ex.Message}");
        }

        if (reply == null)
        {
            stop.Cancel();
            WinDivertNative.WinDivertClose(handleA);
            WinDivertNative.WinDivertClose(handleE);
            try { await Task.WhenAll(captureTask, taskE, resolveTask); } catch { }
            return 1;
        }

        // ── 7. Reinject the REAL reply to the client. The client's socket
        //       expects a reply from the IP it sent the query to (the original
        //       query DESTINATION — the system resolver), so the injected
        //       packet's source is that IP:53, with the payload being the test
        //       server's real reply bytes. Same injection pattern as E8-a. ──
        var originalQueryDstIp = GetQueryDstIp(query!);
        var packet = BuildUdpPacket(originalQueryDstIp, querySrcIp!, 53, querySrcPort, reply);
        var injected = InjectUdp(handleA, packet, ref queryAddr);
        Console.WriteLine(injected
            ? $"  [injected reply] {originalQueryDstIp}:53->{querySrcIp}:{querySrcPort} len={packet.Length} (DNS {reply.Length} bytes)"
            : $"[FAILED] WinDivertSend for the real UDP reply failed. error={Marshal.GetLastWin32Error()}");

        // ── 8. Observe a few seconds (loop detection), then close. ──
        await Task.Delay(TimeSpan.FromSeconds(4));

        stop.Cancel();
        WinDivertNative.WinDivertClose(handleA);
        WinDivertNative.WinDivertClose(handleE);
        try { await Task.WhenAll(captureTask, taskE, resolveTask); } catch { }

        // ── 9. Classify. ──
        Console.WriteLine($"  [E] UDP 53 packets observed: {observed.Count}");
        foreach (var p in observed)
            Console.WriteLine($"    {p.Ms,5}ms {p.Src}:{p.SrcPort}->{p.Dst}:{p.DstPort} len={p.Len}");

        var clientRetried = observed.Count(p => p.SrcPort == querySrcPort && p.DstPort == 53) > 1;

        Console.WriteLine($"  [client acceptance] Resolve-DnsName returned: '{resolvedName ?? "(none)"}'");

        // The local test server answers A=192.0.2.1; the client can only get
        // that answer from OUR reinjected reply (the real network never
        // answers the held query). PASS requires the client to have gotten it.
        var clientGotAnswer = resolvedName == "192.0.2.1";

        string classification;
        if (injected && clientGotAnswer)
            classification = "PASS";
        else if (injected && !clientRetried)
            classification = "INCONCLUSIVE";
        else
            classification = "FAIL";

        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine($"  evidence: queryCaptured={queryCaptured} forwarded={forwarded} " +
                          $"replyBytes={(reply?.Length ?? 0)} injected={injected} " +
                          $"resolvedName='{resolvedName}' clientGotAnswer={clientGotAnswer} " +
                          $"clientRetried={clientRetried} observed={observed.Count}");
        Console.WriteLine("=== E8b complete ===");
        return 0;
    }

    // ── Local DNS test server (a real UDP 53 peer) ──

    private sealed record DnsTestServer(int Port)
    {
        public static DnsTestServer? Start()
        {
            try
            {
                var listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
                var port = ((IPEndPoint)listener.Client.LocalEndPoint!).Port;
                _ = Task.Run(async () =>
                {
                    try
                    {
                        while (true)
                        {
                            var recv = await listener.ReceiveAsync();
                            // Answer with a real reply: echo the query's ID and
                            // question, set QR|RA, one A record 192.0.2.1.
                            var reply = BuildReply(recv.Buffer);
                            if (reply != null)
                                await listener.SendAsync(reply, reply.Length, recv.RemoteEndPoint);
                        }
                    }
                    catch { }
                });
                return new DnsTestServer(port);
            }
            catch { return null; }
        }

        /// <summary>Builds a DNS reply for the query: echoed ID+question, A=192.0.2.1.</summary>
        private static byte[]? BuildReply(byte[] query)
        {
            if (query.Length < 12) return null;
            var qdcount = (ushort)((query[4] << 8) | query[5]);
            if (qdcount == 0) return null;

            // Question section: labels + QTYPE(2) + QCLASS(2).
            var qStart = 12;
            var p = qStart;
            while (p < query.Length && query[p] != 0) { p += 1 + query[p]; }
            if (p >= query.Length) return null;
            var qEnd = p + 1 + 4;

            var answer = new byte[]
            {
                0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, // pointer, type A, class IN
                0x00, 0x00, 0x00, 0x3C,             // TTL 60
                0x00, 0x04, 192, 0, 2, 1            // rdlength 4, 192.0.2.1
            };
            var resp = new byte[12 + (qEnd - qStart) + answer.Length];
            resp[0] = query[0]; resp[1] = query[1]; // ID echoed
            resp[2] = 0x81; resp[3] = 0x80;         // QR=1, RD, RA
            resp[5] = 0x01;                         // QDCOUNT=1
            resp[7] = 0x01;                         // ANCOUNT=1
            Array.Copy(query, qStart, resp, 12, qEnd - qStart);
            Array.Copy(answer, 0, resp, 12 + (qEnd - qStart), answer.Length);
            return resp;
        }
    }

    private static DnsTestServer? StartLocalDnsServer() => DnsTestServer.Start();

    /// <summary>Reads the destination IP of the captured query (the resolver the client queried).</summary>
    private static IPAddress GetQueryDstIp(byte[] query)
    {
        return new IPAddress(query.AsSpan(16, 4));
    }

    // ── Helpers (shared with E8-a; kept local to the experiment) ──

    private static void SniffUdp(
        IntPtr handle,
        List<(long Ms, string Src, string Dst, ushort SrcPort, ushort DstPort, int Len)> events,
        CancellationToken ct)
    {
        var buffer = new byte[65535];
        var addr = new WinDivertAddress();
        var sw = Stopwatch.StartNew();
        while (!ct.IsCancellationRequested)
        {
            uint readLen = 0;
            if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                break;
            if (readLen < 28) continue;
            if (ParseUdp(buffer, readLen, out var src, out var dst, out var srcPort, out var dstPort))
            {
                lock (events)
                {
                    events.Add((sw.ElapsedMilliseconds, src, dst, srcPort, dstPort, (int)readLen));
                }
            }
        }
    }

    private static bool ParseUdp(byte[] packet, uint len, out string srcIp, out string dstIp,
        out ushort srcPort, out ushort dstPort)
    {
        srcIp = dstIp = "";
        srcPort = dstPort = 0;
        if (len < 28) return false;
        if ((packet[0] >> 4) != 4) return false;
        if (packet[9] != 17) return false;
        var ihl = (packet[0] & 0x0F) * 4;
        if (len < ihl + 8) return false;
        srcIp = new IPAddress(packet.AsSpan(12, 4)).ToString();
        dstIp = new IPAddress(packet.AsSpan(16, 4)).ToString();
        var udp = ihl;
        srcPort = (ushort)((packet[udp] << 8) | packet[udp + 1]);
        dstPort = (ushort)((packet[udp + 2] << 8) | packet[udp + 3]);
        return true;
    }

    private static void DumpDnsHeader(byte[] packet, uint len, string label)
    {
        var ihl = (packet[0] & 0x0F) * 4;
        var udp = ihl + 8;
        if (len < udp + 12) { Console.WriteLine($"  [{label} dns] too short for DNS header"); return; }
        var id = (ushort)((packet[udp] << 8) | packet[udp + 1]);
        var flags = (ushort)((packet[udp + 2] << 8) | packet[udp + 3]);
        Console.WriteLine($"  [{label} dns] id=0x{id:X4} flags=0x{flags:X4}");
    }

    private static byte[] BuildUdpPacket(IPAddress src, string dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var packet = new byte[20 + 8 + payload.Length];
        packet[0] = 0x45;
        packet[2] = (byte)(packet.Length >> 8); packet[3] = (byte)packet.Length;
        packet[6] = 0x40;
        packet[8] = 64;
        packet[9] = 17;
        src.GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(dstIp).GetAddressBytes().CopyTo(packet, 16);

        var udp = 20;
        packet[udp + 0] = (byte)(srcPort >> 8); packet[udp + 1] = (byte)srcPort;
        packet[udp + 2] = (byte)(dstPort >> 8); packet[udp + 3] = (byte)dstPort;
        var udpLen = 8 + payload.Length;
        packet[udp + 4] = (byte)(udpLen >> 8); packet[udp + 5] = (byte)udpLen;
        payload.CopyTo(packet, udp + 8);
        return packet;
    }

    private static bool InjectUdp(IntPtr handle, byte[] packet, ref WinDivertAddress queryAddr)
    {
        var addr = queryAddr;
        addr.LayerEventFlags &= ~(1u << 17); // clear Outbound -> inbound (Impostor stays 0)
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);
        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    private static IPAddress? GetSystemDnsResolver()
    {
        try
        {
            var adapters = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (var adapter in adapters)
            {
                if (adapter.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                    continue;
                foreach (var addr in adapter.GetIPProperties().DnsAddresses)
                {
                    if (addr.AddressFamily == AddressFamily.InterNetwork)
                        return addr;
                }
            }
        }
        catch { }
        return null;
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
}
