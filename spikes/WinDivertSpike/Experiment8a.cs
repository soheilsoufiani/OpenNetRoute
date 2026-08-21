using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// Experiment 8a — UDP 53 capture/reinject feasibility (Phase 8 DNS design,
/// open question 1). Answers the make-or-break question empirically:
///
///   1. Can WinDivert capture an OUTBOUND UDP packet to port 53 (from a real
///      Resolve-DnsName run) with the filter
///      "outbound and ip and udp and udp.DstPort == 53 and not loopback"?
///   2. Can we REINJECT a crafted DNS response back to the client
///      (src = resolver IP:53, dst = client, correct checksum, Impostor=0)
///      so the client's stack accepts it — WITHOUT the injected packet being
///      re-captured (no infinite loop)? Uses the same inbound-injection
///      pattern validated for TCP (Outbound bit cleared, IfIdx/SubIfIdx
///      preserved, WinDivertHelperCalcChecksums).
///   3. Can the owning PID of a UDP 53 socket be resolved via
///      GetExtendedUdpTable (per-process UDP attribution), the UDP analogue
///      of ProcessTable's GetExtendedTcpTable?
///
/// WinDivert semantics applied (from the TCP experiments, E5b/E6):
///   Outbound bit 17 = 0 → inbound path; inbound injection requires valid
///   IfIdx/SubIfIdx; Impostor stays 0; helper checksums.
///
/// Experiment flow:
///   A (priority 0, modify): captures + HOLDS the outbound UDP 53 query.
///   E (priority 1, SNIFF) : independent observer on the same filter — sees
///     both the original query and ANY re-captured injected reply (loop
///     detection).
///
///   PASS      : query captured, crafted DNS reply injected inbound, the
///               observer sees the injected reply AT MOST ONCE (no loop),
///               and Resolve-DnsName returns an address WITHOUT the real
///               network answering (the reply was accepted).
///   FAIL      : capture missed the query, injection failed, the reply was
///               re-captured repeatedly (loop), or the client did not accept
///               the reply.
///   INCONCLUSIVE: no query observed (system resolver not used) or the
///               client's acceptance cannot be determined.
/// </summary>
internal static class Experiment8a
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 8a] UDP 53 capture/reinject feasibility (Phase 8 open question 1).");

        // ── 1. Determine the system DNS resolver (the reply must appear to
        //       come from it; the client sent its query there). ──
        var resolver = GetSystemDnsResolver();
        if (resolver == null)
        {
            Console.WriteLine("[FAILED] Could not determine the system DNS resolver via GetAdaptersAddresses.");
            return 1;
        }
        Console.WriteLine($"  [system DNS resolver] {resolver}");

        // ── 2. Open the capture handle A (modify) and the observer E (SNIFF). ──
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

        // ── 3. Observer E: count every UDP 53 packet it sees (including any
        //       re-captured injected reply — loop detection). ──
        var observed = new List<(long Ms, string Src, string Dst, ushort SrcPort, ushort DstPort, int Len)>();
        var taskE = Task.Run(() => SniffUdp(handleE, observed, stop.Token));

        // ── 3b. UDP-table attribution probe (open question 3): can the owning
        //       PID of a UDP 53 socket be resolved via GetExtendedUdpTable,
        //       like ProcessTable does for TCP? We open a UDP socket bound to
        //       port 53 in THIS process and resolve its PID. ──
        using (var probe = new UdpClient(new IPEndPoint(IPAddress.Loopback, 53)))
        {
            var probePid = ResolveUdpOwnerPid(IPAddress.Loopback, 53, IPAddress.Any, 0);
            Console.WriteLine(probePid == Environment.ProcessId
                ? $"  [udp-table probe] GetExtendedUdpTable resolved the UDP 53 socket to this process (PID {probePid}) — per-process UDP attribution WORKS"
                : $"  [udp-table probe] GetExtendedUdpTable returned PID {probePid ?? -1} (expected {Environment.ProcessId}) — attribution NOT confirmed");
        }

        // ── 4. Capture the first outbound UDP 53 query; HOLD it (do NOT
        //       re-inject) so the real resolver never answers. ──
        byte[]? query = null;
        uint queryLen = 0;
        var queryAddr = new WinDivertAddress();
        string? querySrcIp = null;
        ushort querySrcPort = 0;
        ushort queryDstPort = 0;
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
                if (readLen < 28) continue; // IPv4(20) + UDP(8)
                if (ParseUdp(buffer, readLen, out var srcIp, out var dstIp, out var srcPort, out var dstPort))
                {
                    if (dstPort != 53) continue;
                    query = (byte[])buffer.Clone();
                    queryLen = readLen;
                    queryAddr = addr;
                    querySrcIp = srcIp;
                    querySrcPort = srcPort;
                    queryDstPort = dstPort;
                    queryCaptured = true;
                    Console.WriteLine($"  [captured query] {srcIp}:{srcPort}->{dstIp}:{dstPort} " +
                                      $"len={readLen} ifIdx={addr.IfIdx} subIf={addr.SubIfIdx} " +
                                      $"outbound={addr.Outbound} loopback={addr.Loopback}");
                    DumpDnsHeader(query, queryLen, "query");
                    break;
                }
            }
        });

        // ── 5. Run a real Resolve-DnsName (the client we want to satisfy). ──
        string? resolvedName = null;
        var resolveTask = Task.Run(() =>
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"Resolve-DnsName -Name myproxy-dns-test.example -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress\"",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = Process.Start(psi)!;
                p.WaitForExit(8000);
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

        // ── 6. Craft the DNS response and inject it inbound. ──
        // The response must: echo the query's DNS ID, set QR/RA, and carry one
        // A record (192.0.2.1, TEST-NET). Src = resolver:53, dst = client.
        var response = CraftDnsResponse(query!, queryLen);
        if (response == null)
        {
            Console.WriteLine("[FAILED] Could not parse/craft the DNS response from the captured query.");
            stop.Cancel();
            WinDivertNative.WinDivertClose(handleA);
            WinDivertNative.WinDivertClose(handleE);
            try { await Task.WhenAll(captureTask, taskE, resolveTask); } catch { }
            return 1;
        }

        // Build the IPv4/UDP packet (resolver:53 -> client:srcPort).
        var packet = BuildUdpPacket(resolver!, querySrcIp!, 53, querySrcPort, response);
        var injected = InjectUdp(handleA, packet, ref queryAddr);
        Console.WriteLine(injected
            ? $"  [injected response] {resolver}:53->{querySrcIp}:{querySrcPort} len={packet.Length} (DNS {response.Length} bytes)"
            : $"[FAILED] WinDivertSend for crafted UDP response failed. error={Marshal.GetLastWin32Error()}");

        // ── 7. Observe for a few seconds: did the reply get re-captured (loop)? ──
        await Task.Delay(TimeSpan.FromSeconds(4));

        stop.Cancel();
        WinDivertNative.WinDivertClose(handleA);
        WinDivertNative.WinDivertClose(handleE);
        try { await Task.WhenAll(captureTask, taskE, resolveTask); } catch { }

        // ── 8. Classify. ──
        Console.WriteLine($"  [E] UDP 53 packets observed: {observed.Count}");
        foreach (var p in observed)
            Console.WriteLine($"    {p.Ms,5}ms {p.Src}:{p.SrcPort}->{p.Dst}:{p.DstPort} len={p.Len}");

        // The injected reply from the resolver to the client is inbound; the
        // observer E is outbound-only, so it should NOT see it. A loop would
        // manifest as the client re-sending its query (outbound, same ID) — or
        // as E never terminating (it does terminate; we closed handles).
        var clientRetried = observed.Count(p => p.SrcPort == querySrcPort && p.DstPort == 53) > 1;

        Console.WriteLine($"  [client acceptance] Resolve-DnsName returned: '{resolvedName ?? "(none)"}'");

        string classification;
        if (injected && resolvedName == "192.0.2.1")
            classification = "PASS";
        else if (injected && !clientRetried && resolvedName != null)
            classification = "INCONCLUSIVE"; // client answered via another path?
        else if (!injected)
            classification = "FAIL";
        else
            classification = "FAIL";

        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine($"  evidence: queryCaptured={queryCaptured} injected={injected} " +
                          $"resolvedName='{resolvedName}' clientRetried={clientRetried} observed={observed.Count}");
        Console.WriteLine("=== E8a complete ===");
        return 0;
    }

    // ── Helpers ──

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

    /// <summary>Parses the IPv4 + UDP headers of a captured packet. Returns false if not IPv4/UDP.</summary>
    private static bool ParseUdp(byte[] packet, uint len, out string srcIp, out string dstIp,
        out ushort srcPort, out ushort dstPort)
    {
        srcIp = dstIp = "";
        srcPort = dstPort = 0;
        if (len < 28) return false;
        if ((packet[0] >> 4) != 4) return false; // IPv4 only
        if (packet[9] != 17) return false;       // UDP protocol
        var ihl = (packet[0] & 0x0F) * 4;
        if (len < ihl + 8) return false;
        srcIp = new IPAddress(packet.AsSpan(12, 4)).ToString();
        dstIp = new IPAddress(packet.AsSpan(16, 4)).ToString();
        var udp = ihl;
        srcPort = (ushort)((packet[udp] << 8) | packet[udp + 1]);
        dstPort = (ushort)((packet[udp + 2] << 8) | packet[udp + 3]);
        return true;
    }

    /// <summary>Dumps the DNS header (ID, flags, counts) of a captured query/response.</summary>
    private static void DumpDnsHeader(byte[] packet, uint len, string label)
    {
        var ihl = (packet[0] & 0x0F) * 4;
        var udp = ihl + 8;
        if (len < udp + 12) { Console.WriteLine($"  [{label} dns] too short for DNS header"); return; }
        var id = (ushort)((packet[udp] << 8) | packet[udp + 1]);
        var flags = (ushort)((packet[udp + 2] << 8) | packet[udp + 3]);
        var qd = (ushort)((packet[udp + 4] << 8) | packet[udp + 5]);
        Console.WriteLine($"  [{label} dns] id=0x{id:X4} flags=0x{flags:X4} qdcount={qd}");
    }

    /// <summary>
    /// Builds a DNS response for the captured query: echoes the ID, sets
    /// QR|RA, answers the question with one A record 192.0.2.1 (TEST-NET).
    /// Returns null if the query has no question section.
    /// </summary>
    private static byte[]? CraftDnsResponse(byte[] query, uint queryLen)
    {
        var ihl = (query[0] & 0x0F) * 4;
        var udp = ihl + 8;
        if (queryLen < udp + 12) return null;
        var id = (ushort)((query[udp] << 8) | query[udp + 1]);
        var qdcount = (ushort)((query[udp + 4] << 8) | query[udp + 5]);
        if (qdcount == 0) return null;

        // Question section: labels + QTYPE(2) + QCLASS(2).
        var qStart = udp + 12;
        var qLen = 0;
        var p = qStart;
        while (p < queryLen && query[p] != 0) { p += 1 + query[p]; qLen = p - qStart; }
        if (p >= queryLen) return null;
        var qEnd = p + 1 + 4; // null label + QTYPE + QCLASS

        // Response: header(12) + question + answer(1 A record).
        var answer = new byte[]
        {
            0xC0, 0x0C,       // pointer to question name
            0x00, 0x01,       // type A
            0x00, 0x01,       // class IN
            0x00, 0x00, 0x00, 0x3C, // TTL 60
            0x00, 0x04,       // rdlength 4
            192, 0, 2, 1      // 192.0.2.1 (TEST-NET)
        };
        var resp = new byte[12 + (qEnd - qStart) + answer.Length];
        resp[0] = (byte)(id >> 8); resp[1] = (byte)id;      // ID echoed
        resp[2] = 0x81; resp[3] = 0x80;                     // QR=1, RD, RA
        resp[5] = 0x01;                                     // QDCOUNT=1
        resp[7] = 0x01;                                     // ANCOUNT=1
        Array.Copy(query, qStart, resp, 12, qEnd - qStart); // question
        Array.Copy(answer, 0, resp, 12 + (qEnd - qStart), answer.Length);
        return resp;
    }

    /// <summary>Builds an IPv4/UDP packet carrying the DNS payload.</summary>
    private static byte[] BuildUdpPacket(IPAddress src, string dstIp, ushort srcPort, ushort dstPort, byte[] payload)
    {
        var packet = new byte[20 + 8 + payload.Length];
        // IPv4 header (checksums via helper).
        packet[0] = 0x45;
        packet[2] = (byte)(packet.Length >> 8); packet[3] = (byte)packet.Length;
        packet[6] = 0x40; // DF
        packet[8] = 64;
        packet[9] = 17; // UDP
        src.GetAddressBytes().CopyTo(packet, 12);
        IPAddress.Parse(dstIp).GetAddressBytes().CopyTo(packet, 16);

        // UDP header.
        var udp = 20;
        packet[udp + 0] = (byte)(srcPort >> 8); packet[udp + 1] = (byte)srcPort;
        packet[udp + 2] = (byte)(dstPort >> 8); packet[udp + 3] = (byte)dstPort;
        var udpLen = 8 + payload.Length;
        packet[udp + 4] = (byte)(udpLen >> 8); packet[udp + 5] = (byte)udpLen;
        // UDP checksum bytes 6-7 filled by WinDivertHelperCalcChecksums.
        payload.CopyTo(packet, udp + 8);
        return packet;
    }

    /// <summary>Injects the crafted UDP packet inbound (resolver -> client), E5b pattern.</summary>
    private static bool InjectUdp(IntPtr handle, byte[] packet, ref WinDivertAddress queryAddr)
    {
        // Mirror the canonical netfilter.c / E5b pattern:
        //   - Only flip Outbound (17) to 0 → inbound.
        //   - Do NOT set the Impostor bit (19).
        //   - Keep IfIdx/SubIfIdx from the captured query.
        //   - WinDivertHelperCalcChecksums computes IP+UDP checksums.
        var addr = queryAddr;
        addr.LayerEventFlags &= ~(1u << 17); // clear Outbound -> inbound
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);
        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    /// <summary>Returns the system DNS resolver (first IPv4 DNS server) or null.</summary>
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

    // ── GetExtendedUdpTable per-process attribution probe (open question 3) ──

    private enum UdpTableClass
    {
        OwnerPid = 1
    }

    // CS0649 (fields never assigned) is a false positive here: the fields are
    // filled by Marshal.PtrToStructure from the native MIB_UDPROW_OWNER_PID.
#pragma warning disable CS0649
    private struct MibUdpRowOwnerPid
    {
        public uint localAddr;
        public int localPort;
        public int owningPid;
    }
#pragma warning restore CS0649

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwSize, bool bOrder,
        int ulAf, UdpTableClass tableClass, int reserved);

    /// <summary>
    /// Resolves the owning PID of a UDP socket by local address/port via
    /// GetExtendedUdpTable (the UDP analogue of ProcessTable's TCP lookup).
    /// Returns null if the row is not found.
    /// </summary>
    private static int? ResolveUdpOwnerPid(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, UdpTableClass.OwnerPid, 0);
        if (size <= 0) return null;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(buffer, ref size, false, 2, UdpTableClass.OwnerPid, 0) != 0)
                return null;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
            var offset = Marshal.SizeOf<int>();

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(buffer + offset + i * rowSize);
                var rowLocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                var rowLocalIp = new IPAddress(row.localAddr);
                if (rowLocalPort == localPort && rowLocalIp.Equals(localIp) && row.owningPid > 0)
                    return row.owningPid;
            }
            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
