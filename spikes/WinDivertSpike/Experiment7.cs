using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// Experiment 7 — R1 (SYN-time process attribution) + R4 (hold-SYN tolerance)
/// in ONE experiment.
///
/// R1: can we attribute a captured outbound SYN to its owning process at SYN
///     time via GetExtendedTcpTable, before the connection is established?
/// R4: can we HOLD that SYN for a controlled duration D and still have the
///     client accept our crafted SYN-ACK (i.e. without the client retransmitting
///     so badly the handshake fails)?
///
/// Client: curl → 8.8.8.8:80 (no external data path — we never reach 8.8.8.8).
/// Flow:
///   1. capture + hold the SYN (handle A);
///   2. poll GetExtendedTcpTable for (localIP, localPort, remoteIP, remotePort)
///      → owning PID; record if/when found and confirm it is curl;
///   3. sleep D ms (hold duration);
///   4. inject crafted SYN-ACK (E5b pattern);
///   5. observe (handle E, outbound) whether the client ACKs (ack=S1+1).
///
/// PASS       : attribution found curl AND client ACKed after hold D.
/// FAIL       : attribution failed (FAIL-R1) OR attribution ok but no client ACK
///              after hold D (FAIL-R4).
/// INCONCLUSIVE: no SYN captured / setup failure.
/// </summary>
internal static class Experiment7
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;
    private const uint ServerIsn = 0x12345678;
    private const int HoldMs = 600; // R4: controlled hold duration (< ~1s retransmit)

    private static readonly IPAddress RemoteIp = IPAddress.Parse("8.8.8.8");
    private const ushort RemotePort = 80;

    public static async Task<int> RunAsync()
    {
        Console.WriteLine($"[Experiment 7] R1 (SYN-time attribution) + R4 (hold-SYN {HoldMs}ms).");

        string filter = $"outbound and ip and ip.DstAddr == {RemoteIp} and tcp and tcp.DstPort == {RemotePort}";
        var handleA = WinDivertNative.WinDivertOpen(filter, WinDivertLayer.Network, 0, 0);
        var handleE = WinDivertNative.WinDivertOpen(filter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);
        if (handleA == IntPtr.Zero || handleA == new IntPtr(-1) ||
            handleE == IntPtr.Zero || handleE == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open handles. A={handleA} E={handleE}");
            return 1;
        }

        var stop = new CancellationTokenSource();
        var observedOut = new List<(long Ms, ushort SrcPort, byte Flags, uint Seq, uint Ack)>();
        var taskE = Task.Run(() => SniffOutbound(handleE, observedOut, stop.Token));

        uint clientIsn = 0; ushort clientSrcPort = 0; var clientLocalIp = IPAddress.Any;
        var synAddr = new WinDivertAddress(); var synCaptured = false;
        int? attributionPid = null; long attributionMs = -1; string? attributionName = null;

        var captureTask = Task.Run(() =>
        {
            var buffer = new byte[65535];
            var addr = new WinDivertAddress();
            while (!stop.IsCancellationRequested)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(handleA, buffer, (uint)buffer.Length, ref readLen, ref addr)) break;
                if (readLen < 20) continue;
                if (!TcpPacketParser.TryParse(buffer, readLen, out var tuple)) continue;
                if ((tuple.TcpFlags & 0x02) == 0 || (tuple.TcpFlags & 0x10) != 0) continue;
                clientIsn = tuple.Seq; clientSrcPort = tuple.SrcPort; clientLocalIp = tuple.SrcIp;
                synAddr = addr; synCaptured = true;
                Console.WriteLine($"  [captured SYN] {tuple.SrcIp}:{tuple.SrcPort}->{tuple.DstIp}:{tuple.DstPort} seq={tuple.Seq} ifIdx={addr.IfIdx}");
                break;
            }
        });

        using (var curl = StartCurl())
        {
            if (curl is null) { Console.WriteLine("[INCONCLUSIVE] Could not start curl."); stop.Cancel(); await Task.WhenAll(captureTask, taskE); return 1; }

            var gotSyn = await WaitForAsync(() => synCaptured, TimeSpan.FromSeconds(5));
            if (!gotSyn) { Console.WriteLine("[FAILED] No SYN captured within 5s."); stop.Cancel(); WinDivertNative.WinDivertClose(handleA); WinDivertNative.WinDivertClose(handleE); return 1; }

            // ── R1: poll GetExtendedTcpTable for the owning PID ──
            var sw = Stopwatch.StartNew();
            var deadline = sw.Elapsed + TimeSpan.FromSeconds(2);
            while (sw.Elapsed < deadline && !attributionPid.HasValue)
            {
                attributionPid = TcpTableLookup.FindOwnerPid(clientLocalIp, clientSrcPort, RemoteIp, RemotePort);
                if (attributionPid.HasValue)
                {
                    attributionMs = sw.ElapsedMilliseconds;
                    try { attributionName = Process.GetProcessById(attributionPid.Value).ProcessName; } catch { attributionName = "<unresolvable>"; }
                    break;
                }
                await Task.Delay(10);
            }
            Console.WriteLine($"  [R1 attribution] pid={attributionPid?.ToString() ?? "NOT FOUND"} name={attributionName ?? "n/a"} after={attributionMs}ms");

            // ── R4: hold the SYN for HoldMs, then inject crafted SYN-ACK ──
            await Task.Delay(HoldMs);
            var injected = InjectSynAck(handleA, RemoteIp, clientLocalIp, RemotePort, clientSrcPort, ServerIsn, clientIsn, ref synAddr);
            Console.WriteLine($"  [held {HoldMs}ms] injected SYN-ACK seq={ServerIsn} ack={clientIsn + 1}: {injected}");

            // Observe the client's reaction for a short window.
            await Task.Delay(TimeSpan.FromSeconds(2));
            if (!curl.HasExited) { try { curl.Kill(); } catch { } }
        }

        stop.Cancel(); WinDivertNative.WinDivertClose(handleA); WinDivertNative.WinDivertClose(handleE);
        await Task.WhenAny(Task.WhenAll(captureTask, taskE), Task.Delay(TimeSpan.FromSeconds(2)));

        Console.WriteLine($"  [E] outbound packets: {observedOut.Count}");
        foreach (var p in observedOut)
            Console.WriteLine($"    {p.Ms,5}ms {p.SrcPort}->80 flags=0x{p.Flags:X2} seq={p.Seq} ack={p.Ack}");

        var clientAck = observedOut.Any(p => p.SrcPort == clientSrcPort && (p.Flags & 0x10) != 0 && p.Ack == ServerIsn + 1);
        var synRetransmit = observedOut.Any(p => p.SrcPort == clientSrcPort && (p.Flags & 0x02) != 0 && p.Seq == clientIsn);

        // ── Classification ──
        string classification;
        if (!attributionPid.HasValue)
            classification = "FAIL-R1";
        else if (clientAck)
            classification = "PASS";
        else if (synRetransmit)
            classification = "FAIL-R4";
        else
            classification = "INCONCLUSIVE";

        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine($"  evidence: attributionPid={attributionPid?.ToString() ?? "none"} name={attributionName ?? "n/a"} " +
                          $"attributionMs={attributionMs} holdMs={HoldMs} clientAck={clientAck} synRetransmit={synRetransmit}");
        Console.WriteLine("=== E7 complete ===");
        return 0;
    }

    /// <summary>Injects a crafted SYN-ACK (E5b pattern, Impostor NOT set).</summary>
    private static bool InjectSynAck(IntPtr handle, IPAddress serverIp, IPAddress clientIp, ushort serverPort,
        ushort clientPort, uint serverIsn, uint clientIsn, ref WinDivertAddress synAddr)
    {
        var packet = new byte[40];
        packet[0] = 0x45; packet[1] = 0x00; packet[2] = 0x00; packet[3] = 40;
        packet[6] = 0x40; packet[7] = 0x00; packet[8] = 64; packet[9] = 6;
        Array.Copy(serverIp.GetAddressBytes(), 0, packet, 12, 4);
        Array.Copy(clientIp.GetAddressBytes(), 0, packet, 16, 4);
        int tcp = 20;
        packet[tcp + 0] = (byte)(serverPort >> 8); packet[tcp + 1] = (byte)serverPort;
        packet[tcp + 2] = (byte)(clientPort >> 8); packet[tcp + 3] = (byte)clientPort;
        packet[tcp + 4] = (byte)(serverIsn >> 24); packet[tcp + 5] = (byte)(serverIsn >> 16);
        packet[tcp + 6] = (byte)(serverIsn >> 8);  packet[tcp + 7] = (byte)serverIsn;
        var ack = clientIsn + 1;
        packet[tcp + 8] = (byte)(ack >> 24); packet[tcp + 9] = (byte)(ack >> 16);
        packet[tcp + 10] = (byte)(ack >> 8); packet[tcp + 11] = (byte)ack;
        packet[tcp + 12] = 0x50; packet[tcp + 13] = 0x12; packet[tcp + 14] = 0x72; packet[tcp + 15] = 0x10;
        var addr = synAddr;
        addr.LayerEventFlags &= ~(1u << 17); // Outbound -> 0 (inbound), Impostor stays 0
        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);
        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    private static void SniffOutbound(IntPtr handle,
        List<(long Ms, ushort SrcPort, byte Flags, uint Seq, uint Ack)> events, CancellationToken ct)
    {
        var buffer = new byte[65535];
        var addr = new WinDivertAddress();
        var sw = Stopwatch.StartNew();
        while (!ct.IsCancellationRequested)
        {
            uint readLen = 0;
            if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref readLen, ref addr)) break;
            if (readLen < 20) continue;
            if (TcpPacketParser.TryParse(buffer, readLen, out var tuple))
                lock (events) events.Add((sw.ElapsedMilliseconds, tuple.SrcPort, tuple.TcpFlags, tuple.Seq, tuple.Ack));
        }
    }

    private static async Task<bool> WaitForAsync(Func<bool> condition, TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout) { if (condition()) return true; await Task.Delay(50); }
        return condition();
    }

    private static Process? StartCurl()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 5 http://8.8.8.8/",
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = false, RedirectStandardError = false
            };
            return Process.Start(psi);
        }
        catch (Exception ex) { Console.WriteLine($"[info] Failed to start curl: {ex.Message}"); return null; }
    }
}

/// <summary>Minimal GetExtendedTcpTable owner-PID lookup for the spike.</summary>
internal static class TcpTableLookup
{
    private enum TcpTableClass { OwnerPidAll = 5 }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;   // network byte order
        public int localPort;    // network byte order
        public uint remoteAddr;
        public int remotePort;
        public int owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int dwSize,
        bool bOrder, int ulAf, TcpTableClass tableClass, int reserved);

    public static int? FindOwnerPid(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, TcpTableClass.OwnerPidAll, 0);
        if (size <= 0) return null;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(buffer, ref size, false, 2, TcpTableClass.OwnerPidAll, 0) != 0) return null;
            int count = Marshal.ReadInt32(buffer);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            int offset = Marshal.SizeOf<int>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buffer + offset + i * rowSize);
                // MIB_TCPROW_OWNER_PID stores addresses and ports in network byte
                // order. Compare after converting from network byte order.
                var rowLocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                var rowRemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort);
                var rowLocalIp = new IPAddress(row.localAddr);
                var rowRemoteIp = new IPAddress(row.remoteAddr);
                if (rowLocalPort == localPort && rowRemotePort == remotePort &&
                    rowLocalIp.Equals(localIp) && rowRemoteIp.Equals(remoteIp) &&
                    row.owningPid > 0)
                    return row.owningPid;
            }
            return null;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}