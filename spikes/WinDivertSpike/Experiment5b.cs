using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// Experiment 5b — crafted inbound SYN-ACK acceptance (R3), remote destination.
///
/// The local-server approach (E5) is impossible: WinDivert treats any same-machine
/// connection as loopback and never captures loopback on the inbound path. So the
/// destination must be REMOTE (8.8.8.8:80) so the client's reaction is capturable.
///
/// CRITICAL direction fact: after we hold the client's SYN and inject a crafted
/// inbound SYN-ACK, the CLIENT's reaction (ACK, or a SYN retransmit) is an
/// OUTBOUND packet (client → 8.8.8.8). An inbound observer can never see it.
/// So we observe the client's reaction with an OUTBOUND SNIFF handle.
///
///   A (priority 0, modify): captures + holds the outbound SYN.
///   E (priority 1, SNIFF) : sees the client's outbound reaction (ACK or SYN retransmit).
///
/// PASS      : E sees client ACK (src=clientIP:clientSrcPort, dst=8.8.8.8:80,
///             ack=serverISN+1) — proves the stack accepted our crafted SYN-ACK.
/// FAIL      : E sees the client retransmit its SYN (same seq), never ACK.
/// INCONCLUSIVE: E sees no outbound packets from the client to 8.8.8.8:80.
///
/// WinDivert semantics applied (verified): Outbound bit 17 = 0 → inbound path;
/// inbound injection requires valid IfIdx/SubIfIdx; correct checksums or flags.
/// </summary>
internal static class Experiment5b
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;

    private static readonly IPAddress RemoteIp = IPAddress.Parse("8.8.8.8");
    private const ushort RemotePort = 80;

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 5b] Crafted inbound SYN-ACK acceptance (R3) — remote destination.");

        // Capture handle A (modify) for the SYN to the remote.
        string captureFilter = $"outbound and ip and ip.DstAddr == {RemoteIp} and tcp and tcp.DstPort == {RemotePort}";
        var handleA = WinDivertNative.WinDivertOpen(captureFilter, WinDivertLayer.Network, 0, 0);
        if (handleA == IntPtr.Zero || handleA == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open capture handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }

        // We cannot open the outbound observer E before we know the client's source
        // port. Instead, open E with a wide filter on the remote, at priority 1, so
        // it sees BOTH the SYN and the client's reaction before A drops the SYN.
        // E sees: the original SYN, and later the client's ACK (or SYN retransmit).
        string observerFilter = $"outbound and ip and ip.DstAddr == {RemoteIp} and tcp and tcp.DstPort == {RemotePort}";
        var handleE = WinDivertNative.WinDivertOpen(observerFilter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);
        if (handleE == IntPtr.Zero || handleE == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open observer handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }

        var stop = new CancellationTokenSource();
        var observedOut = new List<(long Ms, ushort SrcPort, ushort DstPort, byte Flags, uint Seq, uint Ack)>();
        var taskE = Task.Run(() => SniffOutbound(handleE, observedOut, stop.Token));

        var clientIsn = 0u;
        var clientSrcPort = (ushort)0;
        var clientLocalIp = IPAddress.Any;
        var serverIsn = 0x12345678u;
        var synAddr = new WinDivertAddress();
        var synCaptured = false;

        // Capture the first pure SYN to the remote; hold it (do NOT re-inject).
        var captureTask = Task.Run(() =>
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
                if ((tuple.TcpFlags & 0x02) == 0 || (tuple.TcpFlags & 0x10) != 0) continue; // pure SYN

                clientIsn = tuple.Seq;
                clientSrcPort = tuple.SrcPort;
                clientLocalIp = tuple.SrcIp;
                synAddr = addr;
                synCaptured = true;
                Console.WriteLine($"  [captured SYN] {tuple.SrcIp}:{tuple.SrcPort}->{tuple.DstIp}:{tuple.DstPort} " +
                                  $"seq={tuple.Seq} ifIdx={addr.IfIdx} subIf={addr.SubIfIdx} outbound={addr.Outbound} loopback={addr.Loopback}");
                break;
            }
        });

        using (var curl = StartCurl())
        {
            if (curl is null)
            {
                Console.WriteLine("[INCONCLUSIVE] Could not start curl.");
                stop.Cancel();
                await Task.WhenAll(captureTask, taskE);
                return 1;
            }

            var gotSyn = await WaitForAsync(() => synCaptured, TimeSpan.FromSeconds(5));
            if (!gotSyn)
            {
                Console.WriteLine("[FAILED] No SYN captured to the remote within 5s.");
                stop.Cancel();
                WinDivertNative.WinDivertClose(handleA);
                WinDivertNative.WinDivertClose(handleE);
                try { await Task.WhenAll(captureTask, taskE); } catch { }
                return 1;
            }

            // ── Craft and inject the SYN-ACK (as if from 8.8.8.8:80) ──
            var injected = InjectSynAck(handleA, RemoteIp, clientLocalIp, RemotePort, clientSrcPort, serverIsn, clientIsn, ref synAddr);
            if (!injected)
            {
                Console.WriteLine("[FAILED] WinDivertSend for crafted SYN-ACK failed.");
            }
            else
            {
                Console.WriteLine($"  [injected SYN-ACK] {RemoteIp}:{RemotePort}->{clientLocalIp}:{clientSrcPort} " +
                                  $"seq={serverIsn} ack={clientIsn + 1} flags=0x12");
            }

            // Give the client a moment to react, then observe.
            await Task.Delay(TimeSpan.FromSeconds(3));
            if (!curl.HasExited) { try { curl.Kill(); } catch { } }
        }

        stop.Cancel();
        WinDivertNative.WinDivertClose(handleA);
        WinDivertNative.WinDivertClose(handleE);
        try { await Task.WhenAll(captureTask, taskE); } catch { }

        Console.WriteLine($"  [E] outbound packets from client to {RemoteIp}:{RemotePort}: {observedOut.Count}");
        foreach (var p in observedOut)
            Console.WriteLine($"    {p.Ms,5}ms {p.SrcPort}->{p.DstPort} flags=0x{p.Flags:X2} seq={p.Seq} ack={p.Ack}");

        // The client's ACK to our SYN-ACK: src=clientSrcPort, dst=80, ack=serverISN+1, flags=0x10.
        var clientAck = observedOut.Any(p =>
            p.SrcPort == clientSrcPort && (p.Flags & 0x10) != 0 && p.Ack == serverIsn + 1);
        // A SYN retransmit: same src port, flags=0x02, seq == clientIsn.
        var synRetransmit = observedOut.Any(p =>
            p.SrcPort == clientSrcPort && (p.Flags & 0x02) != 0 && p.Seq == clientIsn);

        string classification;
        if (clientAck)
            classification = "PASS";
        else if (synRetransmit)
            classification = "FAIL";
        else
            classification = "INCONCLUSIVE";

        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine($"  evidence: clientACKToCraftedSynAck={clientAck} synRetransmit={synRetransmit} " +
                          $"outboundObserved={observedOut.Count}");
        Console.WriteLine("=== E5b complete ===");
        return 0;
    }

    /// <summary>Builds a valid IPv4/TCP SYN-ACK packet (server→client) and injects it inbound.</summary>
    private static bool InjectSynAck(
        IntPtr handle,
        IPAddress serverIp,
        IPAddress clientIp,
        ushort serverPort,
        ushort clientPort,
        uint serverIsn,
        uint clientIsn,
        ref WinDivertAddress synAddr)
    {
        var packet = new byte[40];

        // IPv4 header
        packet[0] = 0x45;
        packet[1] = 0x00;
        packet[2] = 0x00; packet[3] = 40;
        packet[4] = 0x00; packet[5] = 0x00;
        packet[6] = 0x40; packet[7] = 0x00; // DF
        packet[8] = 64;
        packet[9] = 6;
        var serverBytes = serverIp.GetAddressBytes();
        var clientBytes = clientIp.GetAddressBytes();
        Array.Copy(serverBytes, 0, packet, 12, 4); // src = server (8.8.8.8)
        Array.Copy(clientBytes, 0, packet, 16, 4); // dst = client (local machine's IP)

        // TCP header
        int tcp = 20;
        packet[tcp + 0] = (byte)(serverPort >> 8); packet[tcp + 1] = (byte)serverPort;
        packet[tcp + 2] = (byte)(clientPort >> 8); packet[tcp + 3] = (byte)clientPort;
        packet[tcp + 4] = (byte)(serverIsn >> 24); packet[tcp + 5] = (byte)(serverIsn >> 16);
        packet[tcp + 6] = (byte)(serverIsn >> 8);  packet[tcp + 7] = (byte)serverIsn;
        var ack = clientIsn + 1;
        packet[tcp + 8] = (byte)(ack >> 24);  packet[tcp + 9] = (byte)(ack >> 16);
        packet[tcp + 10] = (byte)(ack >> 8);  packet[tcp + 11] = (byte)ack;
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x12; // SYN|ACK
        packet[tcp + 14] = 0x72; packet[tcp + 15] = 0x10;

        // ── Injection address: mirror the canonical netfilter.c pattern ──
        //   - Only flip Outbound (17) to 0 → inbound path (docs: "only the Outbound
        //     field ... determines the packet's direction").
        //   - Do NOT set the Impostor bit (19): setting it marks the packet as
        //     injected-by-another-driver, triggers the TTL-decrement loop mitigation,
        //     and made the Windows stack reject the crafted SYN-ACK in the first E5b
        //     run (the client retransmitted its SYN, never ACKed). netfilter.c never
        //     sets Impostor and its injected packets are accepted.
        //   - Leave IfIdx/SubIfIdx as captured from the SYN (netfilter.c memcpy's
        //     the recv address; docs require valid interface numbers for inbound).
        //   - Use WinDivertHelperCalcChecksums to compute IP/TCP checksums (the
        //     canonical path) instead of manual checksums + checksum-valid flags.
        var addr = synAddr;
        addr.LayerEventFlags &= ~(1u << 17); // clear Outbound -> inbound (keep Impostor = 0)

        WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref addr, 0);
        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    private static void SniffOutbound(
        IntPtr handle,
        List<(long Ms, ushort SrcPort, ushort DstPort, byte Flags, uint Seq, uint Ack)> events,
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
            if (readLen < 20) continue;
            if (TcpPacketParser.TryParse(buffer, readLen, out var tuple))
            {
                lock (events)
                {
                    events.Add((sw.ElapsedMilliseconds, tuple.SrcPort, tuple.DstPort,
                        tuple.TcpFlags, tuple.Seq, tuple.Ack));
                }
            }
        }
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
                Arguments = "-s -o NUL --max-time 5 http://8.8.8.8/",
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
