using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// E4d — final minimal TCP-trace diagnostic.
///
/// Same A/B/C/D architecture as E4b/E4c, but focused purely on the TCP exchange
/// after the SYN-ACK, correlated by the exact 4-tuple and recorded in timestamp
/// order. No packet modification, no crafted packets, no sequence-number loop
/// detection.
///
///   B (priority 1, SNIFF) : outbound original   filter: outbound → 1.1.1.1:443
///   A (priority 0, modify): pass-through recv→send unchanged
///   C (priority -1, SNIFF): outbound after reinject
///   D (priority 1, SNIFF) : inbound from 1.1.1.1:443
///
/// Records for every packet: timestamp, direction, flags, seq, ack, TCP payload
/// length, src/dst ports, and (for outbound) the handle it was seen at.
///
/// Answers, from packet evidence only:
///   A) Did the ClientHello actually leave through C?
///   B) How many times was the ClientHello observed at C?
///   C) Did D observe ANY inbound packet after the SYN-ACK?
///   D) Did the outbound ClientHello retransmit, and after what interval?
///   E) Complete handshake followed by outbound retransmission with no inbound response?
///
/// Produces exactly one classification:
///   TCP_TRACE_COMPLETE              — handshake + ClientHello + inbound response seen
///   TCP_TRACE_CLIENTHELLO_NO_RESPONSE — handshake + ClientHello out, no inbound after SYN-ACK
///   TCP_TRACE_INCONCLUSIVE          — evidence is ambiguous/insufficient
/// </summary>
internal static class Experiment4d
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;

    private const string OutboundFilter =
        "outbound and ip and ip.DstAddr == 1.1.1.1 and tcp and tcp.DstPort == 443";
    private const string InboundFilter =
        "inbound and ip and ip.SrcAddr == 1.1.1.1 and tcp and tcp.SrcPort == 443";

    /// <summary>One captured packet, fully described, in arrival order.</summary>
    private readonly record struct PacketEvent(
        long TimestampMs,
        string Direction,   // "OUT" or "IN"
        string Tag,         // handle tag: B / C / D (A re-injects to C)
        ushort SrcPort,
        ushort DstPort,
        byte Flags,
        uint Seq,
        uint Ack,
        int PayloadLen,
        int TcpHeaderLen);

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 4d] TCP trace after SYN-ACK (A/B/C/D, timestamp-ordered).");

        var handleB = WinDivertNative.WinDivertOpen(OutboundFilter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);
        var handleA = WinDivertNative.WinDivertOpen(OutboundFilter, WinDivertLayer.Network, 0, 0);
        var handleC = WinDivertNative.WinDivertOpen(OutboundFilter, WinDivertLayer.Network, -1, FlagSniffAndRecvOnly);
        var handleD = WinDivertNative.WinDivertOpen(InboundFilter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);

        if (handleB == IntPtr.Zero || handleB == new IntPtr(-1) ||
            handleA == IntPtr.Zero || handleA == new IntPtr(-1) ||
            handleC == IntPtr.Zero || handleC == new IntPtr(-1) ||
            handleD == IntPtr.Zero || handleD == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open handles. B={handleB} A={handleA} C={handleC} D={handleD}");
            return 1;
        }

        var events = new List<PacketEvent>();
        var stop = new CancellationTokenSource();

        // A: pass-through (modify mode). Re-injects every outbound packet unchanged.
        var taskA = Task.Run(() =>
        {
            var buffer = new byte[65535];
            var addr = new WinDivertAddress();
            while (!stop.IsCancellationRequested)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(handleA, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break;
                if (readLen < 20) continue;
                if (!WinDivertNative.WinDivertSend(handleA, buffer, readLen, IntPtr.Zero, ref addr))
                {
                    Console.WriteLine($"  [SENDFAIL] err={Marshal.GetLastWin32Error()}");
                }
            }
        });

        // B / C / D: passive sniffers recording timestamp-ordered events.
        var taskB = Task.Run(() => SniffLoop(handleB, "B", "OUT", events, stop.Token));
        var taskC = Task.Run(() => SniffLoop(handleC, "C", "OUT", events, stop.Token));
        var taskD = Task.Run(() => SniffLoop(handleD, "D", "IN", events, stop.Token));

        using (var curl = StartCurl())
        {
            if (curl is null)
            {
                Console.WriteLine("[INCONCLUSIVE] Could not start curl.");
                stop.Cancel();
                await Task.WhenAll(taskA, taskB, taskC, taskD);
                return 1;
            }

            await Task.WhenAny(curl.WaitForExitAsync(), Task.Delay(TimeSpan.FromSeconds(8)));
            if (!curl.HasExited)
                Console.WriteLine("  [result] curl did not finish within 8s (stalled).");
            else
                Console.WriteLine($"  [result] curl exited with code {curl.ExitCode} (0 = success).");
            if (!curl.HasExited) { try { curl.Kill(); } catch { } }
        }

        await Task.Delay(TimeSpan.FromMilliseconds(500));
        stop.Cancel();
        WinDivertNative.WinDivertClose(handleA);
        WinDivertNative.WinDivertClose(handleB);
        WinDivertNative.WinDivertClose(handleC);
        WinDivertNative.WinDivertClose(handleD);
        try { await Task.WhenAll(taskA, taskB, taskC, taskD); } catch { }

        // ── Sort all events by timestamp and print the trace ──
        var sorted = events.OrderBy(e => e.TimestampMs).ThenBy(e => e.Direction).ToList();
        Console.WriteLine($"  [trace] {sorted.Count} events:");
        foreach (var e in sorted)
        {
            var seq = e.Seq;
            var ack = e.Ack;
            Console.WriteLine(
                $"    {e.TimestampMs,8}ms {e.Direction} {e.Tag} " +
                $"{e.SrcPort}->{e.DstPort} flags=0x{e.Flags:X2} seq={seq} ack={ack} " +
                $"payload={e.PayloadLen} tcpHdr={e.TcpHeaderLen}");
        }

        // ── Answer the five questions from packet facts only ──
        // Identify the ClientHello (the first outbound PSH|ACK carrying payload).
        var clientHellosAtC = sorted
            .Where(e => e.Tag == "C" && e.Flags == 0x18 && e.PayloadLen > 0)
            .ToList();
        var clientHelloAny = sorted
            .Where(e => e.Direction == "OUT" && e.Flags == 0x18 && e.PayloadLen > 0)
            .ToList();

        var synAck = sorted.FirstOrDefault(e => e.Direction == "IN" && (e.Flags & 0x12) == 0x12);
        var afterSynAck = sorted
            .Where(e => e.Direction == "IN" && e.TimestampMs >= (synAck.TimestampMs + 1))
            .ToList();

        bool synSeen = sorted.Any(e => e.Direction == "OUT" && (e.Flags & 0x02) != 0 && (e.Flags & 0x10) == 0);
        bool handshakeAckOut = sorted.Any(e => e.Direction == "OUT" && e.Flags == 0x10 && e.Ack != 0);

        Console.WriteLine();
        Console.WriteLine("  [Q1] ClientHello left through C?      " +
            (clientHellosAtC.Count > 0 ? $"YES ({clientHellosAtC.Count}× at C)" : "NO"));
        Console.WriteLine("  [Q2] ClientHello observed at C:       " +
            $"{clientHellosAtC.Count} time(s)");
        Console.WriteLine("  [Q3] Inbound after SYN-ACK:           " +
            (afterSynAck.Count > 0 ? $"YES — {afterSynAck.Count} packet(s)" : "NO — none after SYN-ACK"));
        Console.WriteLine("  [Q4] Outbound ClientHello retransmit: " + DescribeRetransmits(clientHellosAtC));
        Console.WriteLine("  [Q5] Handshake+no inbound response:   " +
            ((synSeen && handshakeAckOut && clientHellosAtC.Count > 0 && afterSynAck.Count == 0)
                ? "YES (complete handshake, ClientHello out, no inbound response)"
                : "no (trace does not match that pattern)"));

        // ── Classification ──
        string classification;
        if (synSeen && handshakeAckOut && clientHellosAtC.Count > 0 && afterSynAck.Count > 0)
            classification = "TCP_TRACE_COMPLETE";
        else if (synSeen && handshakeAckOut && clientHellosAtC.Count > 0 && afterSynAck.Count == 0)
            classification = "TCP_TRACE_CLIENTHELLO_NO_RESPONSE";
        else
            classification = "TCP_TRACE_INCONCLUSIVE";

        Console.WriteLine();
        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine("  evidence: " + string.Join("; ", new[]
        {
            $"SYN={(synSeen ? "Y" : "N")}",
            $"handshakeACK={(handshakeAckOut ? "Y" : "N")}",
            $"ClientHello@C={clientHellosAtC.Count}",
            $"inboundAfterSynAck={afterSynAck.Count}"
        }));
        Console.WriteLine("=== E4d complete ===");
        return 0;
    }

    private static string DescribeRetransmits(List<PacketEvent> clientHellosAtC)
    {
        if (clientHellosAtC.Count <= 1)
            return clientHellosAtC.Count == 0 ? "none" : "no (1× only)";
        var first = clientHellosAtC[0].TimestampMs;
        var last = clientHellosAtC[^1].TimestampMs;
        var gap = last - first;
        return $"YES — {clientHellosAtC.Count}× over {gap}ms (first→last)";
    }

    private static void SniffLoop(IntPtr handle, string tag, string direction, List<PacketEvent> events, CancellationToken ct)
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
                var tcp = (buffer[0] & 0x0F) * 4;
                var payloadLen = (int)readLen - tcp - tuple.TcpHeaderLen;
                if (payloadLen < 0) payloadLen = 0;
                var ev = new PacketEvent(
                    sw.ElapsedMilliseconds,
                    direction,
                    tag,
                    tuple.SrcPort,
                    tuple.DstPort,
                    tuple.TcpFlags,
                    tuple.Seq,
                    tuple.Ack,
                    payloadLen,
                    tuple.TcpHeaderLen);
                lock (events)
                {
                    events.Add(ev);
                }
            }
        }
    }

    private static Process? StartCurl()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = "-s -o NUL --max-time 8 https://1.1.1.1/",
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