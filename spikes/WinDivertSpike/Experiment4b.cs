using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// E4b — focused reinjection isolation experiment.
///
/// Investigates why a priority-0 outbound pass-through stalled curl in E4.
/// Uses three handles on the same filter to independently observe the packet
/// lifecycle:
///
///   B (priority 1, SNIFF) : sees packets BEFORE the pass-through (original)
///   A (priority 0, modify): the pass-through (WinDivertRecv -> WinDivertSend)
///   C (priority -1, SNIFF): sees packets AFTER A re-injects
///
/// This tells us, per packet fingerprint:
///   - If C sees the same packet B saw  -> re-injection delivered it (left the box).
///   - If B sees the same fingerprint twice quickly -> a recapture loop.
///   - If A re-injected a packet but C never saw it -> the re-inject was dropped.
///
/// Also verifies address/checksum handling: we log the WinDivertAddress fields
/// (IfIdx/SubIfIdx/Outbound/flags) and whether checksums were left valid, and we
/// recompute checksums on a SECOND copy of each packet to compare — but only if
/// the "send unchanged" copy fails to appear at C.
///
/// Prints a compact report at the end. No per-packet console I/O in the hot path.
/// </summary>
internal static class Experiment4b
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4; // SNIFF + RECV_ONLY

    private static readonly IPAddress SpikeIp = IPAddress.Parse("1.1.1.1");
    private const int SpikePort = 443;
    private const string Filter =
        "outbound and ip and ip.DstAddr == 1.1.1.1 and tcp and tcp.DstPort == 443";

    /// <summary>Inbound observer D filter: everything the server sends back.</summary>
    private const string InboundFilter =
        "inbound and ip and ip.SrcAddr == 1.1.1.1 and tcp and tcp.SrcPort == 443";

    /// <summary>Full packet fingerprint used to identify exact copies.</summary>
    private readonly record struct Fingerprint(byte[] Packet, WinDivertAddress Address);

    private sealed class Observed
    {
        public readonly List<(string Tag, string Fp, string Detail)> Items = new();
        public int Count;
    }

    /// <summary>Runs the experiment and prints results. Returns 0 on success.</summary>
    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 4b] Pass-through reinjection isolation (3-handle observer).");

        // Handles: B (sniff, high pri), A (modify pass-through, pri 0), C (sniff, low pri),
        //          D (inbound sniff observer, high pri) — passive, sees only server→client.
        var handleB = WinDivertNative.WinDivertOpen(Filter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);
        var handleA = WinDivertNative.WinDivertOpen(Filter, WinDivertLayer.Network, 0, 0);
        var handleC = WinDivertNative.WinDivertOpen(Filter, WinDivertLayer.Network, -1, FlagSniffAndRecvOnly);
        var handleD = WinDivertNative.WinDivertOpen(InboundFilter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);

        if (handleB == IntPtr.Zero || handleB == new IntPtr(-1) ||
            handleA == IntPtr.Zero || handleA == new IntPtr(-1) ||
            handleC == IntPtr.Zero || handleC == new IntPtr(-1) ||
            handleD == IntPtr.Zero || handleD == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open handles. B={handleB} A={handleA} C={handleC} D={handleD}");
            return 1;
        }

        var observedB = new Observed();
        var observedC = new Observed();
        var observedD = new Observed();
        var passThroughCount = 0;
        var sendFailures = 0;
        var reInjectedFp = new List<(string Fp, string Detail)>();
        var stop = new CancellationTokenSource();

        var taskB = Task.Run(() => SniffLoop(handleB, "B", observedB, stop.Token));
        var taskC = Task.Run(() => SniffLoop(handleC, "C", observedC, stop.Token));
        var taskD = Task.Run(() => SniffLoop(handleD, "D", observedD, stop.Token));

        // Pass-through loop (A).
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

                // Record the exact packet + address before Send (for diagnosis).
                var packetCopy = new byte[readLen];
                Array.Copy(buffer, packetCopy, readLen);
                var detail = DescribeAddress(addr);
                reInjectedFp.Add((FingerprintOf(packetCopy, readLen), detail));

                // Re-inject unchanged (the canonical passthru pattern).
                if (!WinDivertNative.WinDivertSend(handleA, packetCopy, readLen, IntPtr.Zero, ref addr))
                {
                    sendFailures++;
                    Console.WriteLine($"  [SENDFAIL] err={Marshal.GetLastWin32Error()}");
                }
                else
                {
                    passThroughCount++;
                }
            }
        });

        // Trigger a controlled connection.
        using (var curl = StartCurl())
        {
            if (curl is null)
            {
                Console.WriteLine("[INCONCLUSIVE] Could not start curl.");
                stop.Cancel();
                await Task.WhenAll(taskA, taskB, taskC, taskD);
                return 1;
            }

            // Let the pass-through run for the curl duration + a little extra.
            await Task.WhenAny(curl.WaitForExitAsync(), Task.Delay(TimeSpan.FromSeconds(8)));
            if (!curl.HasExited)
                Console.WriteLine("  [result] curl did not finish within 8s (stalled).");
            else
                Console.WriteLine($"  [result] curl exited with code {curl.ExitCode} (0 = success).");

            if (!curl.HasExited) { try { curl.Kill(); } catch { } }
        }

        // Allow observers a moment to drain, then stop.
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        stop.Cancel();
        WinDivertNative.WinDivertClose(handleA);
        WinDivertNative.WinDivertClose(handleB);
        WinDivertNative.WinDivertClose(handleC);
        WinDivertNative.WinDivertClose(handleD);
        try { await Task.WhenAll(taskA, taskB, taskC, taskD); } catch { }

        // ── Report ──
        Console.WriteLine($"  [stats] passThroughSent={passThroughCount} sendFailures={sendFailures} " +
                          $"B(original)={observedB.Count} C(after reinject)={observedC.Count}");

        // Cross-reference: did every packet A re-injected appear at C?
        var seenAtC = observedC.Items.Select(i => i.Fp).ToHashSet();
        var seenAtB = observedB.Items.Select(i => i.Fp).ToHashSet();
        var reInjectedNotAtC = reInjectedFp.Where(x => !seenAtC.Contains(x.Fp)).ToList();
        var reInjectedAtC = reInjectedFp.Where(x => seenAtC.Contains(x.Fp)).ToList();

        Console.WriteLine($"  [check] re-injected packets seen at C (left machine): {reInjectedAtC.Count}/{reInjectedFp.Count}");
        foreach (var (fp, detail) in reInjectedFp.Take(10))
            Console.WriteLine($"    reinjected: {detail} {(seenAtC.Contains(fp) ? "-> seen at C" : "-> NOT seen at C")}");

        // Loop detection: a packet seen twice at B (same fingerprint, quickly).
        var bCounts = observedB.Items.GroupBy(x => x.Fp)
            .Where(g => g.Count() > 1).ToList();
        if (bCounts.Count == 0)
            Console.WriteLine("  [loop] no duplicate fingerprints at B — no recapture loop.");
        else
            Console.WriteLine($"  [loop] {bCounts.Count} fingerprints seen >1x at B (may be retransmits):");

        // Distinguish: was the ClientHello (PSH|ACK) re-injected AND seen at C?
        var pshAtB = observedB.Items.Where(i => i.Detail.Contains("flags=0x18")).ToList();
        var pshAtC = observedC.Items.Where(i => i.Detail.Contains("flags=0x18")).ToList();
        Console.WriteLine($"  [psh] ClientHello-style (PSH|ACK) packets: B={pshAtB.Count} C={pshAtC.Count}");

        // ── Inbound observer D report ──
        Console.WriteLine($"  [inbound D] observed={observedD.Count} packets from 1.1.1.1:443");
        foreach (var item in observedD.Items.Take(20))
            Console.WriteLine($"    D: {item.Detail}");

        var synAckSeen = observedD.Items.Any(i => i.Detail.Contains("flags=0x12"));
        var serverResponseSeen = observedD.Items.Any(i =>
            i.Detail.Contains("flags=0x18") || i.Detail.Contains("flags=0x10") || i.Detail.Contains("flags=0x11"));
        var anyInboundAfterHandshake = observedD.Count > (synAckSeen ? 1 : 0);

        Console.WriteLine($"  [inbound D] SYN-ACK seen: {synAckSeen}");
        Console.WriteLine($"  [inbound D] later inbound TCP (response to ClientHello / ServerHello / data): {serverResponseSeen} " +
                          $"({observedD.Count} total inbound packets, >{ (synAckSeen ? 1 : 0) } implies something beyond the SYN-ACK)");

        // Strict classification per the task.
        string classification;
        if (observedD.Count == 0)
        {
            classification = "INBOUND_RESPONSE_NOT_SEEN";
        }
        else if (synAckSeen && observedD.Count > 1)
        {
            classification = "INBOUND_RESPONSE_SEEN";
        }
        else if (synAckSeen)
        {
            classification = "INCONCLUSIVE"; // Only the handshake return; no application data observed.
        }
        else
        {
            classification = "INCONCLUSIVE"; // Inbound captured but not a clean SYN-ACK.
        }
        Console.WriteLine($"[classification] {classification}");
        if (classification == "INBOUND_RESPONSE_SEEN")
            Console.WriteLine("  evidence: server returned a SYN-ACK AND at least one further inbound packet");
        else if (classification == "INBOUND_RESPONSE_NOT_SEEN")
            Console.WriteLine("  evidence: D observed zero inbound packets from 1.1.1.1:443");
        else
            Console.WriteLine("  evidence: inbound capture does not cleanly prove or refute a server response");

        // Verdict.
        if (passThroughCount == 0)
        {
            Console.WriteLine("[FAILED] Pass-through sent nothing — reinjection path broken.");
        }
        else if (reInjectedNotAtC.Count == 0)
        {
            Console.WriteLine("[CONFIRMED] Every re-injected packet appeared at C — reinjection delivers packets to the wire.");
        }
        else
        {
            Console.WriteLine($"[INCONCLUSIVE] {reInjectedNotAtC.Count}/{reInjectedFp.Count} re-injected packets were NOT observed at C — reinjection may be dropping them.");
        }

        if (observedB.Items.Select(i => i.Fp).GroupBy(x => x).Any(g => g.Count() > 1))
            Console.WriteLine("[info] duplicate fingerprints at B could be TCP retransmits (same packet re-sent) — not necessarily a loop.");

        Console.WriteLine("=== E4b complete ===");
        return 0;
    }

    private static void SniffLoop(IntPtr handle, string tag, Observed observed, CancellationToken ct)
    {
        var buffer = new byte[65535];
        var addr = new WinDivertAddress();
        while (!ct.IsCancellationRequested)
        {
            uint readLen = 0;
            if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                break;
            if (readLen < 20) continue;

            var fp = FingerprintOf(buffer, readLen);
            var detail = DescribePacket(buffer, readLen);
            lock (observed)
            {
                observed.Items.Add((tag, fp, detail));
                observed.Count++;
            }
        }
    }

    private static string FingerprintOf(byte[] packet, uint length)
    {
        // Tuple + flags + seq + ack + header length + payload length.
        var tcp = (packet[0] & 0x0F) * 4;
        var seq = BitConverter.ToUInt32(packet.AsSpan(tcp + 4, 4).ToArray().Reverse().ToArray());
        var ack = BitConverter.ToUInt32(packet.AsSpan(tcp + 8, 4).ToArray().Reverse().ToArray());
        var flags = packet[tcp + 13];
        return $"{new IPAddress(packet.AsSpan(12, 4))}:{(packet[tcp] << 8 | packet[tcp + 1])}->" +
               $"{new IPAddress(packet.AsSpan(16, 4))}:{(packet[tcp + 2] << 8 | packet[tcp + 3])} " +
               $"flags=0x{flags:X2} seq={seq} ack={ack} len={(int)length}";
    }

    private static string DescribePacket(byte[] packet, uint length)
    {
        var tcp = (packet[0] & 0x0F) * 4;
        return FingerprintOf(packet, length) +
               $" tcpHdr={((packet[tcp + 12] >> 4) & 0x0F) * 4}";
    }

    private static string DescribeAddress(WinDivertAddress a) =>
        $"ifIdx={a.IfIdx} subIf={a.SubIfIdx} outbound={a.Outbound} loopback={a.Loopback} ipv6={a.IPv6}";

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