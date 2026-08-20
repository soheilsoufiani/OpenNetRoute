using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// WinDivert feasibility spike.
///
/// Runs a sequence of isolated experiments, printing one result line per step
/// prefixed with CONFIRMED / FAILED / INCONCLUSIVE / NOT TESTED. The spike is
/// intentionally narrow: it never modifies the routing table, never intercepts
/// unrelated traffic, and never creates a capture loop. It captures ONLY packets
/// matching a tightly scoped filter (a specific destination IP:port that we
/// control), inspects them, and re-injects them unchanged (pass-through).
///
/// Each experiment opens its own handle. The receive helpers own handle
/// lifecycle: they close it on both success and timeout (closing a WinDivert
/// handle is the documented way to unblock a pending blocking WinDivertRecv).
/// </summary>
internal static class Program
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4; // SNIFF + RECV_ONLY

    /// <summary>Target we will connect to for the spike (a public HTTPS endpoint).</summary>
    private const string SpikeHost = "1.1.1.1";
    private const int SpikePort = 443;

    private static readonly IPAddress SpikeIp = IPAddress.Parse(SpikeHost);

    private static string NetworkFilter =>
        $"outbound and ip and ip.DstAddr == {SpikeIp} and tcp and tcp.DstPort == {SpikePort}";

    private static string FlowFilter =>
        $"not loopback and protocol == 6 and remoteAddr == {SpikeIp} and remotePort == {SpikePort}";

    private static async Task<int> Main(string[] args)
    {
        Console.WriteLine("=== WinDivert Feasibility Spike ===");
        Console.WriteLine($"Process is elevated: {IsElevated()}");
        Console.WriteLine($"Target: {SpikeHost}:{SpikePort} (filter scoped to this IP:port only)");
        Console.WriteLine();

        if (!IsElevated())
        {
            Console.WriteLine("[FAILED] WinDivert capture requires Administrator privileges.");
            Console.WriteLine("Re-run the spike from an elevated (Administrator) shell.");
            return 2;
        }

        // Experiment 0: WinDivert loads and a handle can be opened.
        if (!Experiment0_LoadAndOpen())
            return 3;

        // Experiment 1: capture an outbound SYN to the spike target.
        await Experiment1_CaptureSynAsync();

        // Experiment 2: inspect fields (tuple + seq/ack).
        await Experiment2_InspectPacketAsync();

        // Experiment 3: flow-layer process attribution (separate handle).
        await Experiment3_FlowProcessAttributionAsync();

        // Experiment 4: reinjection / loop prevention (pass-through).
        await Experiment4_ReinjectPassThroughAsync();

        Console.WriteLine();
        Console.WriteLine("=== Spike complete ===");
        return 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Experiment 0: Load + open a narrow-filter handle.
    // ─────────────────────────────────────────────────────────────────────────
    private static bool Experiment0_LoadAndOpen()
    {
        Console.WriteLine("[Experiment 0] Load WinDivert and open a handle with a narrow filter.");

        var handle = OpenNetworkHandle(out var err);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] WinDivertOpen returned invalid handle. error={err} ({DescribeError(err)})");
            return false;
        }

        Console.WriteLine($"[CONFIRMED] WinDivert handle opened. filter='{NetworkFilter}'");
        WinDivertNative.WinDivertClose(handle);
        Console.WriteLine("[info] Handle closed.");
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Experiment 1: capture a real outbound SYN.
    // ─────────────────────────────────────────────────────────────────────────
    private static async Task Experiment1_CaptureSynAsync()
    {
        Console.WriteLine($"[Experiment 1] Capture a real outbound TCP SYN to {SpikeHost}:{SpikePort}.");
        Console.WriteLine("  Trigger: running 'curl.exe https://1.1.1.1' in the background.");

        var handle = OpenNetworkHandle(out _);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            Console.WriteLine("[FAILED] Could not open a capture handle for Experiment 1.");
            return;
        }

        using var curl = StartCurl();
        if (curl is null)
        {
            Console.WriteLine("[INCONCLUSIVE] Could not start curl.exe; cannot generate a real SYN.");
            return;
        }

        var (synSeen, packets) = await ReceiveUntilAsync(
            handle, TimeSpan.FromSeconds(8), p => p.Any(t => (t.TcpFlags & 0x02) != 0));

        foreach (var tuple in packets.Take(10))
            Console.WriteLine($"  [packet] {tuple}");

        Console.WriteLine(synSeen
            ? "[CONFIRMED] Captured a real outbound TCP SYN."
            : "[FAILED] No SYN captured within the deadline.");

        await StopCurlAsync(curl);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Experiment 2: inspect source/dst IP+port, flags, seq/ack.
    // ─────────────────────────────────────────────────────────────────────────
    private static async Task Experiment2_InspectPacketAsync()
    {
        Console.WriteLine($"[Experiment 2] Inspect source/destination IP+port, TCP flags, seq/ack numbers.");
        Console.WriteLine("  Trigger: second curl run.");

        var handle = OpenNetworkHandle(out _);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            Console.WriteLine("[FAILED] Could not open a capture handle for Experiment 2.");
            return;
        }

        using var curl = StartCurl();
        if (curl is null)
        {
            Console.WriteLine("[INCONCLUSIVE] Could not start curl.exe.");
            return;
        }

        var (_, packets) = await ReceiveUntilAsync(
            handle, TimeSpan.FromSeconds(8), p => p.Count >= 3);

        var inspected = 0;
        foreach (var tuple in packets.Take(3))
        {
            inspected++;
            Console.WriteLine($"  [{inspected}] {tuple}");
            Console.WriteLine($"    srcPort={tuple.SrcPort} dstPort={tuple.DstPort} flags=0x{tuple.TcpFlags:X2} " +
                              $"seq={tuple.Seq} ack={tuple.Ack} tcpHdrLen={tuple.TcpHeaderLen}");
        }

        Console.WriteLine(inspected > 0
            ? "[CONFIRMED] Packet fields inspected successfully."
            : "[FAILED] No packets inspected within the deadline.");

        await StopCurlAsync(curl);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Experiment 3: flow-layer process attribution.
    // ─────────────────────────────────────────────────────────────────────────
    private static async Task Experiment3_FlowProcessAttributionAsync()
    {
        Console.WriteLine("[Experiment 3] Flow-layer process/flow attribution.");
        Console.WriteLine("  Open a SNIFF+RECV_ONLY FLOW-layer handle scoped to the spike target.");

        var flowHandle = WinDivertNative.WinDivertOpen(FlowFilter, WinDivertLayer.Flow, 0, FlagSniffAndRecvOnly);
        if (flowHandle == IntPtr.Zero || flowHandle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            Console.WriteLine($"[INCONCLUSIVE] Flow handle open failed. error={err} ({DescribeError(err)})");
            return;
        }

        Console.WriteLine($"  [info] Flow handle opened. filter='{FlowFilter}'");

        using var curl = StartCurl();
        if (curl is null)
        {
            Console.WriteLine("[INCONCLUSIVE] Could not start curl.exe.");
            return;
        }

        var (flowSeen, events) = await ReceiveFlowUntilAsync(
            flowHandle, TimeSpan.FromSeconds(8), e => e.Any(x => x.Event == 1));

        foreach (var e in events.Take(8))
        {
            Console.WriteLine($"  [flow] event={e.Event} pid={e.Pid} localPort={e.LocalPort} " +
                              $"remotePort={e.RemotePort} proto={e.Protocol}");
        }

        Console.WriteLine(flowSeen
            ? "[CONFIRMED] FLOW_ESTABLISHED event captured with process attribution."
            : "[INCONCLUSIVE] No FLOW_ESTABLISHED within the deadline (connection may not have completed).");

        await StopCurlAsync(curl);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Experiment 4: reinjection / loop prevention (pass-through).
    // ─────────────────────────────────────────────────────────────────────────
    private static async Task Experiment4_ReinjectPassThroughAsync()
    {
        Console.WriteLine("[Experiment 4] Reinjection (WinDivertSend pass-through) and loop prevention.");
        Console.WriteLine("  Method: capture packets on a modify-mode handle, re-inject each unchanged,");
        Console.WriteLine("          and verify (a) the connection completes (curl succeeds) and");
        Console.WriteLine("          (b) no packet is re-presented to us (no capture loop).");

        var handle = OpenNetworkHandle(out _);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            Console.WriteLine("[FAILED] Could not open a capture handle for Experiment 4.");
            return;
        }

        var seenSeq = new HashSet<uint>();
        var loopDetected = false;
        var reinjected = 0;
        var handled = 0;
        var task = Task.Run(() =>
        {
            var buffer = new byte[65535];
            var addr = new WinDivertAddress();
            while (handled < 5)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break; // Handle closed (deadline) or error.
                if (readLen < 20) continue;
                if (!TcpPacketParser.TryParse(buffer, readLen, out var tuple)) continue;

                handled++;
                if (!seenSeq.Add(tuple.Seq))
                {
                    loopDetected = true;
                    Console.WriteLine($"  [LOOP?] seq {tuple.Seq} re-presented — possible capture loop.");
                }

                // Re-inject the packet unchanged on the same address.
                if (!WinDivertNative.WinDivertSend(handle, buffer, readLen, IntPtr.Zero, ref addr))
                {
                    Console.WriteLine($"  [FAILED] WinDivertSend failed. error={Marshal.GetLastWin32Error()}");
                    break;
                }
                reinjected++;
                Console.WriteLine($"  [reinject] {tuple}");
            }
        });

        // Run curl while the pass-through loop re-injects its packets. Capture curl's exit.
        using (var curl = StartCurl())
        {
            if (curl is not null)
            {
                try
                {
                    await Task.WhenAny(curl.WaitForExitAsync(), Task.Delay(TimeSpan.FromSeconds(8)));
                    if (!curl.HasExited)
                    {
                        Console.WriteLine("  [result] curl did not finish within 8s (connection likely stalled).");
                    }
                    else
                    {
                        Console.WriteLine($"  [result] curl exited with code {curl.ExitCode} (0 = HTTPS request succeeded through the pass-through).");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [info] curl wait failed: {ex.Message}");
                }
                finally
                {
                    if (!curl.HasExited) { try { curl.Kill(); } catch { } }
                }
            }
            else
            {
                Console.WriteLine("  [info] Could not start curl for Experiment 4.");
            }
        }

        // Allow the reinject loop a moment to observe curl's traffic, then close.
        await Task.Delay(TimeSpan.FromMilliseconds(500));
        WinDivertNative.WinDivertClose(handle);
        try { await task; } catch { }

        Console.WriteLine($"[info] Experiment 4 handled={handled} reinjected={reinjected} loopDetected={loopDetected}");
        if (loopDetected)
            Console.WriteLine("[FAILED] Capture loop detected during pass-through.");
        else if (reinjected > 0)
            Console.WriteLine("[CONFIRMED] Reinjection works; no capture loop observed.");
        else
            Console.WriteLine("[INCONCLUSIVE] No packets were reinjected within the experiment window.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Receive helpers. These run WinDivertRecv on a background task and enforce
    // a deadline by closing the handle, which unblocks the recv. They own the
    // handle lifecycle: they always close it on return.
    // ─────────────────────────────────────────────────────────────────────────

    private static IntPtr OpenNetworkHandle(out int error)
    {
        error = 0;
        var handle = WinDivertNative.WinDivertOpen(NetworkFilter, WinDivertLayer.Network, 0, 0);
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            error = Marshal.GetLastWin32Error();
        return handle;
    }

    private static async Task<(bool Hit, List<TcpTuple> Packets)> ReceiveUntilAsync(
        IntPtr handle,
        TimeSpan timeout,
        Func<List<TcpTuple>, bool> condition)
    {
        var packets = new List<TcpTuple>();
        var hit = false;
        using var cts = new CancellationTokenSource(timeout);

        var recvTask = Task.Run(() =>
        {
            var buffer = new byte[65535];
            var addr = new WinDivertAddress();
            while (!cts.IsCancellationRequested)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break; // Handle closed (deadline) or error.
                if (readLen < 20) continue;
                if (!TcpPacketParser.TryParse(buffer, readLen, out var tuple)) continue;
                lock (packets)
                {
                    packets.Add(tuple);
                    if (condition(packets))
                    {
                        hit = true;
                        break;
                    }
                }
            }
        }, cts.Token);

        // Wait for the condition or the timeout. Either way we own the handle and
        // close it (closing unblocks a pending blocking recv).
        var completed = await Task.WhenAny(recvTask, Task.Delay(timeout));
        if (completed != recvTask)
        {
            WinDivertNative.WinDivertClose(handle);
            try { await recvTask; } catch { }
        }
        else
        {
            WinDivertNative.WinDivertClose(handle);
        }

        return (hit, packets);
    }

    private sealed record FlowEvent(byte Event, uint Pid, ushort LocalPort, ushort RemotePort, byte Protocol);

    private static async Task<(bool Hit, List<FlowEvent> Events)> ReceiveFlowUntilAsync(
        IntPtr handle,
        TimeSpan timeout,
        Func<List<FlowEvent>, bool> condition)
    {
        var events = new List<FlowEvent>();
        var hit = false;
        using var cts = new CancellationTokenSource(timeout);

        var recvTask = Task.Run(() =>
        {
            var addr = new WinDivertAddress();
            while (!cts.IsCancellationRequested)
            {
                uint readLen = 0;
                if (!WinDivertNative.WinDivertRecv(handle, Array.Empty<byte>(), 0, ref readLen, ref addr))
                    break;

                var e = new FlowEvent(addr.Event, addr.Flow_ProcessId, addr.Flow_LocalPort,
                    addr.Flow_RemotePort, addr.Flow_Protocol);
                lock (events)
                {
                    events.Add(e);
                    if (condition(events))
                    {
                        hit = true;
                        break;
                    }
                }
            }
        }, cts.Token);

        var completed = await Task.WhenAny(recvTask, Task.Delay(timeout));
        if (completed != recvTask)
        {
            WinDivertNative.WinDivertClose(handle);
            try { await recvTask; } catch { }
        }
        else
        {
            WinDivertNative.WinDivertClose(handle);
        }

        return (hit, events);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────
    private static Process? StartCurl()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = $"-s -o NUL --max-time 8 https://{SpikeHost}/",
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

    private static async Task StopCurlAsync(Process curl)
    {
        try
        {
            if (!curl.HasExited)
            {
                await Task.WhenAny(curl.WaitForExitAsync(), Task.Delay(TimeSpan.FromSeconds(1)));
                if (!curl.HasExited)
                    curl.Kill();
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[info] curl cleanup: {ex.Message}");
        }
    }

    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var principal = new System.Security.Principal.WindowsPrincipal(identity);
        return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static string DescribeError(int error) => error switch
    {
        2 => "ERROR_FILE_NOT_FOUND - driver (WinDivert64.sys) not found",
        5 => "ERROR_ACCESS_DENIED - requires Administrator privileges",
        87 => "ERROR_INVALID_PARAMETER - invalid filter syntax",
        577 => "ERROR_INVALID_FUNCTION - driver blocked by security policy",
        1060 => "ERROR_SERVICE_DOES_NOT_EXIST - WinDivert service not installed",
        1275 => "ERROR_INVALID_USER_BUFFER - driver blocked by driver signature enforcement",
        _ => $"unknown error {error}"
    };
}