using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDivertSpike;

/// <summary>
/// Experiment 5 — validate the highest-risk untested assumption of the ferry (R3):
/// a crafted inbound SYN-ACK injected via WinDivert (network layer, Outbound=0,
/// valid IfIdx/SubIfIdx, correct checksums) is ACCEPTED by a real Windows TCP
/// client as the genuine response to its held SYN.
///
/// Setup (self-contained, no external network):
///   - A local TCP server (TcpListener) on loopback listens on an ephemeral port.
///   - A real client (curl) connects to it: that SYN is captured and HELD.
///   - We craft a SYN-ACK as if from the server (src = server IP:port,
///     dst = client IP:port, seq = our chosen server ISN, ack = clientISN+1,
///     SYN|ACK, valid IPv4+TCP checksums) and inject it inbound.
///   - We observe (handle D, SNIFF inbound) whether the client sends an ACK with
///     ack = serverISN+1. That proves the stack accepted our crafted SYN-ACK.
///
/// PASS      : client ACK (flags=0x10, ack=serverISN+1) observed on D.
/// FAIL      : client retransmits its SYN (same seq) and never ACKs our SYN-ACK.
/// INCONCLUSIVE: no packets observed / setup could not reach the loopback connect.
///
/// WinDivert semantics applied (verified against reqrypt.org/windivert-doc.html):
///   - Outbound bit (bit 17) = 0 places the injected packet on the inbound path.
///   - Inbound injection requires valid Network.IfIdx/SubIfIdx.
///   - Injected packets must have correct checksums OR the *Checksum flag unset.
///   - Impostor packets (ours) get TTL decremented on injection; TTL 64 is safe.
/// </summary>
internal static class Experiment5
{
    private const ulong FlagSniffAndRecvOnly = 0x1 | 0x4;

    public static async Task<int> RunAsync()
    {
        Console.WriteLine("[Experiment 5] Crafted inbound SYN-ACK acceptance (R3).");

        // The local server MUST bind a non-loopback address: WinDivert considers
        // loopback packets outbound-only and never captures loopback on the
        // inbound path, so a loopback destination would make the client's reply
        // unobservable (E5 first run: inboundObserved=0, INCONCLUSIVE). Binding the
        // machine's own LAN IP makes the connection hairpin through the physical
        // interface: the outbound SYN is capturable AND the server's reply is
        // capturable inbound — the exact shape the ferry needs.
        var bindIp = IPAddress.Parse("192.168.100.10");

        var listener = new TcpListener(bindIp, 0);
        listener.Start();
        var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
        Console.WriteLine($"  [setup] local TCP server on {bindIp}:{serverPort}");

        // Accept the (held) connection so the test ends cleanly even on FAIL.
        var acceptTask = AcceptOnceAsync(listener);

        // ── Capture handle A (modify mode) for the SYN to the server port ──
        string filter = $"outbound and ip and ip.DstAddr == {bindIp} and tcp and tcp.DstPort == {serverPort}";
        var handleA = WinDivertNative.WinDivertOpen(filter, WinDivertLayer.Network, 0, 0);
        if (handleA == IntPtr.Zero || handleA == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open capture handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }

        // ── Inbound observer D (SNIFF) for the server → client path ──
        string inboundFilter = $"inbound and ip and ip.SrcAddr == {bindIp} and tcp and tcp.SrcPort == {serverPort}";
        var handleD = WinDivertNative.WinDivertOpen(inboundFilter, WinDivertLayer.Network, 1, FlagSniffAndRecvOnly);
        if (handleD == IntPtr.Zero || handleD == new IntPtr(-1))
        {
            Console.WriteLine($"[FAILED] Could not open observer handle. error={Marshal.GetLastWin32Error()}");
            return 1;
        }

        var stop = new CancellationTokenSource();
        var observedInbound = new List<(long Ms, ushort SrcPort, ushort DstPort, byte Flags, uint Seq, uint Ack)>();
        var taskD = Task.Run(() => SniffInbound(handleD, observedInbound, stop.Token));

        // ── Wait for the client's SYN, hold it ──
        // Start the client, then read exactly one SYN.
        var clientIsn = 0u;
        var clientSrcPort = (ushort)0;
        var serverIsn = 0x12345678u;
        var synAddr = new WinDivertAddress();
        var synCaptured = false;

        var captureTask = Task.Run(() =>
        {
            var buffer = new byte[65535];
            var addr = new WinDivertAddress();
            // Capture the first SYN to the server port and do NOT re-inject it.
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
                synAddr = addr;
                synCaptured = true;
                Console.WriteLine($"  [captured SYN] 127.0.0.1:{tuple.SrcPort}->127.0.0.1:{serverPort} " +
                                  $"seq={tuple.Seq} ifIdx={addr.IfIdx} subIf={addr.SubIfIdx} outbound={addr.Outbound}");
                break;
            }
        });

        // Start curl to 127.0.0.1:serverPort (this is what generates the SYN we hold).
        using (var curl = StartCurl(serverPort))
        {
            if (curl is null)
            {
                Console.WriteLine("[INCONCLUSIVE] Could not start curl.");
                stop.Cancel();
                await Task.WhenAll(captureTask, taskD);
                return 1;
            }

            // Wait for the SYN capture (or timeout).
            var gotSyn = await WaitForAsync(() => synCaptured, TimeSpan.FromSeconds(5));
            if (!gotSyn)
            {
                Console.WriteLine("[FAILED] No SYN captured to the server port within 5s.");
                stop.Cancel();
                WinDivertNative.WinDivertClose(handleA);
                WinDivertNative.WinDivertClose(handleD);
                try { await Task.WhenAll(captureTask, taskD); } catch { }
                return 1;
            }

            // ── Craft and inject the SYN-ACK ──
            serverIsn = 0x12345678u;
            var injected = InjectSynAck(handleA, bindIp, (ushort)serverPort, clientSrcPort, serverIsn, clientIsn, ref synAddr);
            if (!injected)
            {
                Console.WriteLine("[FAILED] WinDivertSend for crafted SYN-ACK failed.");
            }
            else
            {
                Console.WriteLine($"  [injected SYN-ACK] {bindIp}:{serverPort}->{bindIp}:{clientSrcPort} " +
                                  $"seq={serverIsn} ack={clientIsn + 1} flags=0x12");
            }

            // Give the client a moment to react, then observe.
            await Task.Delay(TimeSpan.FromSeconds(2));
            if (!curl.HasExited) { try { curl.Kill(); } catch { } }
        }

        // ── Report ──
        stop.Cancel();
        WinDivertNative.WinDivertClose(handleA);
        WinDivertNative.WinDivertClose(handleD);
        try { await Task.WhenAll(captureTask, taskD); } catch { }
        try { listener.Stop(); } catch { }
        try { await acceptTask; } catch { }

        Console.WriteLine($"  [D] inbound packets observed from {bindIp}:{serverPort}: {observedInbound.Count}");
        foreach (var p in observedInbound)
            Console.WriteLine($"    {p.Ms,5}ms {p.SrcPort}->{p.DstPort} flags=0x{p.Flags:X2} seq={p.Seq} ack={p.Ack}");

        // The client's ACK to our SYN-ACK has ack = serverIsn + 1 and flags=0x10 (ACK).
        var clientAck = observedInbound.Any(p =>
            (p.Flags & 0x10) != 0 && p.Ack == serverIsn + 1);
        // A SYN retransmission has the SAME seq as the original clientIsn, flags=0x02.
        var synRetransmit = observedInbound.Any(p =>
            (p.Flags & 0x02) != 0 && p.Seq == clientIsn);

        string classification;
        if (clientAck)
            classification = "PASS";
        else if (synRetransmit)
            classification = "FAIL";
        else
            classification = "INCONCLUSIVE";

        Console.WriteLine($"[classification] {classification}");
        Console.WriteLine($"  evidence: clientACKToCraftedSynAck={clientAck} synRetransmit={synRetransmit} " +
                          $"inboundObserved={observedInbound.Count}");
        Console.WriteLine("=== E5 complete ===");
        return 0;
    }

    /// <summary>
    /// Builds a valid IPv4/TCP SYN-ACK packet (server→client) and injects it on the
    /// inbound path. Returns false if WinDivertSend fails.
    /// </summary>
    private static bool InjectSynAck(
        IntPtr handle,
        IPAddress serverIp,
        ushort serverPort,
        ushort clientPort,
        uint serverIsn,
        uint clientIsn,
        ref WinDivertAddress synAddr)
    {
        // 20-byte IPv4 header (no options) + 20-byte TCP header (no options).
        var packet = new byte[40];

        // ── IPv4 header ──
        packet[0] = 0x45;          // version 4, IHL 5
        packet[1] = 0x00;          // DSCP/ECN
        packet[2] = 0x00; packet[3] = 40; // total length
        packet[4] = 0x00; packet[5] = 0x00; // identification
        packet[6] = 0x40; packet[7] = 0x00; // flags=DF, fragment offset
        packet[8] = 64;            // TTL (impostor decrement keeps it well above 0)
        packet[9] = 6;             // protocol TCP
        // checksum bytes 10-11 computed below
        // src = serverIp (the "server"), dst = serverIp (the client's own IP)
        var serverBytes = serverIp.GetAddressBytes();
        Array.Copy(serverBytes, 0, packet, 12, 4);
        Array.Copy(serverBytes, 0, packet, 16, 4);

        // ── TCP header ──
        int tcp = 20;
        packet[tcp + 0] = (byte)(serverPort >> 8); packet[tcp + 1] = (byte)serverPort;
        packet[tcp + 2] = (byte)(clientPort >> 8); packet[tcp + 3] = (byte)clientPort;
        // seq = serverIsn
        packet[tcp + 4] = (byte)(serverIsn >> 24); packet[tcp + 5] = (byte)(serverIsn >> 16);
        packet[tcp + 6] = (byte)(serverIsn >> 8);  packet[tcp + 7] = (byte)serverIsn;
        // ack = clientIsn + 1
        var ack = clientIsn + 1;
        packet[tcp + 8] = (byte)(ack >> 24);  packet[tcp + 9] = (byte)(ack >> 16);
        packet[tcp + 10] = (byte)(ack >> 8);  packet[tcp + 11] = (byte)ack;
        packet[tcp + 12] = 0x50;             // data offset 5 (no options)
        packet[tcp + 13] = 0x12;             // SYN|ACK
        packet[tcp + 14] = 0x72; packet[tcp + 15] = 0x10; // window 0x7210 = 29200

        // ── Checksums ──
        var ipCsum = InternetChecksum(packet, 0, 20);
        packet[10] = (byte)(ipCsum >> 8); packet[11] = (byte)ipCsum;

        var tcpCsum = TcpChecksum(packet, tcp, 20, new IPAddress(packet[12..16]), new IPAddress(packet[16..20]));
        packet[tcp + 16] = (byte)(tcpCsum >> 8); packet[tcp + 17] = (byte)tcpCsum;

        // ── Inject on the inbound path ──
        var addr = synAddr;              // copy: preserve IfIdx/SubIfIdx from the SYN
        addr.LayerEventFlags &= ~(1u << 17); // clear Outbound bit -> inbound
        addr.LayerEventFlags |= (1u << 19);  // set Impostor bit (we are injecting)
        // IP/TCP checksums are valid, so set the checksum-valid flags.
        addr.LayerEventFlags |= (1u << 21);  // IPChecksum valid
        addr.LayerEventFlags |= (1u << 22);  // TCPChecksum valid

        return WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref addr);
    }

    private static ushort InternetChecksum(byte[] data, int offset, int length)
    {
        uint sum = 0;
        int i = offset;
        while (i + 1 < offset + length)
        {
            sum += (uint)((data[i] << 8) | data[i + 1]);
            i += 2;
        }
        if (i < offset + length)
            sum += (uint)(data[i] << 8);
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    private static ushort TcpChecksum(byte[] packet, int tcpOffset, int tcpLen, IPAddress src, IPAddress dst)
    {
        uint sum = 0;
        // Pseudo-header: src(4) + dst(4) + zero(1) + proto(1) + TCP len(2).
        foreach (var b in src.GetAddressBytes()) sum += b;
        foreach (var b in dst.GetAddressBytes()) sum += b;
        sum += 6u; // protocol
        sum += (uint)tcpLen;
        // TCP header + payload.
        for (int i = tcpOffset; i + 1 < tcpOffset + tcpLen; i += 2)
            sum += (uint)((packet[i] << 8) | packet[i + 1]);
        if ((tcpLen & 1) == 1)
            sum += (uint)(packet[tcpOffset + tcpLen - 1] << 8);
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    private static void SniffInbound(
        IntPtr handle,
        List<(long Ms, ushort SrcPort, ushort DstPort, byte Flags, uint Seq, uint Ack)> events,
        CancellationToken ct)
    {
        var buffer = new byte[65535];
        var addr = new WinDivertAddress();
        var sw = System.Diagnostics.Stopwatch.StartNew();
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
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (sw.Elapsed < timeout)
        {
            if (condition()) return true;
            await Task.Delay(50);
        }
        return condition();
    }

    private static async Task AcceptOnceAsync(TcpListener listener)
    {
        try
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var stream = client.GetStream();
            var buf = new byte[4096];
            try
            {
                // Drain whatever the client sends (it will send the HTTP request).
                while (await stream.ReadAsync(buf, 0, buf.Length) > 0) { }
            }
            catch { }
            // Send a minimal HTTP response so curl (if it reached the server) can
            // complete cleanly rather than hanging.
            try
            {
                var resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(resp));
            }
            catch { }
        }
        catch { /* listener stopped / connection closed */ }
    }

    private static Process? StartCurl(int port)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "curl.exe",
                Arguments = $"-s -o NUL --max-time 6 http://192.168.100.10:{port}/",
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