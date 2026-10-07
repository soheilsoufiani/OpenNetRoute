using System.Runtime.InteropServices;

namespace ProxyApp.WinDivert;

/// <summary>
/// Drops outbound STUN address-discovery datagrams, identified by CONTENT
/// (the RFC 5389 magic cookie) rather than by destination port.
///
/// <para>
/// WHY A SEPARATE, BROADER CAPTURE: the DNS ferry's handle is port-matched,
/// which is fine for DNS but useless for STUN — a WebRTC server may listen on
/// any port, and the browserleaks.com test uses a non-standard one. Blocking by
/// port therefore let the real address through while appearing to work. This
/// handle captures outbound UDP broadly so <see cref="StunMessage"/> can decide.
/// </para>
///
/// <para>
/// THE COST, STATED PLAINLY: this copies every outbound UDP datagram (except
/// loopback and port 53, which the DNS ferry owns) into this process. That is
/// real overhead, proportional to UDP volume, and it is why this runs ONLY when
/// the user explicitly enables WebRTC blocking.
/// </para>
///
/// <para>
/// THE LOOP IS DELIBERATELY SYNCHRONOUS AND AWAIT-FREE. If the queue overflows
/// while this loop is descheduled, WinDivert drops packets at the driver — and
/// for a broad filter that would break unrelated traffic, not just WebRTC. The
/// loop therefore does no allocation, no parsing beyond four bytes, no logging
/// on the hot path, and never awaits: recv → test → re-inject or drop. Logging
/// happens only for actual drops, which are rare.
/// </para>
/// </summary>
internal sealed class StunBlocker : IDisposable
{
    /// <summary>
    /// Outbound UDP, excluding loopback and DNS. Port 53 is excluded so this
    /// handle and the DNS ferry never both consume the same datagram — two
    /// diverting handles on one packet is a race, not a feature.
    /// </summary>
    internal const string CaptureFilter =
        "outbound and ip and udp and udp.DstPort != 53 and not loopback";

    /// <summary>The IPv6 twin of <see cref="CaptureFilter"/> (a filter cannot mix families).</summary>
    internal const string CaptureFilterV6 =
        "outbound and ipv6 and udp and udp.DstPort != 53 and not loopback";

    private readonly Action<string>? _trace;
    private IntPtr _handle = IntPtr.Zero;
    private IntPtr _handleV6 = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private Task? _loopV6;
    private long _dropped;

    /// <summary>STUN datagrams dropped this session.</summary>
    internal long Dropped => Interlocked.Read(ref _dropped);

    /// <summary>True while the blocker is capturing.</summary>
    public bool IsRunning => _handle != IntPtr.Zero;

    /// <summary>True when the IPv6 handle is also open (false on a v4-only host).</summary>
    public bool IsIpv6Active => _handleV6 != IntPtr.Zero;

    /// <summary>Creates the blocker.</summary>
    /// <param name="trace">Optional sink; called only on an actual drop.</param>
    public StunBlocker(Action<string>? trace = null)
    {
        _trace = trace;
    }

    /// <summary>Opens the capture handle(s) and starts the drop loop.</summary>
    public void Start()
    {
        if (_handle != IntPtr.Zero)
            return;

        WinDivertLibrary.EnsureRegistered();

        _handle = WinDivertNative.WinDivertOpen(
            CaptureFilter, WinDivertLayer.Network, 0, 0);
        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            _handle = IntPtr.Zero;
            _trace?.Invoke(
                $"[WebRTC] STUN blocker could not start (WinDivertOpen error {err}) — " +
                "WebRTC will NOT be blocked. Routing is unaffected.");
            return;
        }

        // Generous queues: this loop must never fall behind, because a full
        // queue on a broad filter drops OTHER traffic too.
        WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.Params.QueueLength, 16384);
        WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.Params.QueueTime, 2000);
        WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.Params.QueueSize, 33554432);

        _handleV6 = WinDivertNative.WinDivertOpen(
            CaptureFilterV6, WinDivertLayer.Network, 0, 0);
        if (_handleV6 == IntPtr.Zero || _handleV6 == new IntPtr(-1))
        {
            var v6err = Marshal.GetLastWin32Error();
            _handleV6 = IntPtr.Zero;
            _trace?.Invoke(
                $"[WebRTC] IPv6 STUN blocking unavailable (WinDivertOpen error {v6err}) — " +
                "browsers prefer IPv6 for STUN, so WebRTC could still leak via IPv6.");
        }

        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => DropLoop(_handle, false));
        if (_handleV6 != IntPtr.Zero)
            _loopV6 = Task.Run(() => DropLoop(_handleV6, true));

        _trace?.Invoke(
            "[WebRTC] STUN blocking ACTIVE — matched by message content on ANY port " +
            "(not a port list), on IPv4" +
            (_handleV6 != IntPtr.Zero ? " and IPv6." : " only (no IPv6 handle)."));
    }

    /// <summary>
    /// The drop loop. Deliberately allocation-free and await-free on the hot
    /// path — see the class remarks for why a stall here is dangerous.
    /// </summary>
    private void DropLoop(IntPtr handle, bool isV6)
    {
        var buffer = new byte[65535];
        var ct = _cts?.Token ?? CancellationToken.None;

        while (!ct.IsCancellationRequested)
        {
            try
            {
                uint readLen = 0;
                var addr = new WinDivertAddress();
                if (!WinDivertNative.WinDivertRecv(
                        handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break; // handle closed

                var ipHeaderLength = isV6 ? UdpPacketParser.Ipv6HeaderLength : 20;
                const int udpHeaderLength = 8;
                var payloadStart = ipHeaderLength + udpHeaderLength;

                if (readLen > (uint)payloadStart &&
                    StunMessage.IsStun(buffer.AsSpan(payloadStart, (int)readLen - payloadStart)))
                {
                    // NOT re-injecting is the block. There is deliberately no
                    // fallback path: a STUN request that escaped here is
                    // exactly the disclosure this setting exists to prevent.
                    var n = Interlocked.Increment(ref _dropped);
                    // Log the first few and then only occasionally, so a
                    // STUN flood cannot flood the log.
                    if (n <= 3 || (n & 0x3FF) == 0)
                        _trace?.Invoke(
                            $"[WebRTC] blocked STUN datagram #{n} " +
                            $"(IPv{(isV6 ? 6 : 4)}, content-matched, {readLen} bytes) — " +
                            "WebRTC cannot learn your public address from this.");
                    continue;
                }

                // Not STUN: put it straight back. Anything this handle does not
                // block must behave exactly as if the handle did not exist.
                WinDivertNative.WinDivertSend(
                    handle, buffer, readLen, IntPtr.Zero, ref addr);
            }
            catch (Exception ex)
            {
                // Never let the loop die: a dead blocker silently disables the
                // protection the user believes they have.
                _trace?.Invoke($"[WebRTC] STUN blocker error (recovered): {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    /// <summary>Closes both handles and stops the loop.</summary>
    public async Task StopAsync()
    {
        _cts?.Cancel();
        if (_handle != IntPtr.Zero)
        {
            WinDivertNative.WinDivertClose(_handle);
            _handle = IntPtr.Zero;
        }
        if (_handleV6 != IntPtr.Zero)
        {
            WinDivertNative.WinDivertClose(_handleV6);
            _handleV6 = IntPtr.Zero;
        }
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); } catch { }
        }
        if (_loopV6 is not null)
        {
            try { await _loopV6.ConfigureAwait(false); } catch { }
        }
        _cts?.Dispose();
        _cts = null;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        try { StopAsync().GetAwaiter().GetResult(); } catch { }
    }
}