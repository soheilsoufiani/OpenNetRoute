using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Rules;
using ProxyApp.Network;
using ProxyApp.Processes;

namespace ProxyApp.WinDivert;

/// <summary>
/// The DNS ferry (Phase 8): intercepts outbound DNS queries (IPv4 UDP 53)
/// SYSTEM-WIDE, relays each query through the active SOCKS5 proxy's UDP
/// ASSOCIATE leg to the query's ORIGINAL DNS server, and re-injects the reply
/// inbound — spoofed to appear from the original server — so the application
/// cannot tell the difference. This closes the DNS leak for locally-resolving
/// apps (design + experiments: docs/DNS-DESIGN.md; the capture/attribution/
/// injection mechanics are the PROVEN E8-a/E8-b spike results).
///
/// Why SYSTEM-WIDE (not per-app): Windows apps do not send DNS themselves —
/// the DNS Cache service (svchost.exe, dnscache) sends the UDP 53 query on
/// the app's behalf, so a per-process gate would almost never match the
/// selecting app and the queries would leak (observed live: ipleak's DNS test
/// showed the real IP). DNS queries are low-volume; relaying all of them is
/// what tools like Proxifier do.
///
/// Behavior contract:
/// <list type="bullet">
/// <item>The PID attribution is DIAGNOSTIC ONLY (traced) — it never gates
/// interception.</item>
/// <item>The query's DNS payload is forwarded AS-IS (the E8-b lesson: no
/// reconstruction — a crafted question section was rejected by the client's
/// resolver).</item>
/// <item>Relay failure or timeout is FAIL-CLOSED: the captured query is
/// dropped and traced; the client's resolver retries. If the proxy does not
/// support UDP ASSOCIATE, system DNS fails while enabled — disable the
/// setting or enable UDP support in the proxy.</item>
/// <item>Injected replies are INBOUND (the Outbound address flag cleared) —
/// the capture filter is outbound-only, so no capture/injection loop (E8-a/E8-b
/// verified).</item>
/// <item>Known limits: DoH/DoT bypasses packet interception entirely; DNS over
/// IPv6 transport is not intercepted (Phase 9); WebRTC/STUN (UDP 3478) is
/// arbitrary UDP — not covered until R6; the proxy must support UDP
/// ASSOCIATE.</item>
/// </list>
/// </summary>
public sealed class UdpDnsFerry : IDisposable
{
    /// <summary>STUN/ICE UDP ports relayed when <see cref="DnsSettings.RelayStun"/>:
    /// the standard ports (3478/3479, 5348/5349) plus Google's STUN range
    /// 19302–19309 (browsers' default STUN servers — stun.l.google.com:19302
    /// — live here; the WebRTC leak test uses them).</summary>
    internal static readonly IReadOnlyCollection<int> StunPorts =
        [3478, 3479, 5348, 5349, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309];

    private const string CaptureFilter = "outbound and ip and udp and udp.DstPort == 53 and not loopback";

    /// <summary>Per-query relay timeout — the client's resolver retries on its own.</summary>
    private static readonly TimeSpan RelayTimeout = TimeSpan.FromSeconds(2);

    private readonly DnsSettings _dns;
    private readonly bool _gameMode;
    private readonly Func<ISocks5UdpRelay> _relayFactory;
    private readonly Action<string>? _trace;
    private readonly Action<bool, string>? _relayStatus;
    private IPAddress? _resolverOverride;

    /// <summary>Human-readable relay state for the UI ("Starting…/Active/FAILED: …").</summary>
    private volatile string _relayStatusText = "Not started";

    /// <summary>The current DNS-relay status ("Active" / "FAILED: …").</summary>
    public string RelayStatus => _relayStatusText;

    private IntPtr _captureHandle = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _captureLoop;
    private volatile bool _isRunning;

    // ── Relay lifecycle ──
    // One association for the whole session (RFC 1928 §7: the association
    // lives as long as the TCP control connection). (Re-)established lazily
    // and retried after failures — availability over secrecy, loudly traced.
    private readonly SemaphoreSlim _relayLock = new(1, 1);
    private ISocks5UdpRelay? _relay;
    private DateTimeOffset _nextRelayRetry = DateTimeOffset.MinValue;

    // ── Process identity cache (PID → name/path) — DNS bursts hit the same PID ──
    private readonly ConcurrentDictionary<int, (string? Name, string? Path)> _processByIdentity = new();

    // ── Health counters (Interlocked) ──
    private long _queriesCaptured;
    private long _queriesRelayed;
    private long _queriesPassedThrough;
    private long _repliesInjected;
    private long _relayFailures;

    /// <summary>Total captured outbound UDP 53 queries.</summary>
    internal long QueriesCaptured => Interlocked.Read(ref _queriesCaptured);

    /// <summary>Total queries relayed through the proxy.</summary>
    internal long QueriesRelayed => Interlocked.Read(ref _queriesRelayed);

    /// <summary>Total queries re-injected unchanged (non-selected processes).</summary>
    internal long QueriesPassedThrough => Interlocked.Read(ref _queriesPassedThrough);

    /// <summary>Total replies re-injected inbound.</summary>
    internal long RepliesInjected => Interlocked.Read(ref _repliesInjected);

    /// <summary>Total relay failures (fail-closed drops + client retry).</summary>
    internal long RelayFailures => Interlocked.Read(ref _relayFailures);

    /// <summary>Creates the ferry. <paramref name="relayFactory"/> creates one relay per session.</summary>
    /// <param name="relayStatus">Optional UI sink for the eager relay-probe result
    /// (true = active; false = failed — e.g. the proxy has no UDP support).</param>
    public UdpDnsFerry(
        DnsSettings dnsSettings,
        Func<ISocks5UdpRelay> relayFactory,
        Action<string>? trace = null,
        Action<bool, string>? relayStatus = null,
        bool gameMode = false)
    {
        _dns = dnsSettings ?? throw new ArgumentNullException(nameof(dnsSettings));
        _relayFactory = relayFactory ?? throw new ArgumentNullException(nameof(relayFactory));
        _trace = trace;
        _relayStatus = relayStatus;
        _gameMode = gameMode;
    }

    private void Trace(string message) => _trace?.Invoke($"[UdpDns] {message}");

    private void SetRelayStatus(bool ok, string message)
    {
        _relayStatusText = ok ? "Active" : $"FAILED: {message}";
        _relayStatus?.Invoke(ok, message);
    }

    /// <summary>
    /// Builds the WinDivert filter: outbound UDP 53 (plus the STUN/ICE port
    /// set when <paramref name="relayStun"/>), never loopback. Outbound-only
    /// capture ⇒ injected (inbound) replies can never loop.
    /// </summary>
    internal static string BuildFilter(bool relayStun)
    {
        if (!relayStun)
            return CaptureFilter;
        var stunPorts = string.Join(", ", StunPorts);
        return "outbound and ip and udp and " +
               $"(udp.DstPort == 53 or udp.DstPort in {{{stunPorts}}}) and not loopback";
    }

    /// <summary>True when the capture loop is running.</summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// Starts the capture loop. Opens a WinDivert network handle for the UDP 53
    /// filter (plus UDP 3478 STUN when <see cref="DnsSettings.RelayStun"/>);
    /// the relay is established lazily on the first intercepted query.
    /// </summary>
    public void Start()
    {
        if (_isRunning)
            return;

        // Resolver override: a strict IPv4 literal relayed queries are sent to
        // instead of each query's own server (keeps the ISP resolver out of
        // the path). Null = transparent.
        _resolverOverride = null;
        if (!string.IsNullOrEmpty(_dns.ResolverOverride))
        {
            if (!DestinationMatch.TryParseIpv4(_dns.ResolverOverride, out var overrideIp))
                throw new InvalidOperationException(
                    $"DNS resolver override '{_dns.ResolverOverride}' is not a valid IPv4 address.");
            _resolverOverride = overrideIp;
        }

        WinDivertLibrary.EnsureRegistered();

        // Outbound-only capture ⇒ injected (inbound) replies can never loop.
        var filter = BuildFilter(_dns.RelayStun);

        _captureHandle = WinDivertNative.WinDivertOpen(
            filter, WinDivertLayer.Network, 0, 0);
        if (_captureHandle == IntPtr.Zero || _captureHandle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"WinDivertOpen failed for the DNS capture: error {err}. " +
                "Check that the application is running with administrator privileges.");
        }

        WinDivertNative.WinDivertSetParam(_captureHandle, WinDivertNative.Params.QueueLength, 8192);
        WinDivertNative.WinDivertSetParam(_captureHandle, WinDivertNative.Params.QueueTime, 2000);
        WinDivertNative.WinDivertSetParam(_captureHandle, WinDivertNative.Params.QueueSize, 4194304);

        _isRunning = true;
        _cts = new CancellationTokenSource();
        _captureLoop = Task.Run(() => CaptureLoopAsync(_cts.Token));

        // ── EAGER relay probe: establish the UDP ASSOCIATE NOW (not lazily on
        //    the first query) so a proxy without UDP support is reported at
        //    START, not discovered in silence later. Retried in the background
        //    every 15 s until it succeeds. ──
        _relayStatusText = "Probing…";
        Trace(_dns.RelayStun
            ? $"DNS ferry started (outbound UDP 53 + STUN capture, resolver override '{_dns.ResolverOverride}') — probing the relay…"
            : $"DNS ferry started (outbound UDP 53 capture, resolver override '{_dns.ResolverOverride}') — probing the relay…");
        _ = Task.Run(() => ProbeRelayUntilRunningAsync(_cts.Token));
    }

    /// <summary>Probes the association at START and retries every 15 s while running.</summary>
    private async Task ProbeRelayUntilRunningAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && _isRunning)
        {
            try
            {
                await EnsureRelayAsync(ct).ConfigureAwait(false);
                SetRelayStatus(true, "DNS relay active (UDP ASSOCIATE established).");
                Trace("DNS relay ACTIVE — queries will be relayed through the proxy.");
                return;
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (Exception ex)
            {
                SetRelayStatus(false,
                    $"DNS relay FAILED — the proxy did not accept UDP ASSOCIATE ({ex.Message}). " +
                    "Queries are dropped while this persists; enable UDP support in your proxy.");
                Trace($"relay probe failed: {ex.Message} — retrying in 15 s.");
                try { await Task.Delay(TimeSpan.FromSeconds(15), ct).ConfigureAwait(false); }
                catch (OperationCanceledException) { return; }
            }
        }
    }

    /// <summary>Stops the capture loop and the relay association.</summary>
    public async Task StopAsync()
    {
        if (!_isRunning)
            return;

        _isRunning = false;
        _cts?.Cancel();
        try { if (_captureLoop is not null) await _captureLoop.ConfigureAwait(false); } catch { }
        WinDivertNative.WinDivertClose(_captureHandle);
        _captureHandle = IntPtr.Zero;

        await _relayLock.WaitAsync().ConfigureAwait(false);
        try
        {
            _relay?.Dispose();
            _relay = null;
            _nextRelayRetry = DateTimeOffset.MinValue;
        }
        finally
        {
            _relayLock.Release();
        }

        Trace("DNS ferry stopped.");
    }

    private async Task CaptureLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[65535];
        while (!ct.IsCancellationRequested)
        {
            try
            {
                uint readLen = 0;
                var addr = new WinDivertAddress();
                if (!WinDivertNative.WinDivertRecv(_captureHandle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break; // handle closed

                if (readLen < 28)
                    continue; // IP(20) + UDP(8) minimum

                await HandleDatagramAsync(buffer, readLen, addr, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // Never let one bad packet/flow kill the capture loop.
                Trace($"capture-loop error (recovered): {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    private async Task HandleDatagramAsync(byte[] buffer, uint readLen, WinDivertAddress addr, CancellationToken ct)
    {
        Interlocked.Increment(ref _queriesCaptured);

        // ── Parse the IPv4 + UDP headers (E8-b ParseUdp, typed) ──
        if (!UdpPacketParser.TryParse(buffer, readLen,
                out var srcIp, out var dstIp, out var srcPort, out var dstPort, out var ihl))
        {
            Interlocked.Increment(ref _queriesPassedThrough);
            ReinjectUnchanged(buffer, readLen, addr);
            return;
        }

        // ── Attribute the owning process (E8-a: GetExtendedUdpTable) —
        //    DIAGNOSTIC ONLY. System DNS arrives from svchost (dnscache),
        //    never from the selecting app, so it must not gate interception. ──
        var pid = UdpProcessTable.ResolveOwnerPid(srcIp, srcPort);
        var (name, _) = ResolveProcessIdentity(pid);

        var dnsPayload = buffer.AsSpan(ihl + 8, (int)readLen - ihl - 8).ToArray();

        // Relay target: the configured public resolver keeps the user's ISP
        // resolver out of the path (leak tests show the public resolver's
        // egress, not the ISP); null = transparent (each query's own server).
        var relayTarget = _resolverOverride ?? dstIp;

        // Correlation key: a DNS reply echoes the transaction ID in the FIRST
        // TWO bytes; a STUN reply echoes its 12-byte transaction ID in the
        // first 12 (the message type changes, so 2 bytes do not correlate).
        var correlationBytes = dstPort == 53 ? 2 : 12;

        Trace($"query {srcIp}:{srcPort} -> {dstIp}:{dstPort} pid={pid} name={name ?? "?"} " +
              $"({dnsPayload.Length} bytes) — relaying via proxy to {relayTarget}:{dstPort}");

        // ── Relay through the proxy (fail-closed: drop on failure) ──
        try
        {
            var relay = await EnsureRelayAsync(ct).ConfigureAwait(false);
            var result = await relay
                .RelayAsync(dnsPayload, relayTarget, dstPort, RelayTimeout, ct, correlationBytes)
                .ConfigureAwait(false);

            Interlocked.Increment(ref _queriesRelayed);

            // ── Re-inject the reply inbound, spoofed from the ORIGINAL server
            //    the client addressed (its socket expects that source — even
            //    when the reply actually came from the override resolver;
            //    E8-b InjectUdp: Outbound cleared, IfIdx/SubIfIdx preserved,
            //    helper checksums, Impostor=0). ──
            var packet = UdpPacketParser.BuildUdpPacket(dstIp, srcIp, (ushort)dstPort, srcPort, result.DnsPayload);
            var replyAddr = addr;
            replyAddr.LayerEventFlags &= ~(1uL << 17); // clear Outbound → inbound
            ApplyGameModeDscp(packet);
            WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref replyAddr, 0);
            if (WinDivertNative.WinDivertSend(_captureHandle, packet, (uint)packet.Length, IntPtr.Zero, ref replyAddr))
            {
                Interlocked.Increment(ref _repliesInjected);
            }
            else
            {
                var err = Marshal.GetLastWin32Error();
                Trace($"reply injection FAILED (error {err}) — the client's resolver will retry.");
            }
        }
        catch (OperationCanceledException)
        {
            Interlocked.Increment(ref _relayFailures);
            Trace($"query relay cancelled (shutdown) — dropped, client will retry.");
        }
        catch (Exception ex)
        {
            // Fail-closed: never re-inject the query (that would leak it) — the
            // client's resolver retries shortly.
            Interlocked.Increment(ref _relayFailures);
            Trace($"query relay FAILED ({ex.Message}) — dropped (fail-closed), client will retry.");
        }
    }

    /// <summary>Re-injects a captured packet unchanged (pass-through, no rewrite).</summary>
    private void ReinjectUnchanged(byte[] buffer, uint readLen, WinDivertAddress addr)
    {
        var passAddr = addr; // outbound preserved — the packet goes on its way
        WinDivertNative.WinDivertSend(_captureHandle, buffer, readLen, IntPtr.Zero, ref passAddr);
    }

    /// <summary>
    /// Game Mode packet tuning: DSCP EF (Expedited Forwarding) on IPv4 packets
    /// we inject toward the client — ECN bits preserved. Must run BEFORE the
    /// checksum helper (the IPv4 header checksum covers the TOS byte).
    /// </summary>
    private void ApplyGameModeDscp(byte[] packet)
    {
        if (!_gameMode || packet.Length < 2)
            return;
        packet[1] = (byte)((packet[1] & 0x03) | 0xB8); // DSCP 46 (EF) << 2
    }

    /// <summary>Gets the association (re-establishing after a failure at most every 15 s).</summary>
    private async Task<ISocks5UdpRelay> EnsureRelayAsync(CancellationToken ct)
    {
        await _relayLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_relay is { IsAssociated: true })
                return _relay;

            if (DateTimeOffset.UtcNow < _nextRelayRetry)
                throw new InvalidOperationException("The UDP relay is not available (retrying shortly).");

            _relay?.Dispose();
            _relay = _relayFactory();
            try
            {
                await _relay.StartAsync(ct).ConfigureAwait(false);
                _nextRelayRetry = DateTimeOffset.MinValue;
                Trace("UDP ASSOCIATE established through the proxy.");
            }
            catch (Exception ex)
            {
                // Loud trace, then back off — queries fail-closed until the
                // proxy accepts an association again.
                _nextRelayRetry = DateTimeOffset.UtcNow.AddSeconds(15);
                throw new InvalidOperationException(
                    $"UDP ASSOCIATE with the proxy failed: {ex.Message}", ex);
            }
            return _relay;
        }
        finally
        {
            _relayLock.Release();
        }
    }

    /// <summary>
    /// Resolves the process name + path for a PID (cached; DNS bursts repeat).
    /// Unattributable or vanished processes resolve to (null, null) —
    /// name-only rules still match, everything else passes through.
    /// </summary>
    private (string? Name, string? Path) ResolveProcessIdentity(int? pid)
    {
        if (pid is not { } id || id <= 0)
            return (null, null);

        return _processByIdentity.GetOrAdd(id, static pid2 =>
        {
            try
            {
                using var process = System.Diagnostics.Process.GetProcessById(pid2);
                if (process is null)
                    return (null, null);
                string? name = null;
                string? path = null;
                try
                {
                    name = process.ProcessName + ".exe";
                    path = process.MainModule?.FileName;
                }
                catch
                {
                    // Access denied / 32-64 bit boundary — name may still be set.
                }
                return (name, path);
            }
            catch
            {
                return (null, null); // process exited during lookup — documented race
            }
        });
    }

    public void Dispose()
    {
        try { StopAsync().GetAwaiter().GetResult(); } catch { }
        _relayLock.Dispose();
    }
}
