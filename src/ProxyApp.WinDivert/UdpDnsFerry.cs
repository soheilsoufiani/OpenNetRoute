using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using ProxyApp.Core.Configuration;
using ProxyApp.Network;
using ProxyApp.Processes;

namespace ProxyApp.WinDivert;

/// <summary>
/// The DNS ferry: intercepts outbound DNS queries SYSTEM-WIDE over BOTH IPv4
/// and IPv6 (UDP 53, two WinDivert handles), relays each query through the
/// active SOCKS5 proxy's UDP ASSOCIATE leg to the query's ORIGINAL DNS server,
/// and re-injects the reply inbound — spoofed to appear from the original
/// server — so the application cannot tell the difference (design + experiments:
/// docs/DNS-DESIGN.md; the capture/attribution/injection mechanics are the
/// PROVEN E8-a/E8-b spike results).
///
/// Plaintext DNS over TCP/53 is relayed too — as a forced-proxy port in the
/// <see cref="TcpFerry"/> (both transports are needed: Windows falls back to
/// TCP/53 for truncated answers, and some resolvers are TCP-only).
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
/// <item>Unparsable captured packets are dropped fail-closed (never
/// re-injected): a packet the parser cannot understand must not take the
/// direct path. This includes IPv6 packets carrying extension headers.</item>
/// <item>The Windows resolver cache is flushed at START and STOP, so a name
/// resolved before interception cannot be answered from cache without being
/// relayed.</item>
/// <item>Known limits: encrypted DNS (DoH/DoT/DoQ) bypasses packet
/// interception entirely, and custom resolvers on non-standard ports are
/// outside the port-53 capture; the proxy must support UDP ASSOCIATE.</item>
/// </list>
/// </summary>
public sealed class UdpDnsFerry : IDisposable
{
    /// <summary>
    /// STUN/ICE UDP ports captured as a FAST PATH when STUN handling is on:
    /// the standard ports (3478/3479, 5348/5349) plus Google's STUN range
    /// 19302–19309 (browsers hard-code stun.l.google.com:19302).
    ///
    /// THIS LIST IS NOT SUFFICIENT, and treating it as if it were was a real,
    /// reported bug: WebRTC servers may listen on ANY port (the port is carried
    /// in the STUN server URI), and browserleaks.com's WebRTC test in particular
    /// uses a non-standard port. A port-matched filter therefore let that
    /// traffic through untouched, STUN succeeded, and the page showed a
    /// server-reflexive candidate carrying the real address.
    ///
    /// It is kept only because capturing two known ports is far cheaper than
    /// inspecting every UDP datagram. <see cref="StunMessage.IsStun"/> is the
    /// authoritative test; see <see cref="BuildWebRtcFilter"/>.
    /// </summary>
    internal static readonly IReadOnlyCollection<int> StunPorts =
        [3478, 3479, 5348, 5349, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309];

    private const string CaptureFilter = "outbound and ip and udp and udp.DstPort == 53 and not loopback";

    /// <summary>IPv6 twin of <see cref="CaptureFilter"/>: outbound v6 UDP 53, never loopback.</summary>
    private const string CaptureFilterV6 = "outbound and ipv6 and udp and udp.DstPort == 53 and not loopback";

    /// <summary>Per-query relay timeout — the client's resolver retries on its own.</summary>
    private static readonly TimeSpan RelayTimeout = TimeSpan.FromSeconds(2);

    private readonly DnsSettings _dns;
    private readonly bool _gameMode;
    private readonly Func<ISocks5UdpRelay> _relayFactory;
    private readonly Action<string>? _trace;
    private readonly Action<bool, string>? _relayStatus;
    private IPAddress? _resolverOverride;

    /// <summary>IPv6 resolver override (the v6 query path's override); null = none.</summary>
    private IPAddress? _resolverOverrideV6;

    /// <summary>Human-readable relay state for the UI ("Starting…/Active/FAILED: …").</summary>
    private volatile string _relayStatusText = "Not started";

    /// <summary>The current DNS-relay status ("Active" / "FAILED: …").</summary>
    public string RelayStatus => _relayStatusText;

    private IntPtr _captureHandle = IntPtr.Zero;
    private IntPtr _captureHandleV6 = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _captureLoop;
    private Task? _captureLoopV6;
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
    private long _queriesDroppedUnparsable;
    private long _repliesInjected;
    private long _relayFailures;

    // ── STUN/ICE counters (separate from DNS: the two are different features
    //    with different failure modes, and mixing them in one number would
    //    hide a working DNS relay behind a broken STUN relay or vice versa) ──
    private long _stunCaptured;
    private long _stunRelayed;
    private long _stunInjected;
    private long _stunFailures;

    /// <summary>STUN/ICE datagrams dropped by the WebRTC block.</summary>
    private long _webRtcBlocked;

    /// <summary>Total captured STUN/ICE datagrams (UDP, DNS or STUN ports).</summary>
    internal long StunCaptured => Interlocked.Read(ref _stunCaptured);

    /// <summary>STUN datagrams successfully relayed through the proxy.</summary>
    internal long StunRelayed => Interlocked.Read(ref _stunRelayed);

    /// <summary>STUN replies re-injected inbound toward the client.</summary>
    internal long StunInjected => Interlocked.Read(ref _stunInjected);

    /// <summary>
    /// STUN relay failures (fail-closed drops). Non-zero means WebRTC is
    /// falling back to whatever transport it can reach directly — the likely
    /// cause of a WebRTC leak test still reporting the real address.
    /// </summary>
    internal long StunFailures => Interlocked.Read(ref _stunFailures);

    /// <summary>Total captured outbound UDP 53 queries.</summary>
    internal long QueriesCaptured => Interlocked.Read(ref _queriesCaptured);

    /// <summary>Total queries relayed through the proxy.</summary>
    internal long QueriesRelayed => Interlocked.Read(ref _queriesRelayed);

    /// <summary>
    /// Total captured datagrams dropped because the parser could not read them
    /// (fail-closed). Was a "passed through" counter before fail-closed parsing:
    /// an unparsable captured query is now NEVER re-injected.
    /// </summary>
    internal long QueriesDroppedUnparsable => Interlocked.Read(ref _queriesDroppedUnparsable);

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
    internal static IPAddress ResolveRelayTarget(
        IPAddress dstIp, ushort dstPort, IPAddress? resolverOverride)
        => dstPort == 53 && resolverOverride is not null ? resolverOverride : dstIp;

    /// <summary>
    /// Builds the WinDivert filter for one address family: outbound UDP 53
    /// (when DNS relaying is on) plus the STUN/ICE ports (when STUN relaying OR
    /// blocking is on), never loopback. Outbound-only capture ⇒ injected
    /// (inbound) replies can never loop.
    ///
    /// Each leg is INDEPENDENT so enabling one never captures the other:
    /// blocking WebRTC must not silently start intercepting DNS, and relaying
    /// STUN must not either.
    /// </summary>
    internal static string BuildFilter(
        bool dnsEnabled, bool stunPortsEnabled,
        bool relayStun = true) => BuildFamilyFilter("ip", dnsEnabled, stunPortsEnabled);

    /// <summary>The IPv6 twin of <see cref="BuildFilter"/> (see the class remarks).</summary>
    /// <summary>
    /// The IPv6 twin of <see cref="BuildFilter"/>. Built by the SAME helper as
    /// IPv4 precisely because STUN being absent from IPv6 (with a comment
    /// asserting "STUN is IPv4-standard") was a real reported defect: browsers
    /// resolve AAAA records and prefer IPv6 for the same STUN server, so on a
    /// dual-stack machine STUN left the IPv4 handle and went out the IPv6 NIC
    /// directly, reporting the real address while the setting showed "on".
    /// </summary>
    internal static string BuildFilterV6(bool dnsEnabled, bool stunPortsEnabled, bool relayStun = true)
        => BuildFamilyFilter("ipv6", dnsEnabled, stunPortsEnabled);

    /// <summary>
    /// The shared filter construction. A WinDivert expression cannot mix
    /// <c>ip</c> and <c>ipv6</c>, which is why both families need their own
    /// handle — and why both are built from this one function: a hand-written
    /// IPv6 variant is exactly how STUN ended up missing from IPv6 while
    /// looking correct in review.
    /// </summary>
    private static string BuildFamilyFilter(string family, bool dnsEnabled, bool stunPortsEnabled)
    {
        if (!dnsEnabled && !stunPortsEnabled)
            // Nothing to capture on this family. The caller must not open a
            // handle for it (an always-matching handle would cost a queue and
            // deliver every packet for nothing).
            return $"outbound and {family} and udp and udp.DstPort == 0 and not loopback";

        var conditions = new List<string>();
        if (dnsEnabled)
            conditions.Add("udp.DstPort == 53");
        if (stunPortsEnabled)
            conditions.Add($"udp.DstPort in {{{string.Join(", ", StunPorts)}}}");

        // With one condition the parentheses are pure noise, and keeping the
        // single-leg form byte-identical to the historical filter makes the
        // unchanged case obvious in review and in the tests.
        var portClause = conditions.Count == 1
            ? conditions[0]
            : $"({string.Join(" or ", conditions)})";

        return $"outbound and {family} and udp and {portClause} and not loopback";
    }

    /// <summary>True when the capture loop is running.</summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// True when the IPv6 UDP capture handle is open. False on a v4-only host
    /// (benign) and also when the v6 handle FAILED to open on a dual-stack host
    /// (a real exposure: IPv6 DNS would go direct). Traced either way.
    /// </summary>
    public bool IsIpv6CaptureActive => _captureHandleV6 != IntPtr.Zero;

    /// <summary>
    /// True when STUN/ICE relaying is enabled in the CURRENT settings. Read by
    /// the UI so it can tell the user the difference between "STUN relaying is
    /// on but captured nothing" (a port/address-family problem) and "STUN
    /// relaying is off" (the setting simply is not in effect).
    /// </summary>
    public bool IsStunRelayEnabled => _dns.RelayStun && !_dns.BlockWebRtc;

    /// <summary>
    /// True when STUN/ICE is being dropped rather than relayed. Blocking wins
    /// over relaying when both are set: of the two, it is the only one that
    /// cannot fail open into a direct candidate.
    /// </summary>
    public bool IsWebRtcBlocked => _dns.BlockWebRtc;

    /// <summary>
    /// True when the DNS relay leg is enabled. Independent of the STUN legs —
    /// the two can be used separately (blocking WebRTC must not start
    /// intercepting DNS).
    /// </summary>
    public bool IsDnsRelayEnabled => _dns.Enabled;

    /// <summary>
    /// The STUN/ICE datagrams dropped by <see cref="IsWebRtcBlocked"/>. Surfaced
    /// in the UI so "blocking is on" is visibly doing something rather than
    /// being indistinguishable from "blocking is on but nothing matched".
    /// </summary>
    internal long WebRtcBlocked => Interlocked.Read(ref _webRtcBlocked);

    /// <summary>
    /// The decision for one captured datagram: drop it, relay it, or ignore it.
    /// Split out as an internal seam so the precedence rule — blocking wins
    /// over relaying — is unit-testable without a WinDivert handle, and so the
    /// capture loop cannot grow a second, subtly different path.
    ///
    /// Ignored means "re-inject unchanged": nothing intercepted it, which for
    /// the DNS ferry is fail-closed (never reached) and for STUN means the port
    /// was outside the filter.
    /// </summary>
    public enum StunDisposition
    {
        /// <summary>Not captured; the packet continues untouched.</summary>
        PassThrough,

        /// <summary>Relay through the proxy (STUN relaying enabled).</summary>
        Relay,

        /// <summary>Drop locally (WebRTC blocking enabled).</summary>
        Drop
    }

    /// <summary>
    /// Decides what happens to a captured non-DNS datagram.
    ///
    /// Blocking wins over relaying, and that precedence is deliberate rather
    /// than incidental: of the two, dropping is the only one that cannot fail
    /// open. A relay failure (no UDP ASSOCIATE, an unlisted port, a timeout)
    /// makes WebRTC fall back to a direct candidate and report the real
    /// address — the exact leak the user is trying to close — so when a user
    /// has explicitly asked for WebRTC protection, the stricter behaviour wins.
    /// </summary>
    internal static StunDisposition DecideStunDisposition(bool blockWebRtc, bool relayStun)
        => blockWebRtc ? StunDisposition.Drop
            : relayStun ? StunDisposition.Relay
                : StunDisposition.PassThrough;

    /// <summary>
    /// Starts the capture loops. Opens a WinDivert network handle for the IPv4
    /// UDP 53 filter (plus UDP 3478 STUN when <see cref="DnsSettings.RelayStun"/>)
    /// and a second handle for the IPv6 equivalent, so DNS over v6 transport is
    /// relayed too. The relay is established eagerly, not lazily, so a proxy
    /// without UDP support is reported at START.
    /// </summary>
    public void Start()
    {
        if (_isRunning)
            return;

        // Resolver override: an IP literal relayed queries are sent to instead
        // of each query's own server (keeps the ISP resolver out of the path).
        // Both families are accepted — an IPv4 query can be sent to a v4
        // resolver and a v6 query to a v6 one through the same association.
        // Null = transparent.
        _resolverOverride = null;
        _resolverOverrideV6 = null;
        if (!string.IsNullOrEmpty(_dns.ResolverOverride))
        {
            if (!IPAddress.TryParse(_dns.ResolverOverride, out var overrideIp) ||
                IPAddress.IsLoopback(overrideIp))
            {
                throw new InvalidOperationException(
                    $"DNS resolver override '{_dns.ResolverOverride}' is not a valid IP address.");
            }
            if (overrideIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                _resolverOverrideV6 = overrideIp;
            else
                _resolverOverride = overrideIp;
        }

        WinDivertLibrary.EnsureRegistered();

        // Each leg is independent: blocking WebRTC alone must not start
        // intercepting DNS, and relaying STUN alone must not either. The proxy
        // resolver override is only meaningful with the DNS leg on.
        var dnsLeg = _dns.Enabled;

        // WHY STUN BLOCKING IS NOT A LEG HERE ANY MORE:
        // <see cref="StunBlocker"/> owns blocking, and it matches by CONTENT on
        // any port. This ferry matched by PORT, which is why blocking appeared
        // to work while leaking: a WebRTC server may listen anywhere (the port
        // rides in the STUN server URI), and the leak test uses a non-standard
        // one, so those datagrams never reached this handle at all.
        //
        // If both handles captured STUN, ONE packet would match two diverting
        // handles — which is a race over who re-injects it, not redundancy. The
        // ferry therefore captures STUN only when it is relaying it.
        var stunLeg = _dns.RelayStun && !_dns.BlockWebRtc;

        if (!dnsLeg && _resolverOverride != null && !string.IsNullOrEmpty(_dns.ResolverOverride))
            Trace("DNS relay is off — the resolver override is not in effect.");

        // Outbound-only capture ⇒ injected (inbound) replies can never loop.
        var filter = BuildFilter(dnsLeg, stunLeg);

        _captureHandle = WinDivertNative.WinDivertOpen(
            filter, WinDivertLayer.Network, 0, 0);
        if (_captureHandle == IntPtr.Zero || _captureHandle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"WinDivertOpen failed for the DNS capture: error {err}. " +
                "Check that the application is running with administrator privileges.");
        }

        TuneQueue(_captureHandle);

        // ── IPv6 twin handle: DNS over v6 transport would otherwise bypass the
        //    relay entirely (the v4 filter cannot see it). Failing to open it
        //    is NOT fatal — a v4-only system legitimately has no v6 stack —
        //    but it is always traced, never silent. ──
        _captureHandleV6 = WinDivertNative.WinDivertOpen(
            BuildFilterV6(dnsLeg, stunLeg), WinDivertLayer.Network, 0, 0);
        if (_captureHandleV6 == IntPtr.Zero || _captureHandleV6 == new IntPtr(-1))
        {
            var v6err = Marshal.GetLastWin32Error();
            _captureHandleV6 = IntPtr.Zero;
            Trace($"IPv6 capture unavailable (WinDivertOpen error {v6err}) — " +
                  (stunLeg
                      ? (dnsLeg ? "DNS AND STUN" : "STUN") +
                        " over IPv6 cannot be handled on this system. Browsers prefer " +
                        "IPv6 for STUN, so this is a real leak path, not a cosmetic gap."
                      : "DNS over IPv6 transport cannot be relayed on this system."));
        }
        else
        {
            TuneQueue(_captureHandleV6);
        }

        _isRunning = true;
        _cts = new CancellationTokenSource();
        _captureLoop = Task.Run(() => CaptureLoopAsync(_captureHandle, false, _cts.Token));
        if (_captureHandleV6 != IntPtr.Zero)
            _captureLoopV6 = Task.Run(() => CaptureLoopAsync(_captureHandleV6, true, _cts.Token));

        // ── Flush the Windows resolver cache: names resolved BEFORE this point
        //    were answered by the direct path and would be served from the
        //    cache without any query to intercept. Flushing forces the next
        //    lookup to go through the relay. Only meaningful with the DNS leg
        //    on — flushing with only WebRTC blocking would discard the cache
        //    for no benefit. ──
        if (dnsLeg)
        {
            Trace(DnsCache.Flush()
                ? "Windows DNS cache flushed — pre-START answers cannot bypass the relay."
                : "Could not flush the Windows DNS cache — pre-START answers may be served from cache.");
        }

        // ── The startup line states EXACTLY which legs are active. The
        //    "STUN checkbox did nothing" reports all trace back to this line
        //    saying "+ STUN" while no STUN port was actually captured — a
        //    single unambiguous sentence removes that whole class of confusion.
        Trace(
            $"DNS/STUN ferry started — " +
            $"DNS relay: {(dnsLeg ? "ON (UDP 53, both families; TCP/53 via the TCP ferry)" : "off")}; " +
            $"STUN relay: {(_dns.RelayStun && !_dns.BlockWebRtc ? $"ON (ports {string.Join("/", StunPorts)}, both families)" : "off")}; " +
            $"WebRTC block: {(_dns.BlockWebRtc ? $"ON (dropping those ports — browser video calls will NOT work)" : "off")}");

        // ── EAGER relay probe: establish the UDP ASSOCIATE NOW (not lazily on
        //    the first query) so a proxy without UDP support is reported at
        //    START, not discovered in silence later. Retried in the background
        //    every 15 s until it succeeds.
        //
        //    Only when something actually NEEDS the association. Blocking
        //    WebRTC is a pure local drop — no proxy involvement — so probing
        //    for it would report a spurious relay failure on a proxy with no
        //    UDP support, which is unrelated to whether blocking works. ──
        if (dnsLeg || _dns.RelayStun)
        {
            _relayStatusText = "Probing…";
            Trace(_resolverOverride is not null || _resolverOverrideV6 is not null
                ? $"resolver override '{(_resolverOverride?.ToString() ?? _resolverOverrideV6?.ToString())}' — probing the relay…"
                : "transparent DNS (each app's own resolver) — probing the relay…");
            _ = Task.Run(() => ProbeRelayUntilRunningAsync(_cts.Token));
        }
        else
        {
            // Blocking-only mode: the relay is never used, so say so rather
            // than leaving the UI showing "Not started" as if something failed.
            _relayStatusText = "Not used (WebRTC blocking only)";
            Trace("No relay needed — WebRTC blocking drops STUN locally and never contacts the proxy.");
        }
    }

    /// <summary>Queue tuning shared by both capture handles.</summary>
    private static void TuneQueue(IntPtr handle)
    {
        WinDivertNative.WinDivertSetParam(handle, WinDivertNative.Params.QueueLength, 8192);
        WinDivertNative.WinDivertSetParam(handle, WinDivertNative.Params.QueueTime, 2000);
        WinDivertNative.WinDivertSetParam(handle, WinDivertNative.Params.QueueSize, 4194304);
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
        try { if (_captureLoopV6 is not null) await _captureLoopV6.ConfigureAwait(false); } catch { }
        WinDivertNative.WinDivertClose(_captureHandle);
        _captureHandle = IntPtr.Zero;
        if (_captureHandleV6 != IntPtr.Zero)
        {
            WinDivertNative.WinDivertClose(_captureHandleV6);
            _captureHandleV6 = IntPtr.Zero;
        }

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

        // Leave the system resolving normally again (the proxy leg is gone). Only
        // with the DNS leg on: in a blocking-only session nothing was ever
        // intercepted, so there is no cache state to undo.
        if (_dns.Enabled)
            DnsCache.Flush();
        Trace("DNS/STUN ferry stopped.");
    }

    private async Task CaptureLoopAsync(IntPtr handle, bool isV6, CancellationToken ct)
    {
        var buffer = new byte[65535];
        // v4 minimum is IP(20)+UDP(8); v6 is 40+8.
        var minimum = isV6 ? UdpPacketParser.Ipv6HeaderLength + 8 : 28;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                uint readLen = 0;
                var addr = new WinDivertAddress();
                if (!WinDivertNative.WinDivertRecv(handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break; // handle closed

                // FAIL-CLOSED: a captured packet too short to be a DNS query is
                // DROPPED, never re-injected — an intercepted query must never
                // silently continue on the direct path.
                if (readLen < minimum)
                    continue;

                await HandleDatagramAsync(handle, isV6, buffer, readLen, addr, ct).ConfigureAwait(false);
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

    private async Task HandleDatagramAsync(
        IntPtr handle, bool isV6, byte[] buffer, uint readLen, WinDivertAddress addr, CancellationToken ct)
    {
        Interlocked.Increment(ref _queriesCaptured);

        // ── Parse the IP + UDP headers (E8-b ParseUdp, typed; v4 or v6) ──
        //    FAIL-CLOSED: an unparsable captured datagram is DROPPED, never
        //    re-injected. Re-injecting would put the query back on the direct
        //    path — exactly the leak this feature exists to prevent.
        IPAddress srcIp, dstIp;
        ushort srcPort, dstPort;
        int ipHeaderLength;
        if (isV6)
        {
            if (!UdpPacketParser.TryParseUdp6(buffer, readLen, out srcIp, out dstIp, out srcPort, out dstPort))
            {
                Interlocked.Increment(ref _queriesDroppedUnparsable);
                Trace("IPv6 DNS datagram could not be parsed — dropped (fail-closed).");
                return;
            }
            ipHeaderLength = UdpPacketParser.Ipv6HeaderLength;
        }
        else if (!UdpPacketParser.TryParse(buffer, readLen,
                     out srcIp, out dstIp, out srcPort, out dstPort, out ipHeaderLength))
        {
            Interlocked.Increment(ref _queriesDroppedUnparsable);
            Trace("IPv4 DNS datagram could not be parsed — dropped (fail-closed).");
            return;
        }

        // ── Attribute the owning process (E8-a: GetExtendedUdpTable) —
        //    DIAGNOSTIC ONLY. System DNS arrives from svchost (dnscache),
        //    never from the selecting app, so it must not gate interception. ──
        var pid = isV6
            ? UdpProcessTable.ResolveOwnerPidV6(srcIp, srcPort)
            : UdpProcessTable.ResolveOwnerPid(srcIp, srcPort);
        var (name, _) = ResolveProcessIdentity(pid);

        var dnsPayload = buffer.AsSpan(ipHeaderLength + 8, (int)readLen - ipHeaderLength - 8).ToArray();

        // Relay target. DNS (port 53) honours the resolver override so the
        // user's ISP resolver stays out of the path (leak tests then show the
        // public resolver's egress, not the ISP).
        //
        // CRITICAL: the override applies to DNS ONLY. A STUN datagram must go
        // to the server the client addressed — relaying STUN to 1.1.1.1:19302
        // instead of stun.l.google.com:19302 can never correlate a reply, so
        // the injection times out and WebRTC silently keeps its direct STUN
        // (i.e. the real IP). That bug is exactly why relaying the override
        // unconditionally broke the STUN feature.
        var isDns = dstPort == 53;

        // ── WebRTC BLOCK: drop STUN here, before ANY relay work. ──
        // Blocking is the reliable WebRTC protection — relaying depends on the
        // proxy supporting UDP ASSOCIATE and on the port being in the list,
        // whereas dropping removes the only mechanism WebRTC has for learning
        // the public address.
        //
        // Not re-injecting IS the block: a captured packet only continues if
        // this process sends it onward. There is deliberately no fallback path
        // and no error branch — a STUN datagram that failed to be dropped would
        // be exactly the leak the user asked to prevent, so it must never reach
        // the relay or the wire.
        //
        // The user-visible cost is stated in the UI and docs: browser video
        // calls stop working.
        if (!isDns)
        {
            switch (DecideStunDisposition(_dns.BlockWebRtc, _dns.RelayStun))
            {
                case StunDisposition.Drop:
                    Interlocked.Increment(ref _stunCaptured);
                    Interlocked.Increment(ref _webRtcBlocked);
                    Trace($"BLOCKED STUN {srcIp}:{srcPort} -> {dstIp}:{dstPort} ({(isV6 ? "v6" : "v4")}) " +
                          $"pid={pid} name={name ?? "?"} ({dnsPayload.Length} bytes) — dropped; " +
                          "WebRTC cannot learn your public address from this.");
                    return;

                case StunDisposition.PassThrough:
                    // Neither option on: re-inject unchanged so the datagram
                    // behaves exactly as if this handle did not exist.
                    var passthroughAddr = addr;
                    WinDivertNative.WinDivertSend(
                        handle, buffer, readLen, IntPtr.Zero, ref passthroughAddr);
                    return;
            }
        }

        var relayTarget = ResolveRelayTarget(
            dstIp, dstPort, isV6 ? _resolverOverrideV6 : _resolverOverride);

        // STUN is counted separately from DNS: they are different features with
        // different failure modes, and one number for both would hide a working
        // DNS relay behind a broken STUN relay (exactly the confusion when a
        // leak test still reports the real address).
        if (!isDns)
            Interlocked.Increment(ref _stunCaptured);

        // Correlation key: a DNS reply echoes the transaction ID in the FIRST
        // TWO bytes; a STUN reply echoes its 12-byte transaction ID in the
        // first 12 (the message type changes, so 2 bytes do not correlate).
        var correlationBytes = isDns ? 2 : 12;

        // The trace names the ORIGINAL destination and the ACTUAL relay target. Both
        // are needed to diagnose: "relaying to 1.1.1.1:53" alone hides which
        // app asked and which resolver the app itself wanted (an ISP address
        // there is the signal that the override is not taking effect).
        //
        // STUN lines are prefixed STUN so they are greppable on their own — the
        // user reporting "the STUN checkbox changed nothing" could not tell
        // "STUN never captured" from "STUN relayed fine", because both looked
        // like an ordinary `query` line in a wall of DNS.
        Trace(isDns
            ? $"query {srcIp}:{srcPort} -> {dstIp}:{dstPort} pid={pid} name={name ?? "?"} " +
              $"({dnsPayload.Length} bytes) — relaying via proxy to {relayTarget}:{dstPort}" +
              (!Equals(relayTarget, dstIp)
                  ? $" (resolver override: {dstIp} -> {relayTarget})"
                  : "")
            : $"STUN {srcIp}:{srcPort} -> {dstIp}:{dstPort} ({(isV6 ? "v6" : "v4")}) " +
              $"pid={pid} name={name ?? "?"} ({dnsPayload.Length} bytes) — " +
              $"relaying via proxy to {relayTarget}:{dstPort} (original destination kept)");

        // ── Relay through the proxy (fail-closed: drop on failure) ──
        try
        {
            var relay = await EnsureRelayAsync(ct).ConfigureAwait(false);
            var result = await relay
                .RelayAsync(dnsPayload, relayTarget, dstPort, RelayTimeout, ct, correlationBytes)
                .ConfigureAwait(false);

            if (isDns)
                Interlocked.Increment(ref _queriesRelayed);
            else
                Interlocked.Increment(ref _stunRelayed);

            // ── Re-inject the reply inbound, spoofed from the ORIGINAL server
            //    the client addressed (its socket expects that source — even
            //    when the reply actually came from the override resolver;
            //    E8-b InjectUdp: Outbound cleared, IfIdx/SubIfIdx preserved,
            //    helper checksums, Impostor=0). ──
            var packet = isV6
                ? UdpPacketParser.BuildUdp6Packet(dstIp, srcIp, (ushort)dstPort, srcPort, result.DnsPayload)
                : UdpPacketParser.BuildUdpPacket(dstIp, srcIp, (ushort)dstPort, srcPort, result.DnsPayload);
            var replyAddr = addr;
            replyAddr.LayerEventFlags &= ~(1uL << 17); // clear Outbound → inbound
            ApplyGameModeDscp(packet, isV6);
            WinDivertNative.WinDivertHelperCalcChecksums(packet, (uint)packet.Length, ref replyAddr, 0);
            if (WinDivertNative.WinDivertSend(handle, packet, (uint)packet.Length, IntPtr.Zero, ref replyAddr))
            {
                Interlocked.Increment(ref _repliesInjected);
                if (!isDns)
                    Interlocked.Increment(ref _stunInjected);
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
            if (!isDns)
                Interlocked.Increment(ref _stunFailures);
            Trace($"query relay cancelled (shutdown) — dropped, client will retry.");
        }
        catch (Exception ex)
        {
            // Fail-closed: never re-inject the query (that would leak it) — the
            // client's resolver retries shortly.
            Interlocked.Increment(ref _relayFailures);
            if (!isDns)
            {
                Interlocked.Increment(ref _stunFailures);
                // The STUN case is the one that matters for a WebRTC leak test:
                // a dropped STUN request makes WebRTC fall back to whatever it
                // can reach directly, so this is a real leak path and must be
                // stated as such rather than reported as a plain retry.
                Trace($"STUN relay FAILED ({ex.Message}) — dropped (fail-closed). " +
                      "WebRTC will fall back to a direct STUN candidate, which reveals the real address.");
            }
            Trace($"query relay FAILED ({ex.Message}) — dropped (fail-closed), client will retry.");
        }
    }

    /// <summary>
    /// Game Mode packet tuning: DSCP EF (Expedited Forwarding) on the packets
    /// we inject toward the client — ECN bits preserved. Must run BEFORE the
    /// checksum helper (the IPv4 header checksum covers the TOS byte; the IPv6
    /// traffic-class field is covered by no checksum, but the helper recomputes
    /// the UDP checksum over the pseudo-header either way).
    /// <para>
    /// v4: DSCP lives in the TOS byte at offset 1. v6: the traffic class
    /// SPANS the low nibble of byte 0 and the high nibble of byte 1.
    /// </para>
    /// </summary>
    private void ApplyGameModeDscp(byte[] packet, bool isV6)
    {
        if (!_gameMode || packet.Length < 2)
            return;
        const byte dscpEf = 46 << 2; // 0xB8
        if (isV6)
        {
            packet[0] = (byte)((packet[0] & 0xF0) | (dscpEf >> 4));
            packet[1] = (byte)((packet[1] & 0x0F) | (dscpEf << 4));
        }
        else
        {
            packet[1] = (byte)((packet[1] & 0x03) | dscpEf);
        }
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
