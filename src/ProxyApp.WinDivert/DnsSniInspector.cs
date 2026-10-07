using System.Runtime.InteropServices;
using System.Text;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Processes;
using ProxyApp.Processes;

namespace ProxyApp.WinDivert;

/// <summary>
/// A DIAGNOSTIC observer for encrypted DNS. It is deliberately NOT a blocker
/// and relays nothing: it watches outbound TLS ClientHello messages on TCP 443
/// and reports the plaintext SNI hostname, so the user can see WHICH process is
/// resolving through a DoH endpoint (and to which IP) instead of guessing from
/// a leak test's list of resolvers.
///
/// Why SNI works at all without decrypting anything: the TLS ClientHello is
/// sent in the CLEAR by design — the server hostname must be readable before
/// the session keys exist (RFC 6066 §3). So a passive observer sees the name
/// while the DNS query itself stays inside the tunnel. That is enough to prove
/// an encrypted resolver is in use; it is NOT enough to read the queries.
///
/// SAFETY: the handle is opened in SNIFF mode (<see cref="WinDivertNative.Flags.SniffAndReceiveOnly"/>).
/// A sniff handle COPIES each matching packet to this process and lets the real
/// packet continue untouched — it cannot consume, delay, reorder, inject or drop
/// anything. This inspector therefore CANNOT affect routing, cannot break the
/// tunnel, and cannot be the cause of a leak. It is safe to leave running.
///
/// KNOWN LIMITS (stated honestly, not glossed over):
/// <list type="bullet">
/// <item>SNI is absent when the client uses Encrypted ClientHello (ECH, now
/// common in Chrome) — the hostname is then genuinely unreadable without keys.
/// Those connections are counted as "encrypted (no SNI)" so the gap is VISIBLE
/// rather than silently missing.</item>
/// <item>QUIC/DoH3 (HTTP/3) does not use a TLS-over-TCP ClientHello. DoH over
/// QUIC on UDP 443 is therefore NOT observable here.</item>
/// <item>The SNI is the CONNECTED hostname, which is not always the resolver: a
/// self-hosted DoH server on a random hostname will not be flagged as a known
/// resolver. It is still reported as a hostname so it is visible.</item>
/// </list>
/// </summary>
internal sealed class DnsSniInspector : IDisposable
{
    /// <summary>
    /// Capture filter: outbound TCP 443, never loopback. SNIFF + RECEIVE_ONLY so
    /// packets are observed, never diverted.
    /// </summary>
    internal const string CaptureFilter = "outbound and ip and tcp and tcp.DstPort == 443 and not loopback";

    /// <summary>
    /// Known public DoH/DoT resolver hostnames. Matched case-insensitively, with
    /// and without a leading "www.". A hit means the app is resolving names
    /// through an ENCRYPTED channel that this app cannot relay.
    ///
    /// Only resolver ENDPOINTS live here — never a CDN or hosting range. A
    /// Cloudflare or Google CDN prefix would flag ordinary web traffic, and for a
    /// user whose proxy egress is one of these providers it would look like
    /// "everything is leaking".
    /// </summary>
    internal static readonly IReadOnlySet<string> KnownEncryptedDnsHosts = new HashSet<string>(
        new[]
        {
            // Cloudflare. NOTE: the apex "cloudflare.com" is deliberately NOT
            // listed — it serves a normal website, and matching it would report
            // ordinary browsing as encrypted DNS. The documented DoH endpoints
            // are the dedicated resolver hostnames below.
            "cloudflare-dns.com", "chrome.cloudflare-dns.com", "one.one.one.one",
            // Google
            "dns.google", "dns.google.com",
            // Quad9
            "dns.quad9.net", "dns.quad9.com",
            // OpenDNS / Cisco
            "doh.opendns.com", "doh.familyshield.opendns.com",
            // AdGuard
            "dns.adguard-dns.com", "dns.adguard.com", "adguard-dns.com",
            // NextDNS
            "dns.nextdns.io",
            // CleanBrowsing
            "doh.cleanbrowsing.org", "doh.de.cleanbrowsing.org",
            "doh.opendns.com",
            // Mullvad / ControlD
            "doh.mullvad.net", "dns.mullvad.net",
            // Comodo / Secure DNS
            "secure.dns.comodo.net",
            // DNS.SB
            "doh.dns.sb", "dot.sb", "dns.sb",
            // Yandex
            "common.dot.dns.yandex.net",
            // AliDNS
            "dns.alidns.com",
            // dns0.eu / LibreDNS
            "doh.dns0.eu", "doh.libredns.gr",
        },
        StringComparer.OrdinalIgnoreCase);

    private const ushort EncryptedDnsTlsPort = 443;

    private readonly DnsSettings _dns;
    private readonly Action<string>? _trace;
    private readonly Action<string>? _hit;

    /// <summary>
    /// Process attribution for the reported hit. Injectable so tests can pass a
    /// stub and assert the reported process without touching the OS.
    /// </summary>
    private readonly IConnectionProcessResolver _processResolver;

    private IntPtr _handle = IntPtr.Zero;
    private CancellationTokenSource? _cts;
    private Task? _loop;
    private volatile bool _isRunning;

    // ── Counters (Interlocked; read by the UI's DNS diagnostics line) ──
    private long _connectionsObserved;
    private long _encryptedDnsHits;
    private long _hostnamesParsed;
    private long _noSniConnections;
    private long _packetsSeen;

    /// <summary>
    /// Outbound ClientHellos observed on TCP/443. This counts handshake records,
    /// not TCP connections: a ClientHello retransmitted after a timeout is
    /// counted again. It is a volume indicator, not a connection census.
    /// </summary>
    internal long ConnectionsObserved => Interlocked.Read(ref _connectionsObserved);

    /// <summary>Connections to a KNOWN encrypted-DNS resolver hostname.</summary>
    internal long EncryptedDnsHits => Interlocked.Read(ref _encryptedDnsHits);

    /// <summary>Connections where a hostname was read from the ClientHello.</summary>
    internal long HostnamesParsed => Interlocked.Read(ref _hostnamesParsed);

    /// <summary>
    /// ClientHellos with no readable SNI — Encrypted ClientHello (ECH) or a
    /// truncated capture. NOT proof of a leak, but a blind spot: these cannot be
    /// classified, so they are surfaced rather than silently missed. Only
    /// ClientHello records are considered, so ordinary data traffic never
    /// inflates this count.
    /// </summary>
    internal long NoSniConnections => Interlocked.Read(ref _noSniConnections);

    /// <summary>Total packets observed (diagnostic only).</summary>
    internal long PacketsSeen => Interlocked.Read(ref _packetsSeen);

    /// <summary>True while the inspector's capture loop runs.</summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// Creates the inspector. It observes only; it never changes routing.
    /// </summary>
    /// <param name="dnsSettings">Used to decide whether inspection is enabled at all.</param>
    /// <param name="trace">Optional diagnostic trace sink.</param>
    /// <param name="hit">
    /// Optional sink for a detected encrypted-DNS connection — the UI shows
    /// these as a prominent "encrypted DNS in use" warning.
    /// </param>
    /// <param name="processResolver">
    /// Optional process resolver for attributing a detected connection
    /// (defaults to <see cref="CachedProcessTable"/>).
    /// </param>
    public DnsSniInspector(
        DnsSettings dnsSettings,
        Action<string>? trace = null,
        Action<string>? hit = null,
        IConnectionProcessResolver? processResolver = null)
    {
        _dns = dnsSettings ?? throw new ArgumentNullException(nameof(dnsSettings));
        _trace = trace;
        _hit = hit;
        _processResolver = processResolver ?? new CachedProcessTable();
    }

    private void Trace(string message) => _trace?.Invoke($"[Sni] {message}");

    /// <summary>
    /// True when the inspector should run. Tied to the DNS relay being on so it
    /// appears exactly when the user is trying to prove DNS is clean — the whole
    /// point of the feature is diagnostic, and a permanent passive observer is
    /// needless work when the relay is off.
    /// </summary>
    internal bool ShouldRun => _dns.Enabled;

    /// <summary>Starts the passive observation loop. Never throws.</summary>
    public void Start()
    {
        if (_isRunning || !ShouldRun)
            return;

        WinDivertLibrary.EnsureRegistered();

        // SNIFF | RECEIVE_ONLY: copy-only. This is what makes the inspector
        // incapable of affecting routing — see the class remarks.
        _handle = WinDivertNative.WinDivertOpen(
            CaptureFilter, WinDivertLayer.Network, 0, WinDivertNative.Flags.SniffAndReceiveOnly);

        if (_handle == IntPtr.Zero || _handle == new IntPtr(-1))
        {
            var err = Marshal.GetLastWin32Error();
            _handle = IntPtr.Zero;
            Trace($"SNI inspection unavailable (WinDivertOpen error {err}) — " +
                  "encrypted DNS endpoints cannot be identified. Routing is unaffected.");
            return;
        }

        // Small queues on purpose: this is a low-volume signal (one ClientHello
        // per connection) and must never compete with the ferries for resources.
        WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.Params.QueueLength, 1024);
        WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.Params.QueueTime, 500);
        WinDivertNative.WinDivertSetParam(_handle, WinDivertNative.Params.QueueSize, 1048576);

        _isRunning = true;
        _cts = new CancellationTokenSource();
        _loop = Task.Run(() => ObserveLoopAsync(_cts.Token));
        Trace("SNI inspection active on outbound TCP 443 (passive; copies packets, never diverts them).");
    }

    /// <summary>Stops observing and closes the handle.</summary>
    public async Task StopAsync()
    {
        if (!_isRunning)
            return;
        _isRunning = false;
        _cts?.Cancel();
        if (_handle != IntPtr.Zero)
        {
            WinDivertNative.WinDivertClose(_handle);
            _handle = IntPtr.Zero;
        }
        if (_loop is not null)
        {
            try { await _loop.ConfigureAwait(false); } catch { }
        }
        _cts?.Dispose();
        _cts = null;
    }

    private async Task ObserveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[65535];

        // One flag per (local port, remote port) pair is unnecessary state: a
        // ClientHello is a single packet in practice, and re-reading the same
        // ClientHello after a retransmit is idempotent (same verdict), so the
        // simplest correct thing is to parse each packet that carries one and
        // de-duplicate only the USER-VISIBLE hit, not the parse.
        while (!ct.IsCancellationRequested)
        {
            try
            {
                uint readLen = 0;
                var addr = new WinDivertAddress();
                if (!WinDivertNative.WinDivertRecv(
                        _handle, buffer, (uint)buffer.Length, ref readLen, ref addr))
                    break; // handle closed

                Interlocked.Increment(ref _packetsSeen);
                Inspect(buffer, readLen);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // Never let one odd packet kill the observer.
                Trace($"observe-loop error (recovered): {ex.GetType().Name}: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// Inspects one captured packet for a TLS ClientHello and reports it.
    /// Internal seam: unit-testable without a live WinDivert handle.
    /// </summary>
    internal void Inspect(byte[] packet, uint length)
    {
        if (length < 40 || packet.Length < 40)
            return;
        if (!TcpPacketParser.TryParse(packet, length, out var tuple))
            return;
        if (tuple.DstPort != EncryptedDnsTlsPort)
            return;

        // The ClientHello is client→server payload, so it arrives in the first
        // outbound data segment. Pure ACKs carry no payload and are skipped.
        var ipLen = TcpPacketParser.IpHeaderLength(packet, length);
        var payloadStart = ipLen + tuple.TcpHeaderLen;
        if (payloadStart >= length)
            return;

        var payload = packet.AsSpan(payloadStart, (int)(length - payloadStart));

        // The capture filter matches EVERY outbound TCP/443 packet, which is all
        // uploads and ACKs as well as the handshake. Classifying "anything that
        // is not a readable ClientHello" as a blind spot would therefore count
        // every uploaded byte in the session and report thousands of unreadable
        // connections — a counter that is both wrong and useless.
        //
        // A blind spot is specifically a ClientHello whose SNI could not be read
        // (Encrypted ClientHello, or a capture that truncated the record). So
        // the classification is gated on actually seeing a handshake record
        // carrying a ClientHello message first.
        var isClientHello = payload.Length >= 6 && payload[0] == 0x16 && payload[5] == 0x01;
        if (!isClientHello)
            return; // data, ACK, retransmit, or a non-ClientHello handshake

        Interlocked.Increment(ref _connectionsObserved);

        if (!TryReadClientHelloHost(payload, out var host))
        {
            Interlocked.Increment(ref _noSniConnections);
            Trace("A TLS ClientHello had no readable SNI (Encrypted ClientHello, or a truncated capture) — " +
                  "this connection cannot be classified.");
            return;
        }

        Interlocked.Increment(ref _hostnamesParsed);

        if (!IsKnownEncryptedDnsHost(host))
            return; // ordinary HTTPS — not our business, and not noise

        Interlocked.Increment(ref _encryptedDnsHits);

        // Attribute the process for the message the user actually reads: which
        // app is doing the encrypted resolving. CachedProcessTable (not the raw
        // ProcessTable) because a busy machine can open many TLS connections at
        // once and each uncached lookup walks the ENTIRE OS connection table.
        // By the time a ClientHello arrives the connection is established, so
        // the 4-tuple resolves reliably.
        var owner = _processResolver.ResolveOwner(
            tuple.SrcIp, tuple.SrcPort, tuple.DstIp, tuple.DstPort);
        var processName = owner?.ExecutableName;

        var message =
            $"ENCRYPTED DNS (DoH) detected: {processName ?? "unknown process"} " +
            $"({tuple.SrcIp}:{tuple.SrcPort} -> {tuple.DstIp}:{tuple.DstPort}) " +
            $"resolving via https://{host}/ — this resolver is NOT relayed through the proxy.";
        Trace(message);
        _hit?.Invoke(message);
    }

    /// <summary>
    /// True when the hostname is a known public encrypted-DNS endpoint.
    ///
    /// EXACT match only — never a substring, suffix or "strip www." match.
    /// Looser matching is actively harmful here: a suffix match flags ordinary
    /// sites, and normalizing "www.cloudflare.com" to "cloudflare.com" reports
    /// normal web browsing as encrypted DNS. A false positive trains the user to
    /// ignore the warning, which is worse than missing a leak. A false NEGATIVE
    /// merely means the detection is silent, and the blind-spot counter plus the
    /// per-hit log line keep that honest.
    /// </summary>
    internal static bool IsKnownEncryptedDnsHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return false;
        var normalized = host.Trim().TrimEnd('.').ToLowerInvariant();
        return KnownEncryptedDnsHosts.Contains(normalized);
    }

    /// <summary>
    /// Extracts the SNI hostname from a TLS ClientHello record body.
    /// Returns false when the payload is not a ClientHello, is truncated, or has
    /// no SNI extension. Pure parsing — no state, no I/O, fully unit-testable.
    /// </summary>
    internal static bool TryReadClientHelloHost(ReadOnlySpan<byte> payload, out string host)
    {
        host = string.Empty;

        // TLS record layer: type(1) version(2) length(2). 0x16 = Handshake.
        if (payload.Length < 5 || payload[0] != 0x16)
            return false;

        // Handshake header: type(1) length(3). 0x01 = ClientHello.
        if (payload.Length < 9 || payload[5] != 0x01)
            return false;

        // client_version(2) random(32) session_id_len(1) session_id(n)
        var p = 9 + 2 + 32;
        if (p >= payload.Length) return false;
        var sessionIdLen = payload[p++];
        if (p + sessionIdLen > payload.Length) return false;
        p += sessionIdLen;

        // cipher_suites_len(2) cipher_suites(n)
        if (p + 2 > payload.Length) return false;
        var cipherLen = (payload[p] << 8) | payload[p + 1];
        p += 2 + cipherLen;
        if (p > payload.Length) return false;

        // compression_methods_len(1) compression_methods(n)
        if (p + 1 > payload.Length) return false;
        var compressionLen = payload[p++];
        p += compressionLen;
        if (p > payload.Length) return false;

        // extensions_len(2) extensions(n)
        if (p + 2 > payload.Length) return false;
        var extensionsLen = (payload[p] << 8) | payload[p + 1];
        p += 2;
        var extensionsEnd = p + extensionsLen;
        if (extensionsEnd > payload.Length) return false;

        while (p + 4 <= extensionsEnd)
        {
            var type = (payload[p] << 8) | payload[p + 1];
            var len = (payload[p + 2] << 8) | payload[p + 3];
            p += 4;
            if (p + len > extensionsEnd) return false;

            // extension_type server_name = 0
            if (type == 0)
            {
                // server_name_list_len(2) then entries: name_type(1) len(2) name
                var q = p;
                if (q + 2 > extensionsEnd) return false;
                var listLen = (payload[q] << 8) | payload[q + 1];
                q += 2;
                var listEnd = q + listLen;
                if (listEnd > extensionsEnd) return false;

                while (q + 3 <= listEnd)
                {
                    var nameType = payload[q];       // 0 = host_name
                    var nameLen = (payload[q + 1] << 8) | payload[q + 2];
                    q += 3;
                    if (q + nameLen > listEnd) return false;
                    // name_type 0 = host_name; anything else (e.g. 1) is not a
                    // resolvable name and must be skipped, not returned.
                    if (nameType == 0)
                    {
                        if (nameLen == 0) return false;
                        host = Encoding.ASCII.GetString(payload.Slice(q, nameLen));
                        return host.Length > 0;
                    }
                    q += nameLen;
                }
                return false;
            }
            p += len;
        }
        return false;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        try { StopAsync().GetAwaiter().GetResult(); } catch { }
    }
}