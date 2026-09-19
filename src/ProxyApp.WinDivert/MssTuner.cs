using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ProxyApp.WinDivert;

/// <summary>
/// Automatic-MTU tuner (port of TunnelX's TunnelPerformanceTuner to the ferry
/// architecture): derives a safe upper bound for the TCP MSS the ferry
/// advertises in its SYN-ACKs.
///
/// Two-step probe, same as TunnelX:
/// 1. The physical NIC's MTU (first Up, non-loopback, non-tunnel adapter with
///    an IPv4 gateway; sane-MTU range checked) gives the base candidate.
/// 2. Descending DF (don't-fragment) ping probes — the packet equivalent of
///    <c>ping -f -l</c> — confirm the largest size that survives the path;
///    blocked/unreachable ICMP degrades gracefully to the interface-derived
///    value (probes only ever LOWER the result, never raise it).
///
/// MSS = MTU − 40 (IPv4 header 20 + TCP header 20), clamped to
/// [<see cref="MinMss"/>, <see cref="MaxMss"/>]. In this ferry architecture
/// the effect is intentionally modest (the client leg is machine-local and
/// the upstream leg is OS-managed) — the tuning exists for parity with
/// TunnelX and lets Game Mode's tighter clamp compose with it.
/// </summary>
public static class MssTuner
{
    public const ushort MinMss = 536;
    public const ushort MaxMss = 1460;

    /// <summary>MSS cap Game Mode enforces (TunnelX's clamped value).</summary>
    public const ushort GameModeMss = 1360;

    /// <summary>How far below the base candidate probes descend, per step.</summary>
    public const int ProbeStep = 20;

    /// <summary>Maximum number of DF-ping probes per tune (bounded connect-time cost).</summary>
    public const int MaxProbeSteps = 5;

    /// <summary>Per-probe timeout (TunnelX uses 700 ms too).</summary>
    public const int ProbeTimeoutMs = 700;

    /// <summary>Fallback NIC MTU when no sane adapter is found.</summary>
    public const int FallbackInterfaceMtu = 1500;

    /// <summary>
    /// Pure: the descending probe candidates for a base MTU (base, −20, −40,
    /// −60, −80) — at most <see cref="MaxProbeSteps"/>.
    /// </summary>
    public static IReadOnlyList<int> BuildProbeCandidates(int baseMtu)
    {
        var candidates = new List<int>();
        for (var i = 0; i < MaxProbeSteps; i++)
        {
            var mtu = baseMtu - i * ProbeStep;
            if (mtu < MinMss + 40)
                break;
            candidates.Add(mtu);
        }
        return candidates;
    }

    /// <summary>Pure: MSS for a path MTU (IPv4+TCP header overhead of 40 bytes).</summary>
    public static ushort MssFromMtu(int mtu) =>
        (ushort)Math.Clamp(mtu - 40, MinMss, MaxMss);

    /// <summary>
    /// Pure: the final advertised-MSS cap — the tuned MSS lowered by Game
    /// Mode's tighter clamp when enabled.
    /// </summary>
    public static ushort CombineWithGameMode(ushort tunedMss, bool gameMode) =>
        gameMode ? Math.Min(tunedMss, GameModeMss) : tunedMss;

    /// <summary>
    /// Reads the physical NIC's MTU (TunnelX logic): the first Up adapter that
    /// is not loopback/tunnel, has IPv4 enabled and an IPv4 gateway, ordered
    /// by interface index; its MTU is accepted only within 1300–9000.
    /// Returns <see cref="FallbackInterfaceMtu"/> when nothing qualifies.
    /// </summary>
    public static int GetPrimaryInterfaceMtu()
    {
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
                         .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback &&
                                     n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
                         .OrderBy(n => n.Id))
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;
                var ipProps = nic.GetIPProperties();
                if (ipProps?.GetIPv4Properties() is null)
                    continue;
                if (!ipProps.GatewayAddresses.Any(g => g.Address.AddressFamily == AddressFamily.InterNetwork))
                    continue;

                var mtu = ipProps.GetIPv4Properties().Mtu;
                if (mtu is >= 1300 and <= 9000)
                    return mtu;
            }
        }
        catch
        {
            // NIC enumeration is best-effort — the fallback below applies.
        }
        return FallbackInterfaceMtu;
    }

    /// <summary>
    /// Runs the two-step tune and returns the advertised-MSS cap. Never
    /// throws — any failure degrades to the interface-derived value.
    /// </summary>
    /// <param name="probeHost">A host/IP the DF probes target (the proxy's
    /// host is ideal — it is the path that matters); null skips probing.</param>
    public static async Task<ushort> TuneAsync(string? probeHost, CancellationToken ct = default)
    {
        var baseMtu = GetPrimaryInterfaceMtu();
        var candidates = BuildProbeCandidates(baseMtu);
        if (string.IsNullOrWhiteSpace(probeHost) || candidates.Count == 0)
            return MssFromMtu(baseMtu);

        foreach (var mtu in candidates)
        {
            var result = await ProbeAsync(probeHost, mtu, ct).ConfigureAwait(false);
            switch (result)
            {
                case MtuProbeResult.Success:
                    return MssFromMtu(mtu); // largest size that survived the path
                case MtuProbeResult.TimeoutOrFiltered:
                case MtuProbeResult.Unreachable:
                    // ICMP blocked / host unreachable: probing further only
                    // stalls the connect — stop at the interface-derived value
                    // (TunnelX behavior).
                    return MssFromMtu(baseMtu);
                case MtuProbeResult.TooBig:
                    continue; // try the next smaller candidate
            }
        }

        return MssFromMtu(candidates[^1]);
    }

    /// <summary>
    /// One DF ping probe: a ping with dontFragment=true and a payload sized so
    /// the whole IP packet equals the candidate MTU (payload = MTU − 28 for
    /// IPv4 + ICMP headers).
    /// </summary>
    private static async Task<MtuProbeResult> ProbeAsync(string host, int mtu, CancellationToken ct)
    {
        try
        {
            using var ping = new Ping();
            var payload = new byte[Math.Max(0, mtu - 28)];
            var options = new PingOptions(ttl: 64, dontFragment: true);
            var reply = await ping.SendPingAsync(host, ProbeTimeoutMs, payload, options).ConfigureAwait(false);
            return reply.Status switch
            {
                IPStatus.Success => MtuProbeResult.Success,
                IPStatus.PacketTooBig => MtuProbeResult.TooBig,
                IPStatus.TimedOut => MtuProbeResult.TimeoutOrFiltered,
                _ => MtuProbeResult.Unreachable
            };
        }
        catch
        {
            return MtuProbeResult.TimeoutOrFiltered;
        }
    }

    private enum MtuProbeResult
    {
        Success,
        TooBig,
        TimeoutOrFiltered,
        Unreachable
    }
}
