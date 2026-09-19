namespace ProxyApp.Core.Configuration;

/// <summary>
/// Tunnel-optimization toggles (Phase 12+): latency/performance tuning of the
/// packet ferries, ported from the TunnelX feature set where it maps onto a
/// SOCKS5-ferry architecture.
/// </summary>
public sealed class OptimizationSettings
{
    /// <summary>
    /// Whether the ferry's advertised TCP MSS is auto-tuned at START from the
    /// physical NIC MTU plus DF (don't-fragment) ping probes, instead of the
    /// fixed 1460 default. Prevents fragmentation stalls when the real path
    /// MTU is smaller. Default true.
    /// </summary>
    public bool AutoMtu { get; set; } = true;

    /// <summary>
    /// Game Mode: low-latency packet tuning — DSCP EF (Expedited Forwarding)
    /// marking on injected packets, advertised MSS clamped to 1360 (TunnelX's
    /// value), and EF TOS on the upstream relay sockets. Default false.
    /// </summary>
    public bool GameMode { get; set; }
}
