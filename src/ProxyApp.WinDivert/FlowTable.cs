using System.Collections.Concurrent;
using System.Net;

namespace ProxyApp.WinDivert;

/// <summary>
/// Thread-safe storage of active proxied flows, keyed by 4-tuple. Provides
/// insert, lookup, remove, and periodic expiry of idle flows.
/// </summary>
internal sealed class FlowTable
{
    private readonly ConcurrentDictionary<FlowKey, FlowState> _flows = new();

    /// <summary>Number of active flows.</summary>
    public int Count => _flows.Count;

    /// <summary>Returns true if a flow already exists for the given 4-tuple.</summary>
    public bool Contains(FlowKey key) => _flows.ContainsKey(key);

    /// <summary>Returns the flow for the key, or null if absent.</summary>
    public FlowState? Get(FlowKey key) => _flows.TryGetValue(key, out var flow) ? flow : null;

    /// <summary>Adds a flow, returning true if it was newly added.</summary>
    public bool TryAdd(FlowKey key, FlowState flow) => _flows.TryAdd(key, flow);

    /// <summary>Removes a flow, returning true if it existed.</summary>
    public bool TryRemove(FlowKey key, out FlowState? flow)
    {
        if (_flows.TryRemove(key, out var removed))
        {
            flow = removed;
            return true;
        }
        flow = null;
        return false;
    }

    /// <summary>Builds a <see cref="FlowKey"/> from a captured tuple.</summary>
    public static FlowKey KeyFrom(IPAddress clientIp, ushort clientPort, IPAddress serverIp, ushort serverPort)
        => new(clientIp, clientPort, serverIp, serverPort);

    /// <summary>
    /// Removes flows idle for longer than <paramref name="maxIdle"/>. Returns the
    /// number removed. The caller is responsible for disposing the removed flows.
    /// </summary>
    public List<FlowState> RemoveExpired(TimeSpan maxIdle)
    {
        var cutoff = DateTime.UtcNow - maxIdle;
        var expired = new List<FlowState>();
        foreach (var kv in _flows)
        {
            if (kv.Value.LastActivityUtc < cutoff && _flows.TryRemove(kv.Key, out var flow))
                expired.Add(flow);
        }
        return expired;
    }

    /// <summary>Removes all flows, returning them for disposal.</summary>
    public List<FlowState> RemoveAll()
    {
        var removed = new List<FlowState>();
        foreach (var kv in _flows)
            if (_flows.TryRemove(kv.Key, out var flow))
                removed.Add(flow);
        return removed;
    }
}
