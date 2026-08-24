using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ProxyApp.Core.Processes;

namespace ProxyApp.Processes;

/// <summary>
/// Maps TCP connections to owning processes via the Windows
/// <c>GetExtendedTcpTable</c> API, with a short-lived snapshot cache.
///
/// The uncached lookup (spike E7) takes ~3ms per call because it walks the
/// ENTIRE OS connection table. A browser opening 30+ concurrent connections
/// fires 30+ lookups in the same burst; doing a full table walk per SYN
/// serializes the SYN handlers and is the primary concurrent-flow bottleneck.
///
/// This resolver snapshots the table once per <see cref="CacheWindow"/> (50ms)
/// and serves all lookups in that window from the snapshot. Attribution only
/// needs "which process owns this 4-tuple"; a connection that opened within
/// the last 50ms is still resolvable from the previous snapshot (the row
/// appears in the next refresh if it was not in the last). Connections that
/// closed are simply not found — the SYN path treats a miss as Direct, which
/// is the safe default.
///
/// Thread-safe: the snapshot is replaced atomically under a lock; readers
/// query the current snapshot without holding the lock.
/// </summary>
public sealed class CachedProcessTable : IConnectionProcessResolver
{
    /// <summary>How long a snapshot is reused before the table is re-queried.</summary>
    public static readonly TimeSpan DefaultCacheWindow = TimeSpan.FromMilliseconds(50);

    private readonly TimeSpan _cacheWindow;
    private readonly object _snapshotLock = new();
    private Snapshot? _snapshot;

    /// <summary>
    /// Creates the resolver with the default 50ms snapshot window.
    /// </summary>
    public CachedProcessTable(TimeSpan? cacheWindow = null)
    {
        _cacheWindow = cacheWindow ?? DefaultCacheWindow;
    }

    /// <inheritdoc />
    public ConnectionProcessInfo? ResolveOwner(
        IPAddress localIp, ushort localPort,
        IPAddress remoteIp, ushort remotePort)
    {
        // Fast path: the cached snapshot (one full-table query per window).
        // A browser burst of N SYNs is served by ONE snapshot, not N walks.
        var snapshot = GetSnapshot();
        var pid = snapshot.FindOwnerPid(localIp, localPort, remoteIp, remotePort);

        // Miss path: the connection may have opened after the snapshot was
        // taken (a SYN for a brand-new connection). Fall back to a direct
        // on-demand query so a fresh connection is still attributed — the
        // snapshot is an optimization, never a correctness regression.
        if (pid == null)
            pid = ProcessTable.FindOwnerPid(localIp, localPort, remoteIp, remotePort);

        if (pid == null)
            return null;

        try
        {
            using var proc = Process.GetProcessById(pid.Value);
            var name = proc.ProcessName + ".exe";
            return new ConnectionProcessInfo(pid.Value, name, proc.MainModule?.FileName);
        }
        catch
        {
            // Process exited or access denied.
            return null;
        }
    }

    /// <summary>
    /// Returns the current snapshot, refreshing it if the previous one has
    /// aged past <see cref="_cacheWindow"/>. Thread-safe.
    /// </summary>
    private Snapshot GetSnapshot()
    {
        lock (_snapshotLock)
        {
            if (_snapshot != null && DateTime.UtcNow - _snapshot.CreatedUtc < _cacheWindow)
                return _snapshot;
            _snapshot = Snapshot.Capture();
            return _snapshot;
        }
    }

    /// <summary>An immutable snapshot of the TCP connection table.</summary>
    private sealed class Snapshot
    {
        public DateTime CreatedUtc { get; } = DateTime.UtcNow;

        /// <summary>Rows keyed by (localIp, localPort, remoteIp, remotePort) for O(1) lookup.</summary>
        private readonly Dictionary<RowKey, int> _pidByTuple;

        private Snapshot(Dictionary<RowKey, int> pidByTuple)
        {
            _pidByTuple = pidByTuple;
        }

        public static Snapshot Capture()
        {
            int size = 0;
            NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, TcpTableClass.OwnerPidAll, 0);
            var pidByTuple = new Dictionary<RowKey, int>(size > 0 ? size / 24 : 256);

            if (size > 0)
            {
                var buffer = Marshal.AllocHGlobal(size);
                try
                {
                    if (NativeMethods.GetExtendedTcpTable(buffer, ref size, false, 2, TcpTableClass.OwnerPidAll, 0) != 0)
                        return new Snapshot(pidByTuple);

                    var count = Marshal.ReadInt32(buffer);
                    var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
                    var offset = Marshal.SizeOf<int>();

                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buffer + offset + i * rowSize);
                        var key = new RowKey(row);
                        if (row.owningPid > 0)
                            pidByTuple[key] = row.owningPid;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(buffer);
                }
            }

            return new Snapshot(pidByTuple);
        }

        public int? FindOwnerPid(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
        {
            var key = new RowKey(localIp, localPort, remoteIp, remotePort);
            return _pidByTuple.TryGetValue(key, out var pid) ? pid : null;
        }

        private readonly struct RowKey : IEquatable<RowKey>
        {
            private readonly uint _localIp;
            private readonly int _localPort;
            private readonly uint _remoteIp;
            private readonly int _remotePort;

            public RowKey(MibTcpRowOwnerPid row)
            {
                _localIp = row.localAddr;
                _localPort = row.localPort;
                _remoteIp = row.remoteAddr;
                _remotePort = row.remotePort;
            }

            public RowKey(IPAddress localIp, ushort localPort, IPAddress remoteIp, ushort remotePort)
            {
                // IPAddress stores the dotted-quad in network byte order; the
                // uint overload reconstructs it as a uint in host byte order.
                _localIp = BitConverter.ToUInt32(localIp.GetAddressBytes());
                _localPort = (int)IPAddress.HostToNetworkOrder((short)localPort);
                _remoteIp = BitConverter.ToUInt32(remoteIp.GetAddressBytes());
                _remotePort = (int)IPAddress.HostToNetworkOrder((short)remotePort);
            }

            public bool Equals(RowKey other) =>
                _localIp == other._localIp && _localPort == other._localPort &&
                _remoteIp == other._remoteIp && _remotePort == other._remotePort;

            public override bool Equals(object? obj) => obj is RowKey other && Equals(other);

            public override int GetHashCode() =>
                HashCode.Combine(_localIp, _localPort, _remoteIp, _remotePort);
        }
    }

    private enum TcpTableClass
    {
        OwnerPidAll = 5
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint state;
        public uint localAddr;
        public int localPort;
        public uint remoteAddr;
        public int remotePort;
        public int owningPid;
    }

    private static class NativeMethods
    {
        [DllImport("iphlpapi.dll", SetLastError = true)]
        public static extern int GetExtendedTcpTable(
            IntPtr pTcpTable, ref int dwSize, bool bOrder,
            int ulAf, TcpTableClass tableClass, int reserved);
    }
}
