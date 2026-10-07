using System.Net;
using System.Runtime.InteropServices;

namespace ProxyApp.Processes;

/// <summary>
/// Resolves the owning PID of a UDP socket by local address/port via the
/// Windows <c>GetExtendedUdpTable</c> API — the UDP analogue of
/// <see cref="ProcessTable"/>'s TCP lookup.
///
/// Race conditions (documented): a DNS query is a one-shot datagram — the
/// socket row is visible while the client waits for a reply, but the query may
/// be SENT before the table refreshes, and the client may close the socket
/// right after its (timed-out) wait. A row that is missing is reported as
/// null and the caller decides (queries without an attributable owner are
/// passed through unintercepted).
/// </summary>
public static class UdpProcessTable
{
    private enum UdpTableClass
    {
        OwnerPid = 1
    }

    // CS0649 (fields never assigned) is a false positive: the fields are
    // filled by Marshal.PtrToStructure from the native MIB_UDPROW_OWNER_PID.
#pragma warning disable CS0649
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddr;
        public int LocalPort;
        public int OwningPid;
    }
#pragma warning restore CS0649

#pragma warning disable CS0649
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;
        public uint LocalScopeId;
        public int LocalPort;
        public int OwningPid;
    }
#pragma warning restore CS0649

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable, ref int dwSize, bool bOrder,
        int ulAf, UdpTableClass tableClass, int reserved);

    /// <summary>
    /// Resolves the owning PID of the UDP socket bound to
    /// <paramref name="localIp"/>:<paramref name="localPort"/> (IPv4 table).
    /// Returns null when no row matches (socket gone, or raced the table).
    /// Never throws for lookup failures.
    /// </summary>
    public static int? ResolveOwnerPid(IPAddress localIp, ushort localPort)
    {
        try
        {
            int size = 0;
            _ = GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, UdpTableClass.OwnerPid, 0);
            if (size <= 0)
                return null;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedUdpTable(buffer, ref size, false, 2, UdpTableClass.OwnerPid, 0) != 0)
                    return null;

                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<MibUdpRowOwnerPid>();
                var offset = Marshal.SizeOf<int>();

                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(buffer + offset + i * rowSize);
                    // Byte order matches the E8-a spike (proven): the table
                    // stores the port big-endian in the low 16 bits.
                    var rowLocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.LocalPort);
                    if (rowLocalPort != localPort)
                        continue;

                    var rowLocalIp = new IPAddress(row.LocalAddr);
                    // A socket bound to 0.0.0.0 matches any local address.
                    if (rowLocalIp.Equals(IPAddress.Any) || rowLocalIp.Equals(localIp))
                    {
                        if (row.OwningPid > 0)
                            return row.OwningPid;
                    }
                }
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception)
        {
            // Attribution is best-effort: a failed lookup must never take down
            // the caller. Null = "cannot attribute".
            return null;
        }
    }

    /// <summary>
    /// Resolves the owning PID of the IPv6 UDP socket bound to
    /// <paramref name="localIp"/>:<paramref name="localPort"/> (IPv6 table,
    /// AF_INET6). Returns null when no row matches. Never throws.
    /// Diagnostic-only, like the IPv4 lookup.
    /// </summary>
    public static int? ResolveOwnerPidV6(IPAddress localIp, ushort localPort)
    {
        const int AfInet6 = 23;
        try
        {
            int size = 0;
            _ = GetExtendedUdpTable(IntPtr.Zero, ref size, false, AfInet6, UdpTableClass.OwnerPid, 0);
            if (size <= 0)
                return null;

            var buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (GetExtendedUdpTable(buffer, ref size, false, AfInet6, UdpTableClass.OwnerPid, 0) != 0)
                    return null;

                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<MibUdp6RowOwnerPid>();
                var offset = Marshal.SizeOf<int>();
                var localBytes = localIp.GetAddressBytes();

                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(buffer + offset + i * rowSize);
                    var rowLocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.LocalPort);
                    if (rowLocalPort != localPort)
                        continue;

                    var rowLocalIp = new IPAddress(row.LocalAddr, 0);
                    // A socket bound to :: matches any local address.
                    if (rowLocalIp.Equals(IPAddress.IPv6Any) ||
                        rowLocalIp.GetAddressBytes().SequenceEqual(localBytes))
                    {
                        if (row.OwningPid > 0)
                            return row.OwningPid;
                    }
                }
                return null;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception)
        {
            return null;
        }
    }
}
