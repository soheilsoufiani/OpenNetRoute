using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using ProxyApp.Core.Processes;

namespace ProxyApp.Processes;

/// <summary>
/// Maps TCP connections to owning processes via the Windows
/// <c>GetExtendedTcpTable</c> API. The lookup is validated in the spike
/// experiment E7: the owning PID of a captured SYN is found in ~3ms.
///
/// This class is stateless and thread-safe. Each lookup queries the OS
/// connection table and returns the result immediately.
/// </summary>
public sealed class ProcessTable : IConnectionProcessResolver
{
    /// <inheritdoc />
    public ConnectionProcessInfo? ResolveOwner(
        IPAddress localIp, ushort localPort,
        IPAddress remoteIp, ushort remotePort)
    {
        var pid = FindOwnerPid(localIp, localPort, remoteIp, remotePort);
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
    /// Queries the extended TCP table for the owning PID of the given 4-tuple.
    /// Returns null if the row is not found (not yet visible, or the connection
    /// does not exist in the table).
    /// </summary>
    private static int? FindOwnerPid(
        IPAddress localIp, ushort localPort,
        IPAddress remoteIp, ushort remotePort)
    {
        int size = 0;
        NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, TcpTableClass.OwnerPidAll, 0);
        if (size <= 0)
            return null;

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (NativeMethods.GetExtendedTcpTable(buffer, ref size, false, 2, TcpTableClass.OwnerPidAll, 0) != 0)
                return null;

            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var offset = Marshal.SizeOf<int>();

            for (var i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(buffer + offset + i * rowSize);

                // MIB_TCPROW_OWNER_PID stores addresses and ports in network byte
                // order. Convert to host byte order for comparison.
                var rowLocalPort = (ushort)IPAddress.NetworkToHostOrder((short)row.localPort);
                var rowRemotePort = (ushort)IPAddress.NetworkToHostOrder((short)row.remotePort);
                // The struct stores the address as a uint in network byte order;
                // the uint overload of IPAddress reconstructs the dotted-quad
                // correctly (validated in E7).
                var rowLocalIp = new IPAddress(row.localAddr);
                var rowRemoteIp = new IPAddress(row.remoteAddr);

                if (rowLocalPort == localPort && rowRemotePort == remotePort &&
                    rowLocalIp.Equals(localIp) && rowRemoteIp.Equals(remoteIp) &&
                    row.owningPid > 0)
                {
                    return row.owningPid;
                }
            }

            return null;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
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