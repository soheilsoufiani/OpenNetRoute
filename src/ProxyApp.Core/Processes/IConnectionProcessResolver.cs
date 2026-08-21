using System.Net;

namespace ProxyApp.Core.Processes;

/// <summary>
/// Maps a network connection (identified by its 4-tuple) to the owning process.
/// Used at SYN-capture time to decide whether a connection belongs to a
/// selected application.
/// </summary>
public interface IConnectionProcessResolver
{
    /// <summary>
    /// Resolves the owning process ID and executable name for the given TCP
    /// connection. Returns null if the connection cannot be attributed (no
    /// matching row, process already exited, access denied, or the row is not
    /// yet visible in the connection table).
    /// </summary>
    ConnectionProcessInfo? ResolveOwner(
        IPAddress localIp, ushort localPort,
        IPAddress remoteIp, ushort remotePort);
}

/// <summary>
/// Process identity information for a resolved connection.
/// </summary>
public readonly record struct ConnectionProcessInfo(int ProcessId, string ExecutableName);