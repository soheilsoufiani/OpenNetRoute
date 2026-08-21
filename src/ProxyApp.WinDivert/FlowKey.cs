using System.Net;

namespace ProxyApp.WinDivert;

/// <summary>
/// Uniquely identifies a TCP connection (a 4-tuple: local IP:port → remote
/// IP:port). Used as the key for the flow table.
/// </summary>
internal readonly record struct FlowKey(
    IPAddress LocalIp,
    ushort LocalPort,
    IPAddress RemoteIp,
    ushort RemotePort);
