using System.Runtime.CompilerServices;

// Expose internal protocol helpers to the unit test project. This is limited to
// the pure wire-encoding logic (BuildConnectRequest) so the byte-level format can
// be verified without network I/O; the public ISocks5Client surface is unchanged.
[assembly: InternalsVisibleTo("ProxyApp.Network.Tests")]