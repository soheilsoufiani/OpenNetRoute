using System.Runtime.CompilerServices;

// Expose internal WinDivert types to the integration test project so packet
// parsing/building and the flow table can be unit-tested without network I/O.
[assembly: InternalsVisibleTo("ProxyApp.IntegrationTests")]