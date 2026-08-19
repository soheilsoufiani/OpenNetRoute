namespace ProxyApp.IntegrationTests;

/// <summary>
/// Phase 0 placeholder: verifies the WinDivert assembly marker type is
/// reachable through the project-reference graph. Real integration tests
/// (local SOCKS5 test server, WinDivert capture, process mapping) begin in
/// later phases and must clean up after themselves.
/// </summary>
public class ProjectGraphTests
{
    [Fact]
    public void WinDivertAssembly_IsReachable()
    {
        Assert.NotNull(typeof(ProxyApp.WinDivert.WinDivertAssembly));
    }

    [Fact]
    public void ProcessesAssembly_IsReachable()
    {
        Assert.NotNull(typeof(ProxyApp.Processes.ProcessesAssembly));
    }
}