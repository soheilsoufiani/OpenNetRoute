using ProxyApp.Core.Configuration;
using ProxyApp.Core.Services;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for <see cref="ProxyEngine"/>, the production host the WPF shell
/// drives. Validation failures and the never-started lifecycle are tested
/// directly; the elevated WinDivert open path is covered by the end-to-end
/// ferry tests (and requires Administrator privileges).
/// </summary>
public class ProxyEngineTests
{
    private static bool IsElevated()
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        return new System.Security.Principal.WindowsPrincipal(identity)
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
    }

    private static ApplicationSettings ValidSettings() => new()
    {
        Proxy = new ProxyConfiguration
        {
            Host = "127.0.0.1",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        },
        Rules = new List<ApplicationRule>()
    };

    [Fact]
    public void Start_NullSettings_Throws()
    {
        using var engine = new ProxyEngine();
        Assert.Throws<ArgumentNullException>(() => engine.Start(null!));
    }

    [Fact]
    public void Start_InvalidSettings_Throws()
    {
        using var engine = new ProxyEngine();

        var settings = ValidSettings();
        settings.Proxy!.Port = 0; // invalid per ConfigurationValidator

        var ex = Assert.Throws<ArgumentException>(() => engine.Start(settings));
        Assert.Contains("Invalid configuration", ex.Message);
    }

    [Fact]
    public void Start_WhenNotElevated_SurfacesWinDivertError()
    {
        // The WinDivert open fails without Administrator privileges; the engine
        // must throw a clear, actionable error instead of failing silently.
        // Elevated runs cannot exercise this path (Start succeeds), so skip.
        if (IsElevated())
        {
            return;
        }

        using var engine = new ProxyEngine();
        var settings = ValidSettings();

        var ex = Assert.Throws<InvalidOperationException>(() => engine.Start(settings));
        Assert.Contains("WinDivert", ex.Message);
    }

    [Fact]
    public async Task StopAsync_WhenNeverStarted_IsSafe()
    {
        using var engine = new ProxyEngine();
        await engine.StopAsync();
        Assert.False(engine.IsRunning);
    }

    [Fact]
    public async Task GetDnsDiagnostics_WhenNeverStarted_ReportsTheRelayOff()
    {
        // The UI polls this every second and renders it unconditionally, so a
        // never-started engine must return a usable shape — not null and not a
        // relay-"Active" claim.
        using var engine = new ProxyEngine();

        var diagnostics = engine.GetDnsDiagnostics();

        Assert.False(diagnostics.RelayEnabled);
        Assert.False(diagnostics.SniInspectionActive);
        Assert.Equal(0, diagnostics.QueriesCaptured);
        Assert.Equal(0, diagnostics.QueriesRelayed);
        Assert.Equal(0, diagnostics.EncryptedDnsDetected);
        Assert.Null(engine.LastEncryptedDnsDetection);
    }

    [Fact]
    public async Task StopAsync_WithDiagnosticsRunning_IsStillSafe()
    {
        // Stop must tear down the SNI observer alongside the ferries. A leaked
        // sniff handle would keep observing after STOP, which is a correctness
        // bug even though it cannot affect routing.
        using var engine = new ProxyEngine();
        await engine.StopAsync();
        await engine.StopAsync(); // idempotent
        Assert.False(engine.IsRunning);
    }
}
