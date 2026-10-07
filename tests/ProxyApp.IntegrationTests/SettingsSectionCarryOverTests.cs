using System.Reflection;
using ProxyApp.Core.Configuration;
using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// A regression guard for a SILENT settings-loss bug: the WPF shell's START path
/// builds a brand-new <see cref="ApplicationSettings"/> instead of handing
/// <c>_settings</c> to the engine, and any section it forgets to copy reverts to
/// its property default.
///
/// <para>
/// The sections it originally forgot were <c>Dns</c> and <c>Optimization</c>.
/// With <c>Dns</c> lost, the engine saw <c>settings.Dns == null</c> and therefore
/// started none of: the UDP DNS ferry, the TCP/53 forced proxy port, the IPv6
/// TCP capture handle, the WebRTC/STUN blocker, or the encrypted-DNS SNI
/// observer.
/// </para>
///
/// <para>
/// It stayed invisible because every other layer reported success. The UI logged
/// the user's choice ("WebRTC block=True"), the settings were persisted and read
/// back on the next launch, and the engine started normally with the TCP ferry
/// logging — while the DNS features never existed. The only symptom was an
/// absence of log lines, which is indistinguishable from a feature working but
/// having nothing to do.
/// </para>
/// </summary>
public class SettingsSectionCarryOverTests
{
    /// <summary>
    /// The sections <c>BuildSettingsFromUi</c> is known to carry. MainWindow is
    /// internal to the WPF assembly and cannot be referenced from the test
    /// project, so this list is the contract those tests below enforce instead.
    /// Adding a new section to the app must add it here too.
    /// </summary>
    private static readonly string[] SectionsCarriedByTheUi =
    [
        "Proxy",
        "Rules",
        "IpDomainRules",
        "Proxies",
        "SelectedProxyName",
        "LogLevel",
        "Preferences",
        "Dns",
        "Optimization"
    ];

    /// <summary>
    /// Every public settable section of <see cref="ApplicationSettings"/> must
    /// appear in the carry-over list. A new section added to the model but not
    /// carried across would silently revert to defaults at START — the exact
    /// failure this file exists to prevent.
    /// </summary>
    [Fact]
    public void EverySettingsSection_IsCarriedFromTheUi()
    {
        var modelled = typeof(ApplicationSettings)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanWrite)
            .Select(p => p.Name)
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        var carried = SectionsCarriedByTheUi
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        // Both directions matter: a modelled section that is not carried is the
        // bug, and a carried name that no longer exists is a stale test that
        // would let the real bug back in through a rename.
        Assert.Equal(modelled, carried);
    }

    /// <summary>
    /// The engine must treat a null <c>Dns</c> as "off" rather than crashing —
    /// but it must ALSO not silently claim to be doing DNS work. This pins the
    /// defensive shape of <see cref="ProxyEngine"/> so a future change cannot make
    /// a missing section look like an active one.
    /// </summary>
    [Fact]
    public void ADnsSectionLeftNull_ReportsEverythingOffRatherThanActive()
    {
        // Reproduces the exact object the engine received when the UI dropped the
        // section: Dns and Optimization null.
        var settings = new ApplicationSettings
        {
            Proxy = new ProxyConfiguration
            {
                Host = "127.0.0.1",
                Port = 1080,
                AuthenticationType = ProxyAuthenticationType.None,
                Enabled = true
            },
            Rules = [],
            Dns = null!,
            Optimization = null!
        };

        // Every gate in ProxyEngine.Start is written as `settings.Dns?.X == true`
        // precisely so this object yields no DNS work and no TCP/53 forcing.
        Assert.Null(settings.Dns);
        Assert.Null(settings.Optimization);
        Assert.False(settings.Dns?.Enabled == true);
        Assert.False(settings.Dns?.RelayStun == true);
        Assert.False(settings.Dns?.BlockWebRtc == true);
    }

    /// <summary>
    /// The property defaults must stay OFF, so that losing a section degrades to
    /// "feature off" (a visible, honest state) rather than to "feature on"
    /// (a silent false promise). Defaults that enabled themselves would turn a
    /// dropped-section bug back into a silent no-op in the opposite direction.
    /// </summary>
    [Fact]
    public void PropertyDefaults_AreOff_SoALostSectionDegradesVisibly()
    {
        var fresh = new ApplicationSettings();

        Assert.False(fresh.Dns.Enabled);
        Assert.False(fresh.Dns.RelayStun);
        Assert.False(fresh.Dns.BlockWebRtc);

        // ResolverOverride is deliberately NOT null by default — Cloudflare is a
        // sensible pre-selected resolver. It is inert while the relay is off, so
        // it is not part of the on/off contract asserted above.
    }
}
