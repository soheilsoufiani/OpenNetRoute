using System.Windows;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Services;
using ProxyApp.Core.Validation;

namespace ProxyApp;

/// <summary>
/// Modal editor for a single proxy profile. The UI never stores credentials
/// outside the model: values are read into a <see cref="ProxyConfiguration"/>
/// on demand, and the test result surface never echoes the password.
/// </summary>
public partial class ProxyEditorWindow : Window
{
    /// <summary>Protocols offered by the Type combo, in combo-item order. SOCKS5
    /// is the only protocol the routing engine implements today; new enum values
    /// slot in by adding an item and extending this array.</summary>
    private static readonly ProxyProtocol[] KnownProtocols = { ProxyProtocol.Socks5 };

    private readonly IProxyTester _tester;
    private readonly bool _darkTitleBar;

    /// <summary>The edited profile — valid only after <see cref="DialogResult"/> is true.</summary>
    public ProxyConfiguration Profile { get; private set; } = new();

    public ProxyEditorWindow(IProxyTester tester, ProxyConfiguration? initial, UiPreferences? preferences = null)
    {
        _tester = tester ?? throw new ArgumentNullException(nameof(tester));
        var prefs = preferences ?? new UiPreferences();
        _darkTitleBar = ThemeApplier.IsDark(prefs.Theme);
        InitializeComponent();
        ThemeApplier.Apply(this, prefs); // themed with the app's saved light/dark palette

        initial ??= new ProxyConfiguration { Protocol = ProxyProtocol.Socks5 };
        NameBox.Text = initial.Name ?? "";
        HostBox.Text = initial.Host ?? "";
        PortBox.Text = initial.Port > 0 ? initial.Port.ToString() : "1080";
        UsernameBox.Text = initial.Username ?? "";
        PasswordBox.Password = initial.Password ?? "";
        // Map the profile's protocol onto the combo (index order = KnownProtocols).
        var protocolIndex = Array.IndexOf(KnownProtocols, initial.Protocol);
        ProtocolBox.SelectedIndex = protocolIndex < 0 ? 0 : protocolIndex;
    }

    /// <summary>HWND exists here — the native title bar can follow the palette.</summary>
    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        ThemeApplier.ApplyDarkTitleBar(this, _darkTitleBar);
    }

    private void OnTestClicked(object sender, RoutedEventArgs e)
    {
        var candidate = BuildProfile();
        var validation = ConfigurationValidator.Validate(candidate);
        if (!validation.IsValid)
        {
            ShowResult(string.Join("; ", validation.Errors), isError: true);
            return;
        }

        TestButton.IsEnabled = false;
        ShowResult("Testing…", isError: false);
        _ = TestAsyncCore(candidate);
    }

    private async Task TestAsyncCore(ProxyConfiguration candidate)
    {
        try
        {
            var result = await _tester.TestAsync(candidate, TimeSpan.FromSeconds(5));
            Dispatcher.Invoke(() =>
            {
                ShowResult(result.Message, isError: !result.Success);
                TestButton.IsEnabled = true;
            });
        }
        catch (Exception ex)
        {
            Dispatcher.Invoke(() =>
            {
                ShowResult($"Test failed: {ex.Message}", isError: true);
                TestButton.IsEnabled = true;
            });
        }
    }

    private void OnOkClicked(object sender, RoutedEventArgs e)
    {
        var candidate = BuildProfile();
        var validation = ConfigurationValidator.Validate(candidate);
        if (!validation.IsValid)
        {
            ShowResult(string.Join("; ", validation.Errors), isError: true);
            return;
        }

        Profile = candidate;
        DialogResult = true;
    }

    private ProxyConfiguration BuildProfile() => new()
    {
        Protocol = SelectedProtocol(),
        Name = string.IsNullOrWhiteSpace(NameBox.Text) ? null : NameBox.Text.Trim(),
        Host = HostBox.Text.Trim(),
        Port = int.TryParse(PortBox.Text.Trim(), out var port) ? port : 0,
        Username = string.IsNullOrWhiteSpace(UsernameBox.Text) ? null : UsernameBox.Text.Trim(),
        Password = string.IsNullOrEmpty(PasswordBox.Password) ? null : PasswordBox.Password,
        AuthenticationType = string.IsNullOrWhiteSpace(UsernameBox.Text)
            ? ProxyAuthenticationType.None
            : ProxyAuthenticationType.UsernamePassword,
        Enabled = true
    };

    /// <summary>The protocol chosen in the Type combo, mapped through
    /// <see cref="KnownProtocols"/> (combo index order); falls back to SOCKS5.</summary>
    private ProxyProtocol SelectedProtocol() =>
        ProtocolBox.SelectedIndex >= 0 && ProtocolBox.SelectedIndex < KnownProtocols.Length
            ? KnownProtocols[ProtocolBox.SelectedIndex]
            : ProxyProtocol.Socks5;

    private void ShowResult(string message, bool isError)
    {
        ResultText.Text = message;
        // Theme-aware tokens instead of hardcoded colors so the message stays
        // readable after a light/dark switch.
        ResultText.SetResourceReference(
            System.Windows.Controls.TextBlock.ForegroundProperty,
            isError ? "DangerBrush" : "TextSecondaryBrush");
    }
}
