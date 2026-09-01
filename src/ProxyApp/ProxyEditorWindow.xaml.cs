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
    private readonly IProxyTester _tester;

    /// <summary>The edited profile — valid only after <see cref="DialogResult"/> is true.</summary>
    public ProxyConfiguration Profile { get; private set; } = new();

    public ProxyEditorWindow(IProxyTester tester, ProxyConfiguration? initial)
    {
        _tester = tester ?? throw new ArgumentNullException(nameof(tester));
        InitializeComponent();
        ThemeApplier.Apply(this, new UiPreferences()); // neutral chrome; prefs applied by owner when editing

        initial ??= new ProxyConfiguration { Protocol = ProxyProtocol.Socks5 };
        NameBox.Text = initial.Name ?? "";
        HostBox.Text = initial.Host ?? "";
        PortBox.Text = initial.Port > 0 ? initial.Port.ToString() : "1080";
        UsernameBox.Text = initial.Username ?? "";
        PasswordBox.Password = initial.Password ?? "";
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
        Protocol = ProxyProtocol.Socks5,
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

    private void ShowResult(string message, bool isError)
    {
        ResultText.Text = message;
        ResultText.Foreground = isError
            ? System.Windows.Media.Brushes.Firebrick
            : System.Windows.Media.Brushes.Gray;
    }
}
