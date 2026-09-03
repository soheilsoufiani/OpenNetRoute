using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for <see cref="ConfigurationValidator.Validate(ApplicationSettings)"/>
/// and for JSON round-tripping of the configuration models.
/// </summary>
public class ApplicationSettingsValidationTests
{
    private static ApplicationSettings ValidSettings()
    {
        return new ApplicationSettings
        {
            Proxy = new ProxyConfiguration
            {
                Host = "proxy.example.com",
                Port = 1080,
                AuthenticationType = ProxyAuthenticationType.None,
                Enabled = true
            },
            Rules =
            {
                new ApplicationRule
                {
                    ExecutableName = "chrome.exe",
                    ExecutablePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    Enabled = true,
                    Mode = ProxyMode.Proxy
                }
            },
            LogLevel = LogLevelConfiguration.Information
        };
    }

    [Fact]
    public void ValidSettings_AreValid()
    {
        var result = ConfigurationValidator.Validate(ValidSettings());

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Settings_WithoutProxy_AreInvalid()
    {
        var settings = ValidSettings();
        settings.Proxy = null;

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("proxy", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Settings_WithInvalidProxy_AreInvalid()
    {
        var settings = ValidSettings();
        settings.Proxy!.Port = 0;

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("port", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Settings_WithInvalidRule_AreInvalid()
    {
        var settings = ValidSettings();
        settings.Rules.Add(new ApplicationRule { ExecutableName = "", Mode = ProxyMode.Proxy });

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("executable name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Settings_WithDuplicateRules_AreInvalid()
    {
        var settings = ValidSettings();
        settings.Rules.Add(new ApplicationRule
        {
            ExecutableName = "chrome.exe",
            Enabled = true,
            Mode = ProxyMode.Proxy
        });

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("duplicate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Settings_WithUnsupportedLogLevel_AreInvalid()
    {
        var settings = ValidSettings();
        settings.LogLevel = (LogLevelConfiguration)999;

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("log level", StringComparison.OrdinalIgnoreCase));
    }

    // ── Per-rule proxy pinning (ApplicationRule.ProxyName) ──

    [Fact]
    public void Rule_WithValidProxyName_IsValid()
    {
        var settings = ValidSettings();
        settings.Rules[0].ProxyName = "Home";
        settings.Proxies.Add(new ProxyConfiguration
        {
            Name = "Home",
            Host = "198.51.100.7",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        });

        var result = ConfigurationValidator.Validate(settings);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public void Rule_ProxyNameMatch_IsCaseInsensitive()
    {
        var settings = ValidSettings();
        settings.Rules[0].ProxyName = "home"; // saved as "Home"
        settings.Proxies.Add(new ProxyConfiguration
        {
            Name = "Home",
            Host = "198.51.100.7",
            Port = 1080,
            Enabled = true
        });

        var result = ConfigurationValidator.Validate(settings);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public void Rule_WithUnknownProxyName_IsInvalid()
    {
        var settings = ValidSettings();
        settings.Rules[0].ProxyName = "Does-Not-Exist";

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e =>
            e.Contains("Does-Not-Exist", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Rule_WithBlankProxyName_IsInvalid()
    {
        var settings = ValidSettings();
        settings.Rules[0].ProxyName = "   ";

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("blank", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Rule_WithoutProxyName_IsValid_WithNoSavedProxies()
    {
        // Legacy documents: ProxyName absent means "Default" — always valid.
        var settings = ValidSettings();

        var result = ConfigurationValidator.Validate(settings);

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Fact]
    public void DefaultLogLevel_IsInformation()
    {
        var settings = new ApplicationSettings
        {
            Proxy = ValidSettings().Proxy
        };

        Assert.Equal(LogLevelConfiguration.Information, settings.LogLevel);
    }

    [Fact]
    public void Settings_RoundTripThroughJson_WithoutCustomConverters()
    {
        var settings = ValidSettings();
        settings.Proxy!.AuthenticationType = ProxyAuthenticationType.UsernamePassword;
        settings.Proxy.Username = "alice";
        settings.Proxy.Password = "secret";

        var json = System.Text.Json.JsonSerializer.Serialize(settings);
        var roundTripped = System.Text.Json.JsonSerializer.Deserialize<ApplicationSettings>(json);

        Assert.NotNull(roundTripped);
        Assert.NotNull(roundTripped.Proxy);
        Assert.Equal(settings.Proxy.Host, roundTripped.Proxy.Host);
        Assert.Equal(settings.Proxy.Port, roundTripped.Proxy.Port);
        Assert.Equal(settings.Proxy.Username, roundTripped.Proxy.Username);
        Assert.Equal(settings.Proxy.Password, roundTripped.Proxy.Password);
        Assert.Equal(settings.Proxy.AuthenticationType, roundTripped.Proxy.AuthenticationType);
        Assert.Equal(settings.Proxy.Enabled, roundTripped.Proxy.Enabled);
        Assert.Equal(settings.LogLevel, roundTripped.LogLevel);
        Assert.Single(roundTripped.Rules);
        Assert.Equal(settings.Rules[0].ExecutableName, roundTripped.Rules[0].ExecutableName);
        Assert.Equal(settings.Rules[0].ExecutablePath, roundTripped.Rules[0].ExecutablePath);
        Assert.Equal(settings.Rules[0].Enabled, roundTripped.Rules[0].Enabled);
        Assert.Equal(settings.Rules[0].Mode, roundTripped.Rules[0].Mode);
    }

    [Fact]
    public void RoundTrippedSettings_AreStillValid()
    {
        var settings = ValidSettings();
        var json = System.Text.Json.JsonSerializer.Serialize(settings);
        var roundTripped = System.Text.Json.JsonSerializer.Deserialize<ApplicationSettings>(json);

        var result = ConfigurationValidator.Validate(roundTripped!);

        Assert.True(result.IsValid);
    }
}