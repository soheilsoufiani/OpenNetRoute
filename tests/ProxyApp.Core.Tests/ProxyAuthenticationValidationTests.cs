using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for username/password authentication validation rules
/// (<see cref="ProxyAuthenticationType.UsernamePassword"/>).
/// </summary>
public class ProxyAuthenticationValidationTests
{
    private static ProxyConfiguration AuthProxy(string? username = null, string? password = null)
    {
        return new ProxyConfiguration
        {
            Host = "proxy.example.com",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.UsernamePassword,
            Username = username,
            Password = password,
            Enabled = true
        };
    }

    [Fact]
    public void UsernamePassword_WithValidCredentials_IsValid()
    {
        var proxy = AuthProxy("alice", "secret");

        var result = ConfigurationValidator.Validate(proxy);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void UsernamePassword_WithEmptyPassword_IsValid()
    {
        // RFC 1929 allows an empty password (PLEN = 0).
        var proxy = AuthProxy("alice", "");

        var result = ConfigurationValidator.Validate(proxy);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void UsernamePassword_WithNullPassword_IsValid()
    {
        var proxy = AuthProxy("alice", null);

        Assert.True(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void UsernamePassword_WithEmptyUsername_IsInvalid()
    {
        var proxy = AuthProxy("", "secret");

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("username", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UsernamePassword_WithNullUsername_IsInvalid()
    {
        var proxy = AuthProxy(null, "secret");

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("username", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void UsernamePassword_WithWhitespaceUsername_IsInvalid()
    {
        var proxy = AuthProxy("   ", "secret");

        Assert.False(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void UsernamePassword_WithOverlongUsername_IsInvalid()
    {
        var proxy = AuthProxy(new string('a', ConfigurationValidator.MaxUsernameLength + 1), "secret");

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("255", StringComparison.Ordinal));
    }

    [Fact]
    public void UsernamePassword_WithOverlongPassword_IsInvalid()
    {
        var proxy = AuthProxy("alice", new string('b', ConfigurationValidator.MaxPasswordLength + 1));

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("255", StringComparison.Ordinal));
    }

    [Fact]
    public void NoAuthentication_IgnoresUsernameAndPassword_IsValid()
    {
        var proxy = AuthProxy("", "");
        proxy.AuthenticationType = ProxyAuthenticationType.None;

        var result = ConfigurationValidator.Validate(proxy);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void NoAuthentication_WithBlankUsernameAndPassword_IsValid()
    {
        var proxy = new ProxyConfiguration
        {
            Host = "proxy.example.com",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Username = "  ",
            Password = "  ",
            Enabled = true
        };

        Assert.True(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void DisabledProxy_IsStillValidated()
    {
        // Validation is independent of the Enabled flag: invalid data stays
        // invalid even when the proxy is not in use.
        var proxy = AuthProxy(null, "secret");
        proxy.Enabled = false;

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("username", StringComparison.OrdinalIgnoreCase));
    }
}