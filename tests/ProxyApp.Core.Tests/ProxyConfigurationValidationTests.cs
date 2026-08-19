using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for <see cref="ConfigurationValidator.Validate(ProxyConfiguration)"/>.
/// </summary>
public class ProxyConfigurationValidationTests
{
    private static ProxyConfiguration ValidProxy()
    {
        return new ProxyConfiguration
        {
            Host = "proxy.example.com",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        };
    }

    [Fact]
    public void ValidProxy_WithNoAuth_IsValid()
    {
        var result = ConfigurationValidator.Validate(ValidProxy());

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void ValidProxy_WithIpv4Host_IsValid()
    {
        var proxy = ValidProxy();
        proxy.Host = "192.168.1.1";

        var result = ConfigurationValidator.Validate(proxy);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void ValidProxy_WithIpv6Host_IsValid()
    {
        var proxy = ValidProxy();
        proxy.Host = "::1";

        var result = ConfigurationValidator.Validate(proxy);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void ValidProxy_WithMinimalPort_IsValid()
    {
        var proxy = ValidProxy();
        proxy.Port = 1;

        Assert.True(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void ValidProxy_WithMaximalPort_IsValid()
    {
        var proxy = ValidProxy();
        proxy.Port = 65535;

        Assert.True(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void EmptyHost_IsInvalid()
    {
        var proxy = ValidProxy();
        proxy.Host = "";

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("host", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NullHost_IsInvalid()
    {
        var proxy = ValidProxy();
        proxy.Host = null;

        Assert.False(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void WhitespaceHost_IsInvalid()
    {
        var proxy = ValidProxy();
        proxy.Host = "   ";

        Assert.False(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Fact]
    public void HostWithEmbeddedSpace_IsInvalid()
    {
        var proxy = ValidProxy();
        proxy.Host = "my proxy.example.com";

        Assert.False(ConfigurationValidator.Validate(proxy).IsValid);
    }

    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("::")]
    [InlineData("::0")]
    [InlineData("localhost")]
    public void ForbiddenHostValues_AreInvalid(string host)
    {
        var proxy = ValidProxy();
        proxy.Host = host;

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains(host, StringComparison.Ordinal));
    }

    [Fact]
    public void OverlongHost_IsInvalid()
    {
        var proxy = ValidProxy();
        proxy.Host = new string('a', ConfigurationValidator.MaxHostLength + 1);

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("255", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(100000)]
    public void PortOutsideRange_IsInvalid(int port)
    {
        var proxy = ValidProxy();
        proxy.Port = port;

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("port", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, e => e.Contains(port.ToString(), StringComparison.Ordinal));
    }

    [Fact]
    public void UnsupportedAuthenticationType_IsInvalid()
    {
        var proxy = ValidProxy();
        proxy.AuthenticationType = (ProxyAuthenticationType)999;

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("not supported", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void MultipleErrors_AreAllReported()
    {
        var proxy = new ProxyConfiguration
        {
            Host = "",
            Port = 0,
            AuthenticationType = ProxyAuthenticationType.UsernamePassword,
            Username = "",
            Password = null,
            Enabled = true
        };

        var result = ConfigurationValidator.Validate(proxy);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("host", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, e => e.Contains("port", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Errors, e => e.Contains("username", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Validate_DoesNotMutate_Configuration()
    {
        var proxy = ValidProxy();
        var snapshotHost = proxy.Host;
        var snapshotPort = proxy.Port;

        _ = ConfigurationValidator.Validate(proxy);

        Assert.Equal(snapshotHost, proxy.Host);
        Assert.Equal(snapshotPort, proxy.Port);
    }
}