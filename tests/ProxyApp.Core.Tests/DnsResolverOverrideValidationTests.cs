using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Validation of the DNS resolver override. It is the address every relayed
/// query is sent to, so it must be a real IP literal of either family — a
/// hostname would need a resolution step that does not exist on the relay path,
/// and a loopback address would be useless through a remote proxy.
/// </summary>
public class DnsResolverOverrideValidationTests
{
    private static ApplicationSettings SettingsWithResolver(string resolver) => new()
    {
        Proxy = new ProxyConfiguration
        {
            Host = "proxy.example.com",
            Port = 1080,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        },
        Dns = new DnsSettings { Enabled = true, ResolverOverride = resolver },
        Optimization = new OptimizationSettings()
    };

    [Theory]
    [InlineData("1.1.1.1")]        // Cloudflare v4
    [InlineData("8.8.8.8")]        // Google v4
    [InlineData("2606:4700:4700::1111")] // Cloudflare v6
    [InlineData("2001:4860:4860::8888")] // Google v6
    public void ResolverOverride_AcceptsIpLiteralsOfEitherFamily(string resolver)
    {
        var result = ConfigurationValidator.Validate(SettingsWithResolver(resolver));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }

    [Theory]
    [InlineData("cloudflare-dns.com")]
    [InlineData("not-an-ip")]
    [InlineData("256.1.1.1")]
    public void ResolverOverride_RejectsNonLiterals(string resolver)
    {
        var result = ConfigurationValidator.Validate(SettingsWithResolver(resolver));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("not a valid IP address"));
    }

    [Fact]
    public void ResolverOverride_RejectsLoopback()
    {
        var result = ConfigurationValidator.Validate(SettingsWithResolver("127.0.0.1"));

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("loopback"));
    }

    [Fact]
    public void ResolverOverride_EmptyIsTransparentAndValid()
    {
        var result = ConfigurationValidator.Validate(SettingsWithResolver(""));

        Assert.True(result.IsValid, string.Join("; ", result.Errors));
    }
}
