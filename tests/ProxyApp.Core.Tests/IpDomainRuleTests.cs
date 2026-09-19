using System.Net;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Rules;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for <see cref="DestinationMatch.TryParse"/>: IPv4 literals, domains,
/// optional ':port' suffix, and the deliberate IPv6 rejection.
/// </summary>
public class DestinationRuleParserTests
{
    [Theory]
    [InlineData("1.2.3.4", "1.2.3.4", null)]
    [InlineData("  1.2.3.4  ", "1.2.3.4", null)]
    [InlineData("1.2.3.4:443", "1.2.3.4", 443)]
    [InlineData("example.com", "example.com", null)]
    [InlineData("Example.COM", "Example.COM", null)]
    [InlineData("example.com:8443", "example.com", 8443)]
    [InlineData("sub.deep.example.org:1", "sub.deep.example.org", 1)]
    public void ValidInputs_Parse(string text, string expectedHost, int? expectedPort)
    {
        Assert.True(DestinationMatch.TryParse(text, out var host, out var port));
        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(":443")]          // no host
    [InlineData("1.2.3.4:")]      // no port
    [InlineData("1.2.3.4:0")]     // port below range
    [InlineData("1.2.3.4:65536")] // port above range
    [InlineData("1.2.3.4:port")]  // non-numeric port
    [InlineData("256.1.1.1")]     // invalid IPv4
    [InlineData("1.2.3")]         // partial IPv4 is not a valid DNS name here
    [InlineData("::1")]           // IPv6 unsupported
    [InlineData("[::1]:443")]     // IPv6 with port
    [InlineData("not a domain!")] // invalid host characters
    public void InvalidInputs_Rejected(string? text)
    {
        Assert.False(DestinationMatch.TryParse(text, out _, out _));
    }
}

/// <summary>
/// Tests for <see cref="DestinationMatch.Matches"/>: IPv4-only destinations,
/// exact/port matching, domain rules via resolved addresses, and disabled rules.
/// </summary>
public class DestinationMatchTests
{
    private static readonly IPAddress Dest = IPAddress.Parse("142.250.0.14");

    private static IpDomainRule Rule(
        string host, int? port = null, ProxyMode mode = ProxyMode.Proxy,
        bool enabled = true, string? proxyName = null)
    {
        return new IpDomainRule { Host = host, Port = port, Mode = mode, Enabled = enabled, ProxyName = proxyName };
    }

    [Fact]
    public void IpLiteral_MatchesExactAddress()
    {
        Assert.True(DestinationMatch.Matches(Rule("142.250.0.14"), Dest, 443, null));
    }

    [Fact]
    public void IpLiteral_DifferentAddress_DoesNotMatch()
    {
        Assert.False(DestinationMatch.Matches(Rule("142.250.0.15"), Dest, 443, null));
    }

    [Fact]
    public void PortRestriction_OnlyMatchesThatPort()
    {
        var rule = Rule("142.250.0.14", port: 443);
        Assert.True(DestinationMatch.Matches(rule, Dest, 443, null));
        Assert.False(DestinationMatch.Matches(rule, Dest, 80, null));
    }

    [Fact]
    public void NullPort_MatchesAnyPort()
    {
        Assert.True(DestinationMatch.Matches(Rule("142.250.0.14"), Dest, 80, null));
        Assert.True(DestinationMatch.Matches(Rule("142.250.0.14"), Dest, 443, null));
    }

    [Fact]
    public void DomainRule_MatchesResolvedAddress()
    {
        var resolved = new List<IPAddress> { IPAddress.Parse("142.250.0.14"), IPAddress.Parse("142.250.0.15") };
        Assert.True(DestinationMatch.Matches(Rule("example.com"), Dest, 443, resolved));
    }

    [Fact]
    public void DomainRule_Unresolved_NeverMatches()
    {
        Assert.False(DestinationMatch.Matches(Rule("example.com"), Dest, 443, null));
        Assert.False(DestinationMatch.Matches(Rule("example.com"), Dest, 443, Array.Empty<IPAddress>()));
    }

    [Fact]
    public void Ipv6Destination_NeverMatches()
    {
        var v6 = IPAddress.Parse("2001:db8::1");
        var resolved = new List<IPAddress> { IPAddress.Parse("2001:db8::1") };
        Assert.False(DestinationMatch.Matches(Rule("142.250.0.14"), v6, 443, null));
        Assert.False(DestinationMatch.Matches(Rule("example.com"), v6, 443, resolved));
    }

    [Fact]
    public void DisabledOrNullOrNullHost_NeverMatch()
    {
        Assert.False(DestinationMatch.Matches(null, Dest, 443, null));
        Assert.False(DestinationMatch.Matches(Rule("142.250.0.14", enabled: false), Dest, 443, null));
        Assert.False(DestinationMatch.Matches(Rule(""), Dest, 443, null));
    }
}

/// <summary>
/// Tests for <see cref="RuleEngine.DecideAsync"/>: destination rules evaluate
/// before process rules, first-match-wins within each list, domain resolution
/// through the injected resolver, and the fall-through default.
/// </summary>
public class RuleEngineDestinationTests
{
    private static readonly IPAddress Dest = IPAddress.Parse("1.2.3.4");

    private sealed class FakeResolver(IReadOnlyDictionary<string, IPAddress[]>? answers = null)
        : IDestinationResolver
    {
        public int Calls;

        public Task<IReadOnlyList<IPAddress>?> ResolveAsync(string host, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            if (answers is not null && answers.TryGetValue(host, out var found))
                return Task.FromResult<IReadOnlyList<IPAddress>?>(found);
            return Task.FromResult<IReadOnlyList<IPAddress>?>(null);
        }
    }

    private static ApplicationRule ProcessRule(
        string name, ProxyMode mode = ProxyMode.Proxy, bool enabled = true, string? proxyName = null)
    {
        return new ApplicationRule
        {
            ExecutableName = name,
            Enabled = enabled,
            Mode = mode,
            ProxyName = proxyName
        };
    }

    private static IpDomainRule DestRule(
        string host, int? port = null, ProxyMode mode = ProxyMode.Proxy,
        bool enabled = true, string? proxyName = null)
    {
        return new IpDomainRule { Host = host, Port = port, Enabled = enabled, Mode = mode, ProxyName = proxyName };
    }

    [Fact]
    public async Task DestinationRule_OverridesProcessRule()
    {
        // chrome.exe is pinned to Proxy, but 1.2.3.4 must stay Direct.
        var decision = await RuleEngine.DecideAsync(
            [DestRule("1.2.3.4", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", @"C:\app\chrome.exe",
            Dest, 443, null);

        Assert.Equal(ProxyMode.Direct, decision.Mode);
    }

    [Fact]
    public async Task NoDestinationMatch_FallsThroughToProcessRules()
    {
        var decision = await RuleEngine.DecideAsync(
            [DestRule("9.9.9.9", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", null,
            Dest, 443, null);

        Assert.Equal(ProxyMode.Proxy, decision.Mode);
    }

    [Fact]
    public async Task DestinationRule_CarriesProxyPin()
    {
        var decision = await RuleEngine.DecideAsync(
            [DestRule("1.2.3.4", proxyName: "Work")],
            Array.Empty<ApplicationRule>(),
            "any.exe", null,
            Dest, 443, null);

        Assert.Equal(ProxyMode.Proxy, decision.Mode);
        Assert.Equal("Work", decision.ProxyName);
    }

    [Fact]
    public async Task FirstDestinationRule_Wins()
    {
        var decision = await RuleEngine.DecideAsync(
            new List<IpDomainRule>
            {
                DestRule("1.2.3.4", mode: ProxyMode.Direct),
                DestRule("1.2.3.4", mode: ProxyMode.Proxy, proxyName: "Other")
            },
            Array.Empty<ApplicationRule>(),
            "any.exe", null,
            Dest, 443, null);

        Assert.Equal(ProxyMode.Direct, decision.Mode);
    }

    [Fact]
    public async Task DisabledDestinationRule_IsSkipped()
    {
        var decision = await RuleEngine.DecideAsync(
            [DestRule("1.2.3.4", mode: ProxyMode.Direct, enabled: false)],
            Array.Empty<ApplicationRule>(),
            "any.exe", null,
            Dest, 443, null);

        // No enabled rule matched → default Direct with no pin.
        Assert.Equal(RoutingDecision.Direct, decision);
    }

    [Fact]
    public async Task PortMismatch_RuleDoesNotMatch()
    {
        var decision = await RuleEngine.DecideAsync(
            [DestRule("1.2.3.4", port: 80, mode: ProxyMode.Direct)],
            Array.Empty<ApplicationRule>(),
            "any.exe", null,
            Dest, 443, null);

        Assert.Equal(RoutingDecision.Direct, decision);
    }

    [Fact]
    public async Task DomainRule_ResolvesThroughResolver()
    {
        var resolver = new FakeResolver(new Dictionary<string, IPAddress[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["example.com"] = [Dest]
        });

        var decision = await RuleEngine.DecideAsync(
            [DestRule("example.com", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", null,
            Dest, 443, resolver);

        Assert.Equal(ProxyMode.Direct, decision.Mode);
        Assert.Equal(1, resolver.Calls);
    }

    [Fact]
    public async Task DomainRule_Unresolvable_FallsThroughToProcessRules()
    {
        var resolver = new FakeResolver(); // always fails

        var decision = await RuleEngine.DecideAsync(
            [DestRule("example.com", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", null,
            Dest, 443, resolver);

        Assert.Equal(ProxyMode.Proxy, decision.Mode);
    }

    [Fact]
    public async Task DomainRule_WithoutResolver_NeverMatches()
    {
        var decision = await RuleEngine.DecideAsync(
            [DestRule("example.com", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", null,
            Dest, 443, null);

        Assert.Equal(ProxyMode.Proxy, decision.Mode);
    }

    [Fact]
    public async Task Ipv6Destination_SkipsDestinationRules()
    {
        var resolver = new FakeResolver();

        var decision = await RuleEngine.DecideAsync(
            [DestRule("1.2.3.4", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", null,
            IPAddress.Parse("2001:db8::1"), 443, resolver);

        Assert.Equal(ProxyMode.Proxy, decision.Mode);
        Assert.Equal(0, resolver.Calls); // no resolution attempted for IPv6
    }

    [Fact]
    public async Task NullDestination_GoesStraightToProcessRules()
    {
        var decision = await RuleEngine.DecideAsync(
            [DestRule("1.2.3.4", mode: ProxyMode.Direct)],
            [ProcessRule("chrome.exe", ProxyMode.Proxy)],
            "chrome.exe", null,
            null, 0, null);

        Assert.Equal(ProxyMode.Proxy, decision.Mode);
    }

    [Fact]
    public async Task Cancellation_PropagatesFromResolver()
    {
        var cts = new CancellationTokenSource();
        cts.Cancel();

        // WaitAsync surfaces cancellation as TaskCanceledException — a subclass
        // of OperationCanceledException, so the engine contract holds.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            RuleEngine.DecideAsync(
                [DestRule("example.com", mode: ProxyMode.Direct)],
                Array.Empty<ApplicationRule>(),
                "any.exe", null,
                Dest, 443,
                new CancellingResolver(cts.Token),
                cts.Token));
    }

    private sealed class CancellingResolver(CancellationToken ct) : IDestinationResolver
    {
        public Task<IReadOnlyList<IPAddress>?> ResolveAsync(string host, CancellationToken token) =>
            Task.FromCanceled<IReadOnlyList<IPAddress>?>(ct);
    }
}

/// <summary>
/// Validation tests for <see cref="IpDomainRule"/>: host syntax, port range,
/// mode, proxy pins, duplicates, and full-document dangling-pin checks.
/// </summary>
public class IpDomainRuleValidationTests
{
    private static IpDomainRule Rule(
        string host, int? port = null, ProxyMode mode = ProxyMode.Proxy,
        bool enabled = true, string? proxyName = null)
    {
        return new IpDomainRule { Host = host, Port = port, Mode = mode, Enabled = enabled, ProxyName = proxyName };
    }

    [Fact]
    public void ValidRule_Passes()
    {
        Assert.True(ConfigurationValidator.Validate(Rule("1.2.3.4:443")).IsValid);
        Assert.True(ConfigurationValidator.Validate(Rule("example.com:8443")).IsValid);
        Assert.True(ConfigurationValidator.Validate(Rule("example.com")).IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("::1")]           // IPv6 unsupported
    [InlineData("1.2.3.4:99999")] // port out of range
    [InlineData("not a domain!")]
    public void InvalidHost_Fails(string host)
    {
        Assert.False(ConfigurationValidator.Validate(Rule(host)).IsValid);
    }

    [Fact]
    public void OutOfRangeExplicitPort_Fails()
    {
        Assert.False(ConfigurationValidator.Validate(Rule("1.2.3.4", port: 0)).IsValid);
        Assert.False(ConfigurationValidator.Validate(Rule("1.2.3.4", port: 70000)).IsValid);
    }

    [Fact]
    public void UndefinedMode_Fails()
    {
        Assert.False(ConfigurationValidator.Validate(Rule("1.2.3.4", mode: (ProxyMode)99)).IsValid);
    }

    [Fact]
    public void BlankProxyPin_Fails()
    {
        Assert.False(ConfigurationValidator.Validate(Rule("1.2.3.4", proxyName: "  ")).IsValid);
    }

    [Fact]
    public void DuplicatesAndConflicts_AreReported()
    {
        var result = ConfigurationValidator.ValidateIpDomainRules(new List<IpDomainRule>
        {
            Rule("1.2.3.4", mode: ProxyMode.Direct),
            Rule("1.2.3.4", mode: ProxyMode.Proxy)
        });

        Assert.False(result.IsValid);
        // Identical identities report the duplicate; the conflict branch only
        // fires for rules that never shared an identity — mirroring the
        // process-rule ValidateRules behavior.
        Assert.Contains(result.Errors, e => e.Contains("Duplicate IP/domain rule"));
    }

    [Fact]
    public void SameHostDifferentPort_IsNotADuplicate()
    {
        var result = ConfigurationValidator.ValidateIpDomainRules(new List<IpDomainRule>
        {
            Rule("1.2.3.4", port: 80),
            Rule("1.2.3.4", port: 443)
        });

        Assert.True(result.IsValid);
    }

    [Fact]
    public void FullDocument_DanglingPin_IsReported()
    {
        var settings = new ApplicationSettings
        {
            Proxy = ValidProxy(),
            IpDomainRules = [Rule("1.2.3.4", proxyName: "Missing")]
        };

        var result = ConfigurationValidator.Validate(settings);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors,
            e => e.Contains("IP/domain rule '1.2.3.4'") && e.Contains("'Missing'"));
    }

    [Fact]
    public void FullDocument_ValidDestinationRules_Pass()
    {
        var settings = new ApplicationSettings
        {
            Proxy = ValidProxy(),
            IpDomainRules = [Rule("example.com:443", proxyName: "Saved")]
        };
        settings.Proxies.Add(new ProxyConfiguration
        {
            Name = "Saved",
            Host = "10.0.0.1",
            Port = 1080,
            Protocol = ProxyProtocol.Socks5,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        });

        Assert.True(ConfigurationValidator.Validate(settings).IsValid);
    }

    private static ProxyConfiguration ValidProxy()
    {
        return new ProxyConfiguration
        {
            Name = "Active",
            Host = "10.0.0.1",
            Port = 1080,
            Protocol = ProxyProtocol.Socks5,
            AuthenticationType = ProxyAuthenticationType.None,
            Enabled = true
        };
    }
}
