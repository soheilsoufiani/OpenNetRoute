using ProxyApp.Core.Configuration;
using ProxyApp.Core.Rules;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for <see cref="RuleEngine.Evaluate"/>: first-enabled-match-wins,
/// name/path matching, disabled-rule ignoring, and the no-match default.
/// </summary>
public class RuleEngineTests
{
    private static ApplicationRule Rule(string name, ProxyMode mode = ProxyMode.Proxy, bool enabled = true,
        string? path = null)
    {
        return new ApplicationRule
        {
            ExecutableName = name,
            ExecutablePath = path,
            Enabled = enabled,
            Mode = mode
        };
    }

    [Fact]
    public void EmptyRules_ReturnsDirect()
    {
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(Array.Empty<ApplicationRule>(), "curl.exe", null));
    }

    [Fact]
    public void NoMatchingRule_ReturnsDirect()
    {
        var rules = new List<ApplicationRule> { Rule("chrome.exe") };
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "firefox.exe", null));
    }

    [Fact]
    public void MatchingName_ReturnsProxy()
    {
        var rules = new List<ApplicationRule> { Rule("curl.exe") };
        Assert.Equal(ProxyMode.Proxy, RuleEngine.Evaluate(rules, "curl.exe", null));
    }

    [Fact]
    public void NameMatch_IsCaseInsensitive()
    {
        var rules = new List<ApplicationRule> { Rule("CURL.EXE") };
        Assert.Equal(ProxyMode.Proxy, RuleEngine.Evaluate(rules, "curl.exe", null));
    }

    [Fact]
    public void MatchingPath_ReturnsMode()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe", ProxyMode.Proxy, path: @"C:\Program Files\Chrome\chrome.exe")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "chrome.exe", @"C:\Program Files\Chrome\chrome.exe"));
    }

    [Fact]
    public void PathMatch_IsCaseInsensitive()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe", ProxyMode.Proxy, path: @"c:\program files\chrome\chrome.exe")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "chrome.exe", @"C:\Program Files\Chrome\chrome.exe"));
    }

    [Fact]
    public void DirectMode_Rule_ReturnsDirect()
    {
        var rules = new List<ApplicationRule> { Rule("game.exe", ProxyMode.Direct) };
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "game.exe", null));
    }

    [Fact]
    public void DisabledRule_IsIgnored()
    {
        var rules = new List<ApplicationRule> { Rule("curl.exe", ProxyMode.Proxy, enabled: false) };
        // Disabled rule matches nothing → Direct.
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "curl.exe", null));
    }

    [Fact]
    public void FirstEnabledMatchWins()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("curl.exe", ProxyMode.Direct),
            Rule("curl.exe", ProxyMode.Proxy)
        };
        // First match (Direct) wins even though a later Proxy rule exists.
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "curl.exe", null));
    }

    [Fact]
    public void DisabledRuleDoesNotBlockLaterEnabledRule()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("curl.exe", ProxyMode.Direct, enabled: false),
            Rule("curl.exe", ProxyMode.Proxy)
        };
        // First disabled rule is skipped; the Proxy rule applies.
        Assert.Equal(ProxyMode.Proxy, RuleEngine.Evaluate(rules, "curl.exe", null));
    }

    [Fact]
    public void RuleForOtherName_DoesNotMatch()
    {
        var rules = new List<ApplicationRule> { Rule("chrome.exe", ProxyMode.Proxy) };
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "msedge.exe", null));
    }

    [Fact]
    public void NullProcessName_WithNameRule_ReturnsDirect()
    {
        var rules = new List<ApplicationRule> { Rule("curl.exe") };
        // No process name known → no name match; path is null → no match.
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, null, null));
    }
}
