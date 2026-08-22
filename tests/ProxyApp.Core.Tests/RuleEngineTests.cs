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
    public void RuleMatchesByName_EvenWhenPathKnown()
    {
        // A rule with only an ExecutableName matches when the process's
        // ExecutableName equals it, regardless of the (non-null) process path —
        // the rule needs no path to match.
        var rules = new List<ApplicationRule> { Rule("curl.exe", ProxyMode.Proxy) };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "curl.exe", @"C:\Tools\curl.exe"));
    }

    [Fact]
    public void RuleMatchesByPath_WhenNameDiffers()
    {
        // A rule may match by its ExecutablePath even when the process name does
        // not match the rule's ExecutableName (e.g. a renamed copy of the exe).
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe", ProxyMode.Proxy, path: @"C:\Program Files\Chrome\chrome.exe")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\Program Files\Chrome\chrome.exe"));
    }

    [Fact]
    public void FirstRuleWins_EvenIfLaterRuleMatchesByPath()
    {
        // Order is authoritative: the first enabled matching rule wins, whether
        // it matched by name or by path.
        var rules = new List<ApplicationRule>
        {
            Rule("curl.exe", ProxyMode.Direct),
            Rule("chrome.exe", ProxyMode.Proxy, path: @"C:\Tools\curl.exe")
        };
        // curl.exe matches the first rule by name (Direct); the later path rule
        // is never reached.
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "curl.exe", @"C:\Tools\curl.exe"));
    }

    // ── Folder/bundle rule matching (Phase 10) ──

    private static ApplicationRule FolderRule(string folder, ProxyMode mode = ProxyMode.Proxy, bool enabled = true)
    {
        return new ApplicationRule
        {
            FolderPath = folder,
            Enabled = enabled,
            Mode = mode
        };
    }

    [Fact]
    public void FolderRule_MatchesExecutableUnderFolder()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\Apps\myapp.exe"));
    }

    [Fact]
    public void FolderRule_MatchesNestedExecutable()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "child.exe", @"C:\Apps\sub\child.exe"));
    }

    [Fact]
    public void FolderRule_DoesNotMatchPathOutsideFolder()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps")
        };
        Assert.Equal(ProxyMode.Direct,
            RuleEngine.Evaluate(rules, "other.exe", @"C:\Other\other.exe"));
    }

    [Fact]
    public void FolderRule_Boundary_DoesNotMatchSimilarPrefixFolder()
    {
        // C:\prog must NOT match C:\programs — requires a directory boundary.
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\prog")
        };
        Assert.Equal(ProxyMode.Direct,
            RuleEngine.Evaluate(rules, "app.exe", @"C:\programs\app.exe"));
    }

    [Fact]
    public void FolderRule_TrailingSeparator_Normalized()
    {
        // A trailing separator on the folder is normalized away; the boundary
        // check still applies.
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps\")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\Apps\myapp.exe"));
    }

    [Fact]
    public void FolderRule_IsCaseInsensitive()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"c:\apps")
        };
        Assert.Equal(ProxyMode.Proxy,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\APPS\MyApp.exe"));
    }

    [Fact]
    public void DisabledFolderRule_IsSkipped()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps", ProxyMode.Proxy, enabled: false)
        };
        Assert.Equal(ProxyMode.Direct,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\Apps\myapp.exe"));
    }

    [Fact]
    public void FolderRule_DoesNotMatchWhenProcessPathUnknown()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps")
        };
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, "myapp.exe", null));
    }

    [Fact]
    public void FolderRule_ParticipatesInListOrderPrecedence()
    {
        // First enabled matching rule wins, whether it matched by name, path,
        // or folder. A Direct folder rule ahead of a Proxy name rule wins.
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps", ProxyMode.Direct),
            Rule("myapp.exe", ProxyMode.Proxy)
        };
        Assert.Equal(ProxyMode.Direct,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\Apps\myapp.exe"));
    }

    [Fact]
    public void NameRule_ParticipatesInListOrderPrecedence_OverFolderRule()
    {
        // A name rule ahead of a folder rule wins.
        var rules = new List<ApplicationRule>
        {
            Rule("myapp.exe", ProxyMode.Direct),
            FolderRule(@"C:\Apps", ProxyMode.Proxy)
        };
        Assert.Equal(ProxyMode.Direct,
            RuleEngine.Evaluate(rules, "myapp.exe", @"C:\Apps\myapp.exe"));
    }

    [Fact]
    public void NoMatchingFolderRule_ReturnsDirect()
    {
        var rules = new List<ApplicationRule>
        {
            FolderRule(@"C:\Apps")
        };
        Assert.Equal(ProxyMode.Direct,
            RuleEngine.Evaluate(rules, "myapp.exe", @"D:\Apps\myapp.exe"));
    }

    [Fact]
    public void NullProcessName_WithNameRule_ReturnsDirect()
    {
        var rules = new List<ApplicationRule> { Rule("curl.exe") };
        // No process name known → no name match; path is null → no match.
        Assert.Equal(ProxyMode.Direct, RuleEngine.Evaluate(rules, null, null));
    }
}
