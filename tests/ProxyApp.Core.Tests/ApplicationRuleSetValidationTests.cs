using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for rule-set validation: multiple rules, ordering, duplicates, and
/// conflicts (<see cref="ConfigurationValidator.ValidateRules"/>).
/// </summary>
public class ApplicationRuleSetValidationTests
{
    private static ApplicationRule Rule(string name, ProxyMode mode = ProxyMode.Proxy, bool enabled = true)
    {
        return new ApplicationRule
        {
            ExecutableName = name,
            ExecutablePath = null,
            Enabled = enabled,
            Mode = mode
        };
    }

    [Fact]
    public void MultipleDistinctRules_AreValid()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe"),
            Rule("firefox.exe", ProxyMode.Direct),
            Rule("game.exe", ProxyMode.Proxy, enabled: false)
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void EmptyRuleSet_IsValid()
    {
        var result = ConfigurationValidator.ValidateRules(new List<ApplicationRule>());

        Assert.True(result.IsValid);
    }

    [Fact]
    public void DuplicateRules_AreInvalid()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe"),
            Rule("chrome.exe")
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("duplicate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DuplicateRules_DifferingByCase_AreInvalid()
    {
        // Executable-name matching is case-insensitive, so "Chrome.EXE" and
        // "chrome.exe" are the same rule target.
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe"),
            Rule("Chrome.EXE")
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void ConflictingRules_SameExecutable_AreInvalid()
    {
        // Two rules for the same executable with different modes is ambiguous.
        // The duplicate rule is reported first (evaluation order); whether the
        // message says "duplicate" or "conflicting", the set must be rejected.
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe", ProxyMode.Proxy),
            Rule("chrome.exe", ProxyMode.Direct)
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.False(result.IsValid);
        Assert.Contains(
            result.Errors,
            e => e.Contains("duplicate", StringComparison.OrdinalIgnoreCase) ||
                 e.Contains("conflicting", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void DisabledAndEnabledRule_SameExecutable_AreInvalid()
    {
        // Even when one rule is disabled, two rules for the same executable are
        // ambiguous; the enabled/disabled flag is not a mode selector.
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe", ProxyMode.Proxy, enabled: false),
            Rule("chrome.exe", ProxyMode.Direct, enabled: true)
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void InvalidRule_WithinSet_IsReported()
    {
        var rules = new List<ApplicationRule>
        {
            Rule("chrome.exe"),
            new ApplicationRule { ExecutableName = "", Mode = ProxyMode.Proxy }
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("executable name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NullRule_WithinSet_IsReported()
    {
        var rules = new List<ApplicationRule> { Rule("chrome.exe"), null! };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("null", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidationOrder_IsPreserved()
    {
        // Errors are returned in the order the rules were evaluated, so callers
        // can point the user at the first problem.
        var rules = new List<ApplicationRule>
        {
            new ApplicationRule { ExecutableName = "", Mode = ProxyMode.Proxy },
            Rule("firefox.exe")
        };

        var result = ConfigurationValidator.ValidateRules(rules);

        Assert.Equal("Executable name must not be empty.", result.Errors[0]);
    }
}