using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for <see cref="ConfigurationValidator.Validate(ApplicationRule)"/>.
/// </summary>
public class ApplicationRuleValidationTests
{
    private static ApplicationRule ValidRule()
    {
        return new ApplicationRule
        {
            ExecutableName = "chrome.exe",
            ExecutablePath = @"C:\Program Files\Google\Chrome\Application\chrome.exe",
            Enabled = true,
            Mode = ProxyMode.Proxy
        };
    }

    [Fact]
    public void ValidRule_IsValid()
    {
        var result = ConfigurationValidator.Validate(ValidRule());

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public void Rule_WithoutExecutablePath_IsValid()
    {
        var rule = ValidRule();
        rule.ExecutablePath = null;

        Assert.True(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void Rule_WithEmptyExecutablePath_IsValid()
    {
        var rule = ValidRule();
        rule.ExecutablePath = "";

        Assert.True(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void Rule_InDirectMode_IsValid()
    {
        var rule = ValidRule();
        rule.Mode = ProxyMode.Direct;

        Assert.True(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void Rule_Disabled_IsStillValid()
    {
        var rule = ValidRule();
        rule.Enabled = false;

        Assert.True(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void EmptyExecutableName_IsInvalid()
    {
        var rule = ValidRule();
        rule.ExecutableName = "";

        var result = ConfigurationValidator.Validate(rule);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("executable name", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void NullExecutableName_IsInvalid()
    {
        var rule = ValidRule();
        rule.ExecutableName = null;

        Assert.False(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void WhitespaceExecutableName_IsInvalid()
    {
        var rule = ValidRule();
        rule.ExecutableName = "   ";

        Assert.False(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void OverlongExecutableName_IsInvalid()
    {
        var rule = ValidRule();
        rule.ExecutableName = new string('a', ConfigurationValidator.MaxExecutableNameLength + 1);

        var result = ConfigurationValidator.Validate(rule);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("255", StringComparison.Ordinal));
    }

    [Fact]
    public void ExecutableNameWithPathSeparator_IsInvalid()
    {
        // An executable *name* must not contain path separators; that is what
        // ExecutablePath is for.
        var rule = ValidRule();
        rule.ExecutableName = @"C:\tools\chrome.exe";

        var result = ConfigurationValidator.Validate(rule);

        Assert.False(result.IsValid);
    }

    [Fact]
    public void ExecutableNameWithWildcard_IsInvalid()
    {
        var rule = ValidRule();
        rule.ExecutableName = "chrome*.exe";

        Assert.False(ConfigurationValidator.Validate(rule).IsValid);
    }

    [Fact]
    public void UnsupportedMode_IsInvalid()
    {
        var rule = ValidRule();
        rule.Mode = (ProxyMode)999;

        var result = ConfigurationValidator.Validate(rule);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("not supported", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ExecutablePathWithNullCharacter_IsInvalid()
    {
        var rule = ValidRule();
        // A real embedded NUL byte, not the two-character escape sequence "\0".
        rule.ExecutablePath = @"C:\Program Files\app.exe" + '\0';

        var result = ConfigurationValidator.Validate(rule);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("null character", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void OverlongExecutablePath_IsInvalid()
    {
        var rule = ValidRule();
        rule.ExecutablePath = new string('a', ConfigurationValidator.MaxExecutablePathLength + 1);

        var result = ConfigurationValidator.Validate(rule);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("1024", StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_DoesNotMutate_Rule()
    {
        var rule = ValidRule();
        var name = rule.ExecutableName;

        _ = ConfigurationValidator.Validate(rule);

        Assert.Equal(name, rule.ExecutableName);
    }
}