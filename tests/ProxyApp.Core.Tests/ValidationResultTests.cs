using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for the <see cref="ValidationResult"/> type itself.
/// </summary>
public class ValidationResultTests
{
    [Fact]
    public void Success_IsValid_AndHasNoErrors()
    {
        Assert.True(ValidationResult.Success.IsValid);
        Assert.Empty(ValidationResult.Success.Errors);
    }

    [Fact]
    public void Success_IsASingleton()
    {
        Assert.Same(ValidationResult.Success, ValidationResult.Success);
    }

    [Fact]
    public void Fail_WithSingleError_IsInvalid_AndReportsIt()
    {
        var result = ValidationResult.Fail("Something is wrong.");

        Assert.False(result.IsValid);
        Assert.Equal(new[] { "Something is wrong." }, result.Errors);
    }

    [Fact]
    public void Fail_WithMultipleErrors_PreservesOrder()
    {
        var result = ValidationResult.Fail("First.", "Second.", "Third.");

        Assert.Equal(new[] { "First.", "Second.", "Third." }, result.Errors);
    }

    [Fact]
    public void Fail_WithNoErrors_Throws()
    {
        // A failed result must describe at least one real problem; the
        // "invalid with no errors" state must be impossible to construct.
        Assert.Throws<ArgumentException>(() => ValidationResult.Fail());
    }

    [Fact]
    public void Fail_WithBlankError_Throws()
    {
        // A failed result must describe at least one real problem. Null input is
        // rejected by the null guard; blank strings are rejected explicitly.
        Assert.Throws<ArgumentNullException>(() => ValidationResult.Fail(null!));
        Assert.Throws<ArgumentException>(() => ValidationResult.Fail(""));
        Assert.Throws<ArgumentException>(() => ValidationResult.Fail("   "));
    }

    [Fact]
    public void Errors_AreNotMutablyExposed()
    {
        // The result copies its input, so the caller's original array is never
        // aliased. Mutating the source array after Fail() must not change the
        // result's reported errors.
        var source = new[] { "First.", "Second." };
        var result = ValidationResult.Fail(source);
        source[0] = "Mutated.";

        Assert.Equal(new[] { "First.", "Second." }, result.Errors);
    }

    [Fact]
    public void Errors_AreRepeatedCallsConsistent()
    {
        var result = ValidationResult.Fail("Only.");

        Assert.Same(result.Errors, result.Errors);
    }
}