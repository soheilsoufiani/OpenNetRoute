namespace ProxyApp.Core.Validation;

/// <summary>
/// The outcome of validating a configuration object.
///
/// Intentionally not an exception type: validation of normal user input is an
/// expected flow, not a failure of the program. Throwing for every invalid field
/// would force callers into try/catch for routine input handling.
/// </summary>
public sealed class ValidationResult
{
    private readonly IReadOnlyList<string> _errors;

    /// <summary>An empty result representing a valid configuration.</summary>
    public static ValidationResult Success { get; } = new(Array.Empty<string>());

    private ValidationResult(IReadOnlyList<string> errors)
    {
        _errors = errors;
    }

    /// <summary>True when the configuration is valid (no errors).</summary>
    public bool IsValid => _errors.Count == 0;

    /// <summary>
    /// Human-readable validation errors, in the order they were produced.
    /// Empty when <see cref="IsValid"/> is true.
    /// </summary>
    public IReadOnlyList<string> Errors => _errors;

    /// <summary>
    /// Creates a failed result from one or more errors.
    /// </summary>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="errors"/> is null, empty, or contains a blank entry.
    /// A failed result must describe at least one real problem; this prevents the
    /// inconsistent state "invalid with no errors" from being constructed.
    /// </exception>
    public static ValidationResult Fail(params string[] errors)
    {
        ArgumentNullException.ThrowIfNull(errors);

        if (errors.Length == 0)
            throw new ArgumentException("A failed ValidationResult requires at least one error.", nameof(errors));

        foreach (var error in errors)
        {
            if (string.IsNullOrWhiteSpace(error))
                throw new ArgumentException("Validation errors must not be blank.", nameof(errors));
        }

        return new ValidationResult(errors.ToArray());
    }
}