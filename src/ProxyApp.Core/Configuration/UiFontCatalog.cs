namespace ProxyApp.Core.Configuration;

/// <summary>
/// The UI font families bundled with the application, plus the persistence
/// contract for the selected one. Keys are the font family names exactly as
/// WPF resolves them from the embedded faces; the empty string is the
/// reserved key for the Windows system font (Segoe UI), which is NOT bundled.
///
/// Every bundled family ships under the SIL Open Font License 1.1 (license
/// text next to the faces in Assets/Fonts/&lt;family&gt;/OFL.txt), which
/// permits redistribution inside an open-source application.
/// </summary>
public static class UiFontCatalog
{
    /// <summary>Persisted key meaning "use the Windows system font" (not bundled).</summary>
    public const string SystemKey = "";

    /// <summary>
    /// The family selected on first run / when no preference exists: the
    /// app's identity face. Also the fallback for unknown persisted values.
    /// </summary>
    public const string DefaultKey = "Geist";

    /// <summary>Bundled families in selector order. Geist first: the default face.</summary>
    public static IReadOnlyList<string> BundledKeys { get; } =
    [
        "Geist",
        "Geist Mono",
        "JetBrains Mono",
        "Plus Jakarta Sans",
        "Public Sans",
        "Space Grotesk"
    ];

    /// <summary>True when <paramref name="key"/> names a bundled family (exact, case-sensitive).</summary>
    public static bool IsBundled(string? key) =>
        !string.IsNullOrEmpty(key) && BundledKeys.Contains(key, StringComparer.Ordinal);

    /// <summary>
    /// Maps any persisted value onto a valid key: bundled keys pass through,
    /// everything else (null, empty, hand-edited files, families removed in
    /// later versions) becomes the system font — a cosmetic preference can
    /// never crash the app or block engine startup.
    /// </summary>
    public static string Normalize(string? key) => IsBundled(key) ? key! : SystemKey;

    /// <summary>
    /// Selector-order index of a bundled key (exact match); -1 when the key
    /// is not bundled (including the system key).
    /// </summary>
    public static int IndexOf(string? key)
    {
        if (!IsBundled(key))
            return -1;

        for (var i = 0; i < BundledKeys.Count; i++)
        {
            if (string.Equals(BundledKeys[i], key, StringComparison.Ordinal))
                return i;
        }

        return -1;
    }
}