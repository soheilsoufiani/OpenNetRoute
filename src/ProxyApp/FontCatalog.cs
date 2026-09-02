using System.Windows.Media;
using ProxyApp.Core.Configuration;

namespace ProxyApp;

/// <summary>
/// Resolves a persisted UI-font key (<see cref="UiFontCatalog"/>) into the
/// WPF <see cref="FontFamily"/> that is actually rendered.
///
/// Bundled families are embedded TTFs under Assets/Fonts (one folder per
/// family). The two-argument FontFamily constructor with the folder-anchored
/// pack base URI makes WPF load every face in that folder into ONE family, so
/// the real Regular and Bold faces resolve (no synthetic/fake bold). Glyphs
/// the embedded face does not cover fall through to WPF's global fallback.
/// The system key resolves to plain "Segoe UI".
///
/// The tray icon's WinForms context menu is intentionally left on the OS menu
/// font: WinForms cannot consume WPF-embedded fonts without a
/// PrivateFontCollection temp-file dance, and the tray strip is a native
/// shell surface (documented in README → Fonts).
/// </summary>
public static class FontCatalog
{
    /// <summary>
    /// The WPF family for a settings key: the embedded family (all faces in
    /// its folder) or plain Segoe UI for the system/unknown key. Never
    /// throws — unknown keys fall back by design.
    /// </summary>
    /// <remarks>
    /// Resolution uses the two-argument <see cref="FontFamily(Uri, string)"/>
    /// constructor — the only form verified at runtime to resolve EMBEDDED
    /// fonts (the single-string form silently falls back to the system font).
    /// Base = the Assets/Fonts folder, relative = "&lt;Folder&gt;/#&lt;Family&gt;":
    /// WPF loads every face in that folder into ONE family, so the real
    /// Regular/Bold faces resolve (no synthetic bold). Requires a live
    /// Application — always true here, since every call runs on the UI thread
    /// after App.OnStartup has created it.
    /// </remarks>
    public static FontFamily ResolveFamily(string? key)
    {
        if (!UiFontCatalog.IsBundled(key))
            return new FontFamily("Segoe UI");

        // Folder name = family name without spaces
        // ("Geist Mono" → Assets/Fonts/GeistMono/).
        var folder = key!.Replace(" ", string.Empty);
        var fontsRoot = new Uri($"pack://application:,,,/ProxyApp;component/Assets/Fonts/");
        return new FontFamily(fontsRoot, $"{folder}/#{key}");
    }
}