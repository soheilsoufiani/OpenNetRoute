using ProxyApp.Core.Configuration;
using ProxyApp.Core.Persistence;

namespace ProxyApp.Core.Tests;

/// <summary>
/// The UI font catalog: key normalization (a cosmetic preference must never
/// crash or warn on unknown values), persistence round-trip of the selected
/// font, and the legacy-document default. WPF-side rendering (pack-URI family
/// grouping) is verified at runtime — Core covers the pure key contract.
/// </summary>
public class UiFontCatalogTests
{
    [Theory]
    [InlineData(null, "")]
    [InlineData("", "")]
    [InlineData("Segoe UI", "")] // the system font is NOT a bundled key
    [InlineData("Comic Sans MS", "")]
    [InlineData("Geist", "Geist")]
    [InlineData("Geist Mono", "Geist Mono")]
    public void Normalize_MapsUnknownValuesOntoTheSystemFont(string? input, string expected)
        => Assert.Equal(expected, UiFontCatalog.Normalize(input));

    [Fact]
    public void BundledKeys_StartWithGeist_AndResolveCaseSensitively()
    {
        Assert.Equal(UiFontCatalog.DefaultKey, UiFontCatalog.BundledKeys[0]);
        Assert.Equal("Geist", UiFontCatalog.BundledKeys[0]);
        Assert.All(UiFontCatalog.BundledKeys, k => Assert.True(UiFontCatalog.IsBundled(k)));
        Assert.False(UiFontCatalog.IsBundled("geist")); // exact family names only
        Assert.False(UiFontCatalog.IsBundled(UiFontCatalog.SystemKey));
    }

    [Fact]
    public void Settings_RoundTrip_PreservesAppFontKey()
    {
        var path = Path.Combine(Path.GetTempPath(), "myproxy-tests", Guid.NewGuid().ToString("N"), "settings.json");
        try
        {
            var store = new JsonApplicationSettingsStore(path);
            var original = new ApplicationSettings
            {
                Preferences = new UiPreferences { AppFontKey = "Space Grotesk" }
            };

            store.Save(original);

            Assert.Equal("Space Grotesk", store.Load().Preferences.AppFontKey);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); }
            catch (IOException) { }
        }
    }

    [Fact]
    public void Settings_LegacyDocumentWithoutFontKey_DefaultsToGeist()
    {
        var path = Path.Combine(Path.GetTempPath(), "myproxy-tests", Guid.NewGuid().ToString("N"), "settings.json");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllText(path, """{ "Proxies": [], "Preferences": { "Theme": 1 } }""");
        try
        {
            var loaded = new JsonApplicationSettingsStore(path).Load();

            Assert.Equal(UiFontCatalog.DefaultKey, loaded.Preferences.AppFontKey);
        }
        finally
        {
            try { Directory.Delete(Path.GetDirectoryName(path)!, recursive: true); }
            catch (IOException) { }
        }
    }
}