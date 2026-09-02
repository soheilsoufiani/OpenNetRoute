using ProxyApp.Core.Configuration;
using ProxyApp.Core.Persistence;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Round-trip and safety tests for the JSON settings store: atomic saves,
/// password protection at rest, corrupt-file recovery, and validation of the
/// extended persistence model (profiles, selection, preferences).
/// </summary>
public class SettingsPersistenceTests : IDisposable
{
    private readonly string _path;

    public SettingsPersistenceTests()
    {
        _path = Path.Combine(Path.GetTempPath(), "myproxy-tests", Guid.NewGuid().ToString("N"), "settings.json");
    }

    public void Dispose()
    {
        try { Directory.Delete(Path.GetDirectoryName(_path)!, recursive: true); }
        catch (IOException) { }
    }

    private JsonApplicationSettingsStore NewStore() => new(_path);

    [Fact]
    public void SaveThenLoad_RoundTripsTrayPreferences()
    {
        var store = NewStore();
        var original = new ApplicationSettings
        {
            Preferences = new UiPreferences
            {
                EnableTrayIcon = false,
                StartMinimizedToTray = true,
                MinimizeToTrayInsteadOfTaskbar = false,
                CloseButton = CloseButtonBehavior.Exit
            }
        };

        store.Save(original);
        var loaded = store.Load();

        Assert.False(loaded.Preferences.EnableTrayIcon);
        Assert.True(loaded.Preferences.StartMinimizedToTray);
        Assert.False(loaded.Preferences.MinimizeToTrayInsteadOfTaskbar);
        Assert.Equal(CloseButtonBehavior.Exit, loaded.Preferences.CloseButton);
    }

    [Fact]
    public void Load_LegacyDocumentWithoutTrayKeys_UsesTrayDefaults()
    {
        // Documents written before the tray feature exist have no tray keys;
        // absent keys must fall back to the feature defaults, never to
        // disabled/closed semantics that would strand the icon or the window.
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, """{ "Proxies": [], "Preferences": { "Theme": 1 } }""");

        var loaded = NewStore().Load();

        Assert.True(loaded.Preferences.EnableTrayIcon);
        Assert.False(loaded.Preferences.StartMinimizedToTray);
        Assert.True(loaded.Preferences.MinimizeToTrayInsteadOfTaskbar);
        Assert.Equal(CloseButtonBehavior.MinimizeToTray, loaded.Preferences.CloseButton);
    }

    [Fact]
    public void Load_MissingFile_ReturnsDefaults()
    {
        var settings = NewStore().Load();
        Assert.NotNull(settings);
        Assert.Empty(settings.Proxies);
        Assert.Equal(AppTheme.System, settings.Preferences.Theme);
    }

    [Fact]
    public void SaveThenLoad_RoundTripsEverything()
    {
        var store = NewStore();
        var original = new ApplicationSettings
        {
            Proxy = new ProxyConfiguration
            {
                Name = "Active",
                Host = "1.2.3.4",
                Port = 1080,
                Username = "u",
                Password = "p",
                AuthenticationType = ProxyAuthenticationType.UsernamePassword,
                Protocol = ProxyProtocol.Socks5,
                Enabled = true
            },
            Proxies =
            [
                new ProxyConfiguration { Name = "Home", Host = "5.6.7.8", Port = 9050, Enabled = true },
                new ProxyConfiguration
                {
                    Name = "Work", Host = "9.9.9.9", Port = 443,
                    Username = "bob", Password = "s3cret!",
                    AuthenticationType = ProxyAuthenticationType.UsernamePassword
                }
            ],
            SelectedProxyName = "Home",
            Rules =
            [
                new ApplicationRule { ExecutableName = "firefox.exe", Mode = ProxyMode.Proxy },
                new ApplicationRule { FolderPath = @"C:\Tools\Apps", Mode = ProxyMode.Direct, Enabled = true }
            ],
            LogLevel = LogLevelConfiguration.Debug,
            Preferences = new UiPreferences
            {
                Theme = AppTheme.Dark,
                AccentColorHex = "#E81123",
                TestProxyOnSave = false
            }
        };

        store.Save(original);
        var loaded = store.Load();

        Assert.Equal("Home", loaded.SelectedProxyName);
        Assert.Equal(2, loaded.Proxies.Count);
        Assert.Equal("Work", loaded.Proxies[1].Name);
        Assert.Equal(ProxyProtocol.Socks5, loaded.Proxy!.Protocol);
        Assert.Equal(LogLevelConfiguration.Debug, loaded.LogLevel);
        Assert.Equal(AppTheme.Dark, loaded.Preferences.Theme);
        Assert.Equal("#E81123", loaded.Preferences.AccentColorHex);
        Assert.False(loaded.Preferences.TestProxyOnSave);
        Assert.Equal("firefox.exe", loaded.Rules[0].ExecutableName);
        Assert.Equal(@"C:\Tools\Apps", loaded.Rules[1].FolderPath);

        // Credentials survive the round trip in memory.
        var work = loaded.Proxies.Single(p => p.Name == "Work");
        Assert.Equal("bob", work.Username);
        Assert.Equal("s3cret!", work.Password);
    }

    [Fact]
    public void PasswordIsProtectedAtRest_NotPlaintextInFile()
    {
        var store = NewStore();
        store.Save(new ApplicationSettings
        {
            Proxies = [new ProxyConfiguration
            {
                Name = "secret-profile",
                Host = "h",
                Port = 1,
                Username = "alice",
                Password = "super-secret-password",
                AuthenticationType = ProxyAuthenticationType.UsernamePassword
            }]
        });

        var json = File.ReadAllText(store.Location);
        // The raw secret must never appear on disk.
        Assert.DoesNotContain("super-secret-password", json);
        Assert.Contains("dpapi:v1:", json); // DPAPI-protected blob present
    }

    [Fact]
    public void OnlyThePasswordIsProtected_OtherFieldsStayPlaintext()
    {
        // Regression: the converter must be scoped to Password only — a global
        // string converter would also encrypt Name/Host/Username, bloating the
        // file and breaking portability of every other field.
        var store = NewStore();
        store.Save(new ApplicationSettings
        {
            Proxies = [new ProxyConfiguration
            {
                Name = "My VPS", Host = "vps.example.com", Port = 2080,
                Username = "alice", Password = "secret123",
                AuthenticationType = ProxyAuthenticationType.UsernamePassword
            }]
        });

        var json = File.ReadAllText(store.Location);
        Assert.Contains("My VPS", json);
        Assert.Contains("vps.example.com", json);
        Assert.Contains("alice", json);
        Assert.DoesNotContain("secret123", json);
        // Exactly one protected value in the file (the password).
        Assert.Single(System.Text.RegularExpressions.Regex.Matches(json, "dpapi:v1:"));
    }

    [Fact]
    public void CorruptFile_IsQuarantined_AndDefaultsReturned()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, "{ this is not json ");

        var settings = NewStore().Load();

        Assert.NotNull(settings);
        Assert.Empty(settings.Proxies);
        // The corrupt file was moved aside, not deleted — recoverable by hand.
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(_path)!, "settings.json"));
        Assert.NotEmpty(Directory.GetFiles(Path.GetDirectoryName(_path)!, "settings.json.corrupt-*"));
    }

    [Fact]
    public void Save_IsAtomic_TempFileNeverLeftBehind()
    {
        var store = NewStore();
        store.Save(new ApplicationSettings());
        store.Save(new ApplicationSettings { SelectedProxyName = null }); // second save exercises Replace path

        Assert.True(File.Exists(_path));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(_path)!, "*.tmp"));
    }

    [Fact]
    public void Save_Failure_DoesNotLeaveTempFileBehind()
    {
        // Regression: when serialization or the atomic replace fails, the
        // temp file must be cleaned up — a stale .tmp would mask future
        // corrupt-file quarantine logic.
        var store = NewStore();

        // Make the destination path a DIRECTORY so File.Replace/Move throws.
        Directory.CreateDirectory(_path);

        Assert.ThrowsAny<IOException>(() => store.Save(new ApplicationSettings()));
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(_path)!, "*.tmp"));
    }

    [Fact]
    public void Load_CorruptDpapiBlob_IsQuarantined_NotCrashed()
    {
        // A hand-tampered "dpapi:v1:" blob (non-base64) makes the converter
        // throw FormatException, which previously escaped the Load catch
        // filter and crashed startup. It must quarantine like any corruption.
        var store = NewStore();
        store.Save(new ApplicationSettings
        {
            Proxies = [new ProxyConfiguration
            {
                Name = "p", Host = "h", Port = 1, Username = "u", Password = "x",
                AuthenticationType = ProxyAuthenticationType.UsernamePassword
            }]
        });

        // Corrupt the protected blob: replace its base64 payload with junk.
        var json = File.ReadAllText(store.Location);
        var corrupted = json.Replace("dpapi:v1:", "dpapi:v1:!!!!not-base64!!!!");
        File.WriteAllText(store.Location, corrupted);

        var settings = store.Load();

        Assert.NotNull(settings);
        // Quarantined rather than returned — the file was moved aside.
        Assert.Empty(Directory.GetFiles(Path.GetDirectoryName(_path)!, "settings.json"));
        Assert.NotEmpty(Directory.GetFiles(Path.GetDirectoryName(_path)!, "settings.json.corrupt-*"));
    }

    [Fact]
    public void SecretProtector_RoundTrips_AndMarksFallback()
    {
        var protectedValue = SecretProtector.Protect("hunter2");
        Assert.StartsWith("dpapi:v1:", protectedValue); // Windows test context has DPAPI
        Assert.Equal("hunter2", SecretProtector.Unprotect(protectedValue));

        // Legacy/plain tolerance: unknown formats pass through unchanged.
        Assert.Equal("raw-value", SecretProtector.Unprotect("raw-value"));
    }
    [Fact]
    public void WindowPlacement_Preferences_RoundTrip()
    {
        var store = NewStore();
        var original = new ApplicationSettings
        {
            Proxy = new ProxyConfiguration { Host = "1.2.3.4", Port = 1080 },
            Preferences = new UiPreferences
            {
                Theme = AppTheme.System,
                WindowLeft = -8.5,
                WindowTop = 42.25,
                WindowWidth = 1280.75,
                WindowHeight = 800.125,
                WindowMaximized = true
            }
        };

        store.Save(original);
        var prefs = store.Load().Preferences;

        Assert.Equal(-8.5, prefs.WindowLeft);
        Assert.Equal(42.25, prefs.WindowTop);
        Assert.Equal(1280.75, prefs.WindowWidth);
        Assert.Equal(800.125, prefs.WindowHeight);
        Assert.True(prefs.WindowMaximized);
    }

    [Fact]
    public void LegacyDocument_WithoutWindowKeys_LoadsWithDefaults()
    {
        // Hand-written settings from an older version: no window geometry.
        // The document must load cleanly and leave placement unset so the UI
        // falls back to its default size/position.
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        File.WriteAllText(_path, """{ "Proxies": [], "Preferences": { "Theme": 1 } }""");

        var prefs = NewStore().Load().Preferences;

        Assert.Equal(AppTheme.Light, prefs.Theme);
        Assert.Null(prefs.WindowLeft);
        Assert.Null(prefs.WindowTop);
        Assert.Null(prefs.WindowWidth);
        Assert.Null(prefs.WindowHeight);
        Assert.False(prefs.WindowMaximized);
    }

    // ── Validation of the extended model ──

    // ── Validation of the extended model ──

    [Fact]
    public void Validation_DuplicateProfileNames_AreRejected()
    {
        var settings = new ApplicationSettings
        {
            Proxy = new ProxyConfiguration { Host = "1.2.3.4", Port = 1080, Enabled = true },
            Proxies =
            [
                new ProxyConfiguration { Name = "same", Host = "1.1.1.1", Port = 80 },
                new ProxyConfiguration { Name = "SAME", Host = "2.2.2.2", Port = 81 }
            ],
            SelectedProxyName = "same"
        };

        var result = ConfigurationValidator.Validate(settings);
        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("Duplicate proxy name"));
    }

    [Fact]
    public void Validation_SelectionMustReferenceExistingProfile()
    {
        var settings = new ApplicationSettings
        {
            Proxy = new ProxyConfiguration { Host = "1.2.3.4", Port = 1080 },
            Proxies = [new ProxyConfiguration { Name = "a", Host = "1.1.1.1", Port = 80 }],
            SelectedProxyName = "missing"
        };

        var result = ConfigurationValidator.Validate(settings);
        Assert.Contains(result.Errors, e => e.Contains("does not match any saved proxy"));
    }

    [Theory]
    [InlineData("#E81123", true)]
    [InlineData("#fff", true)]
    [InlineData("", true)]
    [InlineData("red", false)]
    [InlineData("#12345", false)]
    public void Validation_AccentHex(string hex, bool valid)
    {
        var settings = new ApplicationSettings
        {
            Proxy = new ProxyConfiguration { Host = "1.2.3.4", Port = 1080 },
            Preferences = new UiPreferences { AccentColorHex = hex }
        };

        var result = ConfigurationValidator.Validate(settings);
        Assert.Equal(valid, result.IsValid);
    }
    // ── Legacy MyProxy → Open NetRoute settings migration ──

    private static string NewMigrationRoot() =>
        Path.Combine(Path.GetTempPath(), "onr-tests", Guid.NewGuid().ToString("N"));

    private static void TryDelete(string directory)
    {
        try { Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
    }

    [Fact]
    public void Migration_LegacyFilePresent_NewFileAbsent_CopiesContent()
    {
        var root = NewMigrationRoot();
        var legacy = Path.Combine(root, "MyProxy", "settings.json");
        var newPath = Path.Combine(root, "OpenNetRoute", "settings.json");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(legacy)!);
            File.WriteAllText(legacy, """{ "Proxies": [], "Preferences": { "Theme": 2 } }""");

            JsonApplicationSettingsStore.MigrateLegacySettings(legacy, newPath);

            Assert.True(File.Exists(newPath));
            Assert.True(File.Exists(legacy)); // backup kept — never moved or deleted
            // Content came across: legacy Dark theme (2), not the System default.
            Assert.Equal(AppTheme.Dark, new JsonApplicationSettingsStore(newPath).Load().Preferences.Theme);
        }
        finally { TryDelete(root); }
    }

    [Fact]
    public void Migration_NewFileAlreadyExists_DoesNotOverwrite()
    {
        var root = NewMigrationRoot();
        var legacy = Path.Combine(root, "MyProxy", "settings.json");
        var newPath = Path.Combine(root, "OpenNetRoute", "settings.json");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(newPath)!);
            File.WriteAllText(newPath, """{ "Proxies": [], "Preferences": { "Theme": 1 } }""");
            Directory.CreateDirectory(Path.GetDirectoryName(legacy)!);
            File.WriteAllText(legacy, """{ "Proxies": [], "Preferences": { "Theme": 2 } }""");

            JsonApplicationSettingsStore.MigrateLegacySettings(legacy, newPath);

            // The user's existing new-location settings win — no clobbering.
            Assert.Equal(AppTheme.Light, new JsonApplicationSettingsStore(newPath).Load().Preferences.Theme);
        }
        finally { TryDelete(root); }
    }

    [Fact]
    public void Migration_NoLegacyFile_IsNoOp()
    {
        var root = NewMigrationRoot();
        var newPath = Path.Combine(root, "OpenNetRoute", "settings.json");

        JsonApplicationSettingsStore.MigrateLegacySettings(
            Path.Combine(root, "MyProxy", "settings.json"), newPath);

        Assert.False(File.Exists(newPath));
        // No empty skeleton directories left behind either.
        Assert.False(Directory.Exists(Path.GetDirectoryName(newPath)!));
        TryDelete(root);
    }

    [Fact]
    public void Migration_FailureIsSwallowed_LegacyDataUntouched()
    {
        var root = NewMigrationRoot();
        var legacy = Path.Combine(root, "MyProxy", "settings.json");
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(legacy)!);
            File.WriteAllText(legacy, "{}");
            // Target cannot be created: a FILE occupies the target directory name.
            var fileAsDir = Path.Combine(root, "OpenNetRoute");
            File.WriteAllText(fileAsDir, "blocker");

            // Must not throw — app falls back to defaults, legacy file intact.
            JsonApplicationSettingsStore.MigrateLegacySettings(
                legacy, Path.Combine(fileAsDir, "settings.json"));

            Assert.True(File.Exists(legacy));
        }
        finally { TryDelete(root); }
    }

}
