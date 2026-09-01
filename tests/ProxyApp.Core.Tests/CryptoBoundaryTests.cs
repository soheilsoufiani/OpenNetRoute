using ProxyApp.Core.Configuration;
using ProxyApp.Core.Persistence;
using ProxyApp.Core.Rules;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Pins the crypto boundary contract: DPAPI protection happens ONLY during
/// storage-file serialization/deserialization. Every in-memory model property
/// that the UI can bind or display must hold human-readable PLAINTEXT after
/// Load() — never a protected blob ("dpapi:v1:" / "plain:v1:") — while the
/// stored FILE contains protected values where expected. Regression guard
/// against accidentally registering ProtectedStringJsonConverter globally
/// (which historically encrypted Name/Host into the UI surface).
/// </summary>
public class CryptoBoundaryTests : IDisposable
{
    private readonly string _path =
        Path.Combine(Path.GetTempPath(), "myproxy-tests", Guid.NewGuid().ToString("N"), "settings.json");

    public void Dispose()
    {
        try { Directory.Delete(Path.GetDirectoryName(_path)!, recursive: true); }
        catch (IOException) { }
    }

    [Fact]
    public void LoadedModel_ContainsNoCipherPrefix_AnyBindableString()
    {
        const string secret = "sup3r-secret-value";
        var store = new JsonApplicationSettingsStore(_path);
        store.Save(new ApplicationSettings
        {
            Proxy = new ProxyConfiguration
            {
                Name = "US-Proxy-1",
                Host = "192.168.1.1",
                Port = 1080,
                Username = "svc",
                Password = secret,
                AuthenticationType = ProxyAuthenticationType.UsernamePassword
            },
            Proxies =
            [
                new ProxyConfiguration
                {
                    Name = "US-Proxy-1", Host = "192.168.1.1", Port = 1080,
                    Username = "svc", Password = secret,
                    AuthenticationType = ProxyAuthenticationType.UsernamePassword
                },
                new ProxyConfiguration { Name = "Home", Host = "vpn.example.com", Port = 9050 }
            ],
            SelectedProxyName = "US-Proxy-1",
            Rules = [new ApplicationRule { ExecutableName = "chrome.exe", Mode = ProxyMode.Proxy }]
        });

        var loaded = store.Load();

        // Reflectively collect EVERY string reachable in the persisted model —
        // exactly what the UI could ever display — and assert plaintext.
        var strings = CollectStrings(loaded);
        Assert.NotEmpty(strings);
        Assert.Contains("US-Proxy-1", strings);           // name visible as typed
        Assert.Contains("192.168.1.1", strings);          // host visible as typed
        foreach (var value in strings)
        {
            Assert.False(value.StartsWith(SecretProtectorTestExtensions.DpapiPrefix, StringComparison.Ordinal),
                $"Ciphertext leaked into model: '{value[..Math.Min(value.Length, 16)]}…'");
            Assert.False(value.StartsWith(SecretProtectorTestExtensions.PlainPrefix, StringComparison.Ordinal),
                $"Encoded fallback leaked into model: '{value[..Math.Min(value.Length, 16)]}…'");
        }

        // The password itself IS present — decrypted, never as the blob.
        Assert.Contains(secret, strings);

        // Meanwhile the stored document holds the protected form, NOT plaintext.
        var json = File.ReadAllText(store.Location);
        Assert.DoesNotContain(secret, json);
        Assert.Contains(SecretProtectorTestExtensions.DpapiPrefix, json);
    }

    private static List<string> CollectStrings(object root)
    {
        var seen = new HashSet<object?>(ReferenceEqualityComparer.Instance);
        var result = new List<string>();
        var frontier = new Queue<object>();
        frontier.Enqueue(root);

        while (frontier.Count > 0)
        {
            var current = frontier.Dequeue();
            if (!seen.Add(current))
                continue;
            if (current is null || current.GetType().IsPrimitive || current is Enum)
                continue;

            switch (current)
            {
                case string s:
                    result.Add(s);
                    continue;
                case IEnumerable<object> enumerable:
                    {
                        foreach (var item in enumerable.Where(i => i is string or ApplicationSettings
                                   or ProxyConfiguration or ApplicationRule or UiPreferences))
                            frontier.Enqueue(item);
                        continue;
                    }
            }

            if (current is not (ApplicationSettings or ProxyConfiguration or ApplicationRule or UiPreferences))
                continue;

            foreach (var prop in current.GetType().GetProperties())
            {
                if (prop.GetIndexParameters().Length > 0)
                    continue;
                var value = prop.GetValue(current);
                if (value is string or ApplicationSettings or ProxyConfiguration or ApplicationRule or UiPreferences)
                    frontier.Enqueue(value!);
                else if (value is IEnumerable<object>)
                    frontier.Enqueue(value);
            }
        }

        return result;
    }
}

/// <summary>Prefix constants mirrored locally so the production type cannot drift.</summary>
file static class SecretProtectorTestExtensions
{
    public const string DpapiPrefix = "dpapi:v1:";
    public const string PlainPrefix = "plain:v1:";
}
