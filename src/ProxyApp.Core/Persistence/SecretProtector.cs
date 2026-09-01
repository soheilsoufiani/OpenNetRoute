using System.Security.Cryptography;
using System.Text;

namespace ProxyApp.Core.Persistence;

/// <summary>
/// Protects credential strings at rest using Windows DPAPI
/// (CurrentUser scope — only this Windows user can decrypt).
///
/// Stored format: "<c>dpapi:v1:</c>" + base64(ProtectedData blob). On systems
/// where DPAPI is unavailable (non-Windows, restricted sandboxes) the code
/// falls back to "<c>plain:v1:</c>" + base64 — base64 is ENCODING, not
/// encryption; it only prevents casual shoulder-surfing of the settings file.
/// This fallback exists so the store never crashes; on any supported desktop
/// target (Windows 10/11) DPAPI is used.
///
/// Values without a recognized prefix are returned as-is on Unprotect so
/// hand-edited or legacy files keep working.
/// </summary>
public static class SecretProtector
{
    private const string DpapiPrefix = "dpapi:v1:";
    private const string PlainPrefix = "plain:v1:";

    /// <summary>Protects a plaintext secret for storage. Empty/null stays empty.</summary>
    public static string? Protect(string? plain)
    {
        if (string.IsNullOrEmpty(plain))
            return plain;

        // DPAPI is Windows-only; the platform check is explicit so the fallback
        // is deterministic (and the Core assembly stays analyzer-clean).
        if (!OperatingSystem.IsWindows())
            return PlainPrefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));

        try
        {
            var blob = System.Security.Cryptography.ProtectedData.Protect(
                Encoding.UTF8.GetBytes(plain),
                optionalEntropy: null,
                DataProtectionScope.CurrentUser);
            return DpapiPrefix + Convert.ToBase64String(blob);
        }
        catch (CryptographicException)
        {
            // DPAPI failed (e.g. corrupt user profile) — degrade to marked
            // base64 rather than crash. Encoding, not encryption; documented.
            return PlainPrefix + Convert.ToBase64String(Encoding.UTF8.GetBytes(plain));
        }
    }

    /// <summary>
    /// Restores a stored secret to plaintext. Unknown formats are returned
    /// verbatim (tolerates legacy/plain files and hand edits).
    /// </summary>
    public static string? Unprotect(string? stored)
    {
        if (string.IsNullOrEmpty(stored))
            return stored;

        if (stored.StartsWith(DpapiPrefix, StringComparison.Ordinal))
        {
            if (!OperatingSystem.IsWindows())
                throw new CryptographicException(
                    "DPAPI-protected value cannot be decrypted on this platform.");
            var blob = Convert.FromBase64String(stored[DpapiPrefix.Length..]);
            return Encoding.UTF8.GetString(
                System.Security.Cryptography.ProtectedData.Unprotect(
                    blob, optionalEntropy: null, DataProtectionScope.CurrentUser));
        }

        if (stored.StartsWith(PlainPrefix, StringComparison.Ordinal))
            return Encoding.UTF8.GetString(Convert.FromBase64String(stored[PlainPrefix.Length..]));

        return stored;
    }
}
