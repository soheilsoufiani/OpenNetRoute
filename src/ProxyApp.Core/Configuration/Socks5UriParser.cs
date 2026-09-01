using System.Text;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Configuration;

/// <summary>
/// Parses SOCKS5 proxy URIs of the form
/// <c>socks5://[username[:password]@]host[:port]</c> into a
/// <see cref="ProxyConfiguration"/>, as produced by the "Paste Config" feature.
///
/// Rules:
///  - The scheme must be <c>socks5</c> (case-insensitive).
///  - Username and password are optional; a missing userinfo means no
///    authentication. An empty password is permitted (RFC 1929).
///  - Percent-encoded characters in the username/password are decoded
///    (<c>%40</c> → <c>@</c>, <c>%3A</c> → <c>:</c>), so credentials containing
///    reserved characters round-trip.
///  - A missing port defaults to 1080 (the IANA-registered SOCKS port).
///  - Numeric loopback hosts (127.0.0.1, ::1) are accepted — pointing at a
///    local proxy (v2ray/Xray inbound) is supported. The ferry never captures
///    loopback traffic, so a local proxy cannot create an interception loop.
///    Only the validator's forbidden names (<c>localhost</c>, <c>0.0.0.0</c>,
///    <c>::</c>) are rejected (see <see cref="Validation.ConfigurationValidator"/>).
/// </summary>
public static class Socks5UriParser
{
    /// <summary>The default SOCKS5 port used when the URI omits one.</summary>
    public const int DefaultPort = 1080;

    /// <summary>Maximum accepted input length — guards against junk paste.</summary>
    public const int MaxInputLength = 2048;

    /// <summary>
    /// Attempts to parse exactly one SOCKS5 URI. Returns false for null/blank
    /// input, wrong scheme, unparseable URIs, or missing hosts. Never throws.
    /// </summary>
    public static bool TryParse(string? text, out ProxyConfiguration proxy)
    {
        proxy = new ProxyConfiguration();

        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxInputLength)
            return false;

        var candidate = text.Trim();
        if (!candidate.StartsWith("socks5://", StringComparison.OrdinalIgnoreCase))
            return false;

        if (!Uri.TryCreate(candidate, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, "socks5", StringComparison.OrdinalIgnoreCase))
            return false;

        // Uri.Host keeps IPv6 literals bracketed ("[::1]"); store the plain
        // address ("::1") so ConfigurationValidator's IPAddress.TryParse accepts it.
        var host = uri.Host;
        if (host.Length >= 2 && host.StartsWith('[') && host.EndsWith(']'))
            host = host[1..^1];
        if (string.IsNullOrWhiteSpace(host) || host.Length > ConfigurationValidator.MaxHostLength)
            return false;
        if (ConfigurationValidator.IsForbiddenHost(host))
            return false; // "localhost", "0.0.0.0", "::" — the same set the validator rejects.
                          // Numeric loopback (127.0.0.1, ::1) is deliberately ACCEPTED: a local
                          // proxy (v2ray/Xray inbound) is supported, and the ferry's capture
                          // filter ("... and not loopback") never intercepts loopback traffic.

        var port = uri.Port is > 0 and <= ConfigurationValidator.MaxPort ? uri.Port : DefaultPort;

        string? username = null;
        string? password = null;
        ProxyAuthenticationType auth = ProxyAuthenticationType.None;

        var userInfo = uri.UserInfo;
        if (userInfo.Length > 0)
        {
            // Split at the FIRST ':' only; later colons belong to the password
            // (which may contain raw colons when not percent-encoded).
            var separator = userInfo.IndexOf(':');
            username = separator < 0
                ? Decode(userInfo)
                : Decode(userInfo[..separator]);
            password = separator < 0
                ? null
                : Decode(userInfo[(separator + 1)..]);

            if (username.Length == 0 || username.Length > ConfigurationValidator.MaxUsernameLength ||
                password?.Length > ConfigurationValidator.MaxPasswordLength)
                return false;

            auth = ProxyAuthenticationType.UsernamePassword;
        }

        proxy = new ProxyConfiguration
        {
            Protocol = ProxyProtocol.Socks5,
            Host = host,
            Port = port,
            Username = username,
            Password = password,
            AuthenticationType = auth,
            Enabled = true,
            Name = $"{host}:{port}"
        };
        return true;
    }

    private static string Decode(string value)
    {
        // Uri.UserInfo preserves percent-escapes; decode defensively (a literal
        // '%' that forms an invalid escape stays as-is).
        try
        {
            var decoded = Uri.UnescapeDataString(value);
            return decoded.Replace("\0", "");
        }
        catch (UriFormatException)
        {
            return value;
        }
    }
}
