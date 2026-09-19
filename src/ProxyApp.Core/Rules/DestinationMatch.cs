using System.Net;
using System.Net.Sockets;
using ProxyApp.Core.Configuration;
using ProxyApp.Core.Validation;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Parsing and matching for destination-based (IP/domain) rules.
///
/// All methods are pure functions: parsing never throws for user input, and
/// matching never performs I/O — the caller resolves domains (via
/// <see cref="IDestinationResolver"/>) and hands the resolved addresses in.
///
/// IPv4 only by design: an IPv6 destination never matches a destination rule,
/// and an IPv6 literal is rejected at parse time.
/// </summary>
public static class DestinationMatch
{
    /// <summary>Maximum length of a rule host (IPv4 literal or domain name).</summary>
    public const int MaxHostLength = 255;

    /// <summary>
    /// Parses a user-supplied destination match: an IPv4 literal or domain
    /// name, optionally suffixed with <c>:port</c> (e.g. <c>142.250.0.14</c>,
    /// <c>142.250.0.14:443</c>, <c>example.com</c>, <c>example.com:8443</c>).
    /// </summary>
    /// <param name="text">The user-supplied text (never throws).</param>
    /// <param name="host">The parsed host (IPv4 literal or domain, no port).</param>
    /// <param name="port">The parsed port, or null when absent.</param>
    /// <returns>True when the text is a valid destination match.</returns>
    public static bool TryParse(string? text, out string host, out int? port)
    {
        host = "";
        port = null;

        if (string.IsNullOrWhiteSpace(text))
            return false;

        var input = text.Trim();
        var hostPart = input;
        var colon = input.LastIndexOf(':');
        if (colon >= 0)
        {
            // "host:port". An IPv6 literal (e.g. "::1") also contains ':' and
            // fails below — IPv6 is not supported for destination rules.
            hostPart = input[..colon];
            var portPart = input[(colon + 1)..];
            if (hostPart.Length == 0 || portPart.Length == 0)
                return false;
            if (!int.TryParse(portPart, out var parsedPort) ||
                parsedPort < ConfigurationValidator.MinPort ||
                parsedPort > ConfigurationValidator.MaxPort)
                return false;
            port = parsedPort;
        }

        if (hostPart.Length > MaxHostLength)
            return false;

        host = hostPart;

        // A host that parses as an IP must be a valid, UNAMBIGUOUS IPv4
        // literal (strict dotted-quad — IPAddress.TryParse also accepts
        // abbreviated forms like "1.2.3" → 1.2.0.3, which are confusing for
        // user-facing rules). IPv6 is deliberately unsupported. Everything
        // else must be a DNS name.
        if (TryParseIpv4(hostPart, out _))
            return true;

        // A numeric-dotted string that is not a valid dotted-quad is a
        // malformed IP, not a domain name (e.g. "256.1.1.1", "1.2.3") —
        // reject it rather than pretending it is a resolvable DNS name.
        if (hostPart.All(c => c is '.' or (>= '0' and <= '9')))
            return false;

        return Uri.CheckHostName(hostPart) == UriHostNameType.Dns;
    }

    /// <summary>
    /// Strict IPv4-literal check: exactly four dot-separated parts and a
    /// successful <see cref="IPAddress.TryParse"/> into an InterNetwork
    /// address. Shared by parsing, matching, and the rule engine so all agree.
    /// </summary>
    public static bool TryParseIpv4(string text, out IPAddress address)
    {
        address = new IPAddress(0);
        if (text.Count(c => c == '.') != 3)
            return false;
        if (!IPAddress.TryParse(text, out var parsed) ||
            parsed.AddressFamily != AddressFamily.InterNetwork)
            return false;
        address = parsed;
        return true;
    }

    /// <summary>
    /// Returns true when the rule matches the connection's destination.
    /// </summary>
    /// <param name="rule">The destination rule (null/disabled never matches).</param>
    /// <param name="destinationIp">The connection's destination address. IPv6
    /// destinations never match (IPv4-only support).</param>
    /// <param name="destinationPort">The connection's destination port.</param>
    /// <param name="resolvedHostIps">
    /// The addresses <paramref name="rule"/>'s domain resolves to — required
    /// for domain rules, ignored for IP-literal rules. Null/empty = the
    /// domain could not be resolved (no match).
    /// </param>
    public static bool Matches(
        IpDomainRule? rule,
        IPAddress? destinationIp,
        int destinationPort,
        IReadOnlyList<IPAddress>? resolvedHostIps)
    {
        if (rule is null || !rule.Enabled)
            return false;

        // IPv4 only: an IPv6 destination never matches a destination rule.
        if (destinationIp is null ||
            destinationIp.AddressFamily != AddressFamily.InterNetwork)
            return false;

        // Optional port restriction: null matches any port.
        if (rule.Port is { } rulePort && rulePort != destinationPort)
            return false;

        var host = rule.Host;
        if (string.IsNullOrWhiteSpace(host))
            return false;

        // IP-literal rule: exact address equality.
        if (TryParseIpv4(host, out var ruleIp))
            return ruleIp.Equals(destinationIp);

        // Domain rule: the destination must be one of the domain's IPv4
        // addresses (resolved by the caller, cached there).
        if (resolvedHostIps is null || resolvedHostIps.Count == 0)
            return false;

        foreach (var ip in resolvedHostIps)
        {
            if (ip.AddressFamily == AddressFamily.InterNetwork && ip.Equals(destinationIp))
                return true;
        }

        return false;
    }
}

