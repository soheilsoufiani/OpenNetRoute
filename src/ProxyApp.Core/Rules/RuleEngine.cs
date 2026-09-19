using System.Net;
using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Evaluates an ordered list of <see cref="ApplicationRule"/> against a process
/// identity and returns the routing decision.
///
/// First enabled matching rule wins. A rule matches by executable name
/// (case-insensitive) or by executable path (case-insensitive, full path).
/// When no rule matches, the default is <see cref="ProxyMode.Direct"/>.
///
/// Destination-based rules (<see cref="IpDomainRule"/>, the IP/Domain tab) are
/// evaluated BEFORE the process rules via <see cref="DecideAsync"/> — they
/// express per-destination intent ("this site stays direct", "this subnet
/// uses a specific profile") which must override an app-wide process pin.
/// </summary>
public static class RuleEngine
{
    /// <summary>
    /// Evaluates the rules against the given process name and optional path.
    /// </summary>
    /// <param name="rules">The ordered list of application rules.</param>
    /// <param name="processName">The executable name (e.g. "chrome.exe").</param>
    /// <param name="processPath">The full executable path, or null if unknown.</param>
    /// <returns>The routing mode, or <see cref="ProxyMode.Direct"/> if no rule matches.</returns>
    public static ProxyMode Evaluate(
        IReadOnlyList<ApplicationRule> rules,
        string? processName,
        string? processPath)
    {
        return Decide(rules, processName, processPath).Mode;
    }

    /// <summary>
    /// Evaluates the rules against the given process name and optional path,
    /// returning the full routing decision: the mode AND, for proxied traffic,
    /// the saved proxy profile the rule pins (null/empty = the active proxy).
    /// </summary>
    /// <param name="rules">The ordered list of application rules.</param>
    /// <param name="processName">The executable name (e.g. "chrome.exe").</param>
    /// <param name="processPath">The full executable path, or null if unknown.</param>
    /// <returns>
    /// The decision of the first enabled matching rule, or
    /// <see cref="RoutingDecision.Direct"/> if no rule matches.
    /// </returns>
    public static RoutingDecision Decide(
        IReadOnlyList<ApplicationRule> rules,
        string? processName,
        string? processPath)
    {
        if (rules == null || rules.Count == 0)
            return RoutingDecision.Direct;

        foreach (var rule in rules)
        {
            if (rule == null || !rule.Enabled)
                continue;

            if (Matches(rule, processName, processPath))
                return new RoutingDecision(rule.Mode, rule.ProxyName);
        }

        return RoutingDecision.Direct;
    }

    /// <summary>
    /// Full evaluation for one captured connection: destination rules first
    /// (IP/domain, IPv4 only), then the process rules, then
    /// <see cref="RoutingDecision.Direct"/>.
    ///
    /// Domain rules are resolved through <paramref name="destinationResolver"/>
    /// (cached by the implementation) and match when the destination IPv4
    /// address is one of the domain's addresses. IPv6 destinations never match
    /// a destination rule — they fall through to the process rules. Port
    /// pre-checks happen before any DNS resolution so a rule restricted to
    /// another port costs nothing.
    /// </summary>
    /// <param name="destinationRules">Ordered destination rules (IP/Domain tab).</param>
    /// <param name="rules">Ordered process rules (App Rules tab).</param>
    /// <param name="processName">The executable name (e.g. "chrome.exe").</param>
    /// <param name="processPath">The full executable path, or null if unknown.</param>
    /// <param name="destinationIp">The connection's original destination address.</param>
    /// <param name="destinationPort">The connection's original destination port.</param>
    /// <param name="destinationResolver">
    /// Domain resolver for domain rules; may be null (domain rules then never
    /// match — only IP-literal rules apply).
    /// </param>
    /// <param name="ct">Cancels a pending domain resolution.</param>
    public static async Task<RoutingDecision> DecideAsync(
        IReadOnlyList<IpDomainRule>? destinationRules,
        IReadOnlyList<ApplicationRule> rules,
        string? processName,
        string? processPath,
        IPAddress? destinationIp,
        int destinationPort,
        IDestinationResolver? destinationResolver = null,
        CancellationToken ct = default)
    {
        if (destinationRules is { Count: > 0 } &&
            destinationIp is { AddressFamily: System.Net.Sockets.AddressFamily.InterNetwork })
        {
            foreach (var rule in destinationRules)
            {
                if (rule is null || !rule.Enabled)
                    continue;

                var host = rule.Host;
                if (string.IsNullOrWhiteSpace(host))
                    continue;

                IReadOnlyList<IPAddress> resolved;
                if (DestinationMatch.TryParseIpv4(host, out var ruleIp))
                {
                    // IP-literal rule — no resolution needed.
                    resolved = new[] { ruleIp };
                }
                else
                {
                    // Domain rule — resolve (cached by the implementation).
                    // Without a resolver a domain rule can never match.
                    if (destinationResolver is null)
                        continue;
                    resolved = await destinationResolver
                        .ResolveAsync(host, ct)
                        .ConfigureAwait(false);
                }

                if (DestinationMatch.Matches(rule, destinationIp, destinationPort, resolved))
                    return new RoutingDecision(rule.Mode, rule.ProxyName);
            }
        }

        return Decide(rules, processName, processPath);
    }

    private static bool Matches(ApplicationRule rule, string? processName, string? processPath)
    {
        // Match by executable name (case-insensitive). A rule with no name
        // (e.g. a folder/bundle rule) cannot match by name.
        if (!string.IsNullOrWhiteSpace(rule.ExecutableName) &&
            !string.IsNullOrWhiteSpace(processName) &&
            string.Equals(processName, rule.ExecutableName, StringComparison.OrdinalIgnoreCase))
            return true;

        // Match by executable path (case-insensitive, when both are set).
        if (!string.IsNullOrWhiteSpace(processPath) &&
            !string.IsNullOrWhiteSpace(rule.ExecutablePath) &&
            string.Equals(processPath, rule.ExecutablePath, StringComparison.OrdinalIgnoreCase))
            return true;

        // Match by folder path (bundle rule): the process's executable path
        // must be under the rule's folder at a DIRECTORY BOUNDARY. Normalize the
        // folder's trailing separator, then require the separator after the
        // prefix so "C:\prog" does NOT match "C:\programs". Case-insensitive.
        if (!string.IsNullOrWhiteSpace(processPath) &&
            !string.IsNullOrWhiteSpace(rule.FolderPath))
        {
            var folder = rule.FolderPath.TrimEnd('\\', '/');
            if (folder.Length > 0 &&
                processPath.StartsWith(folder + '\\', StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}