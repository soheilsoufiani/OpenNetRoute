using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Rules;

/// <summary>
/// Evaluates an ordered list of <see cref="ApplicationRule"/> against a process
/// identity and returns the routing decision.
///
/// First enabled matching rule wins. A rule matches by executable name
/// (case-insensitive) or by executable path (case-insensitive, full path).
/// When no rule matches, the default is <see cref="ProxyMode.Direct"/>.
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
        if (rules == null || rules.Count == 0)
            return ProxyMode.Direct;

        foreach (var rule in rules)
        {
            if (rule == null || !rule.Enabled)
                continue;

            if (Matches(rule, processName, processPath))
                return rule.Mode;
        }

        return ProxyMode.Direct;
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