namespace ProxyApp.Core.Configuration;

/// <summary>
/// A rule deciding how traffic from one application should be routed.
///
/// A POCO with get/set properties so it can be round-tripped through JSON
/// serialization. Validation is performed by
/// <see cref="ProxyApp.Core.Validation.ConfigurationValidator.Validate(ApplicationRule)"/>.
/// </summary>
public sealed class ApplicationRule
{
    /// <summary>
    /// The process image file name, e.g. <c>chrome.exe</c>. Matches are case-insensitive.
    /// Required.
    /// </summary>
    public string? ExecutableName { get; set; }

    /// <summary>
    /// Optional full path to the executable, e.g. <c>C:\Program Files\...\chrome.exe</c>.
    /// When set, a rule may match by path as well as by name.
    /// </summary>
    public string? ExecutablePath { get; set; }

    /// <summary>
    /// Whether this rule is currently active. A disabled rule is ignored when the
    /// routing engine evaluates traffic.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Whether matching traffic goes through the proxy or stays direct.
    /// </summary>
    public ProxyMode Mode { get; set; }

    /// <summary>
    /// Optional folder path for a bundle rule. When set, this rule matches any
    /// process whose <c>ExecutablePath</c> is located under this folder (prefix
    /// match at a directory boundary). The folder is scanned at add time for
    /// display purposes, but matching itself is by prefix at SYN time — newly
    /// added executables in the folder are automatically covered.
    /// A rule with <c>FolderPath</c> set may have <c>ExecutableName</c> null.
    /// </summary>
    public string? FolderPath { get; set; }
}