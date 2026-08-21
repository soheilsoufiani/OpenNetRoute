namespace ProxyApp.Core.Processes;

/// <summary>A running process as shown in the UI.</summary>
/// <param name="ProcessId">The Windows process ID.</param>
/// <param name="Name">The executable name, e.g. "chrome.exe".</param>
/// <param name="ExecutablePath">
/// The full executable path, or null when it cannot be read (e.g. access denied
/// for protected processes).
/// </param>
public readonly record struct RunningProcess(int ProcessId, string Name, string? ExecutablePath);

/// <summary>
/// Enumerates running processes for the UI. Windows-specific process APIs are
/// isolated behind this interface (CLAUDE.md Phase 3); the implementation lives
/// in ProxyApp.Processes.
/// </summary>
public interface IProcessEnumerator
{
    /// <summary>Returns the running processes sorted by executable name.</summary>
    IReadOnlyList<RunningProcess> GetRunningProcesses();
}
