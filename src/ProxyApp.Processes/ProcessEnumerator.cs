using System.Diagnostics;
using ProxyApp.Core.Processes;

namespace ProxyApp.Processes;

/// <summary>
/// Enumerates running processes for the UI via <see cref="Process.GetProcesses"/>.
/// Handles the access-denied case (protected processes): the process is still
/// listed, but its executable path is null.
/// </summary>
public sealed class ProcessEnumerator : IProcessEnumerator
{
    /// <inheritdoc />
    public IReadOnlyList<RunningProcess> GetRunningProcesses()
    {
        var result = new List<RunningProcess>();
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                // Skip the Idle and System pseudo-processes.
                if (process.Id == 0 || process.Id == 4)
                    continue;

                string? path = null;
                try
                {
                    path = process.MainModule?.FileName;
                }
                catch
                {
                    // Access denied for protected processes; the process is still
                    // listed with an unknown path.
                }

                result.Add(new RunningProcess(process.Id, process.ProcessName + ".exe", path));
            }
            finally
            {
                process.Dispose();
            }
        }

        return result
            .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
