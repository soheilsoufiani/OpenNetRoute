using ProxyApp.Core.Processes;
using ProxyApp.Processes;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for <see cref="ProcessEnumerator"/>, the UI process-list source.
/// These run against the real process table (no elevation required).
/// </summary>
public class ProcessEnumeratorTests
{
    [Fact]
    public void Enumerate_FindsCurrentProcess()
    {
        var enumerator = new ProcessEnumerator();

        var processes = enumerator.GetRunningProcesses();

        // The test host process itself must be listed with its PID.
        Assert.Contains(processes, p => p.ProcessId == Environment.ProcessId);
    }

    [Fact]
    public void Enumerate_ReturnsSortedByName()
    {
        var enumerator = new ProcessEnumerator();

        var processes = enumerator.GetRunningProcesses();

        // Sorted case-insensitively by executable name.
        var names = processes.Select(p => p.Name).ToList();
        var sorted = names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        Assert.Equal(sorted, names);
        Assert.NotEmpty(names);
    }

    [Fact]
    public void Enumerate_DoesNotListPseudoProcesses()
    {
        var enumerator = new ProcessEnumerator();

        var processes = enumerator.GetRunningProcesses();

        // Idle (PID 0) and System (PID 4) are pseudo-processes, not user apps.
        Assert.DoesNotContain(processes, p => p.ProcessId == 0);
        Assert.DoesNotContain(processes, p => p.ProcessId == 4);
    }

    [Fact]
    public void Enumerate_CurrentProcessHasNonEmptyName()
    {
        var enumerator = new ProcessEnumerator();

        var processes = enumerator.GetRunningProcesses();
        var self = processes.Single(p => p.ProcessId == Environment.ProcessId);

        Assert.False(string.IsNullOrWhiteSpace(self.Name));
        Assert.EndsWith(".exe", self.Name, StringComparison.OrdinalIgnoreCase);
    }
}
