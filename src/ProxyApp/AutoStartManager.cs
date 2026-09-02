using Microsoft.Win32;

namespace ProxyApp;

/// <summary>
/// Per-user "start with Windows" registration via the HKCU Run key.
///
/// The registry is the single source of truth (no duplicate preference): the
/// settings-tab checkbox reads <see cref="IsEnabled"/> and writes through
/// <see cref="SetEnabled"/>. Only the CURRENT USER hive is touched — no
/// administrator rights and no machine-wide change. The registered command is
/// the quoted path of the running executable; that launch then follows the
/// persisted tray/window preferences like any other start. Failures (registry
/// access denied) are reported through the return value — never silent.
/// </summary>
public static class AutoStartManager
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "OpenNetRoute";

    /// <summary>False when the executable path is unavailable — the option cannot work.</summary>
    public static bool IsSupported => !string.IsNullOrEmpty(Environment.ProcessPath);

    /// <summary>True when the Run value exists and points at the current executable.</summary>
    public static bool IsEnabled()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath);
            return key?.GetValue(ValueName) is string command &&
                   string.Equals(command, BuildCommand(), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception ex) when (
            ex is UnauthorizedAccessException or System.Security.SecurityException or System.IO.IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Enables or disables the registration. Returns false (registry state
    /// unchanged) when the write failed.
    /// </summary>
    public static bool SetEnabled(bool enabled)
    {
        try
        {
            if (enabled)
            {
                var exe = Environment.ProcessPath;
                if (string.IsNullOrEmpty(exe))
                    return false;

                using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath);
                key.SetValue(ValueName, BuildCommand());
            }
            else
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true);
                key?.DeleteValue(ValueName, throwOnMissingValue: false);
            }

            return true;
        }
        catch (Exception ex) when (
            ex is UnauthorizedAccessException or System.Security.SecurityException or System.IO.IOException)
        {
            return false;
        }
    }

    /// <summary>The exact command string written to / compared against the Run value.</summary>
    private static string BuildCommand() =>
        string.IsNullOrEmpty(Environment.ProcessPath) ? "" : $"\"{Environment.ProcessPath}\"";
}