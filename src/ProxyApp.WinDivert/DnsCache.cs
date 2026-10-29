using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProxyApp.WinDivert;

/// <summary>
/// Flushes the Windows DNS Client cache (<c>dnscache</c>). Called when the DNS
/// ferry starts so no name resolved BEFORE interception can be served from the
/// local cache — otherwise an app could keep using a pre-START answer and a
/// leak test run immediately after START would see stale, un-relayed results.
///
/// The cache is flushed again when the ferry stops, so the system returns to
/// normal resolution instead of re-resolving everything through the proxy.
///
/// WHY NOT A BARE BOOL: the P/Invoke (an undocumented dnsapi export) has been
/// observed returning non-zero on real user machines even elevated, and the
/// Win32 error was discarded, leaving the failure undiagnosable from logs.
/// <see cref="FlushWithDiagnostics"/> now (a) captures the error, (b) retries
/// through <c>ipconfig /flushdns</c> — the documented, supported path that
/// shells out to the same dnscache — and (c) states the outcome in a single
/// trace-ready line.
/// </summary>
internal static class DnsCache
{
    /// <summary>
    /// <c>DnsFlushResolverCache</c> (dnsapi.dll). Returns 0 on success.
    /// Best-effort by contract: a failure is traced, never fatal — the relay
    /// works with a warm cache, it is only a freshness nicety.
    /// <c>SetLastError = true</c> so <see cref="Marshal.GetLastWin32Error"/>
    /// carries the actual failure code for the diagnostics line.
    /// </summary>
    [DllImport("dnsapi.dll", SetLastError = true)]
    private static extern int DnsFlushResolverCache();

    /// <summary>
    /// Flushes the resolver cache and returns a one-line, human-readable
    /// outcome for the trace. Never throws; flush failure is explicitly
    /// NON-FATAL — the relay works with a warm cache, it is only a freshness
    /// nicety, and the ferry must START on DNS even when Windows refuses.
    /// </summary>
    public static string FlushWithDiagnostics()
    {
        var result = DnsFlushResolverCache();
        if (result == 0)
            return "Windows DNS cache flushed — pre-START answers cannot bypass the relay.";

        var win32Error = Marshal.GetLastWin32Error();
        if (FlushViaIpconfig())
        {
            return $"Windows DNS cache flushed via ipconfig /flushdns " +
                   $"(DnsFlushResolverCache failed: Win32 error {win32Error}).";
        }

        return $"Could not flush the Windows DNS cache " +
               $"(DnsFlushResolverCache error {win32Error}: " +
               $"{Win32Message(win32Error)}; ipconfig fallback failed too) — " +
               "pre-START answers may be served from cache until it expires.";
    }

    /// <summary>
    /// The documented fallback: <c>ipconfig /flushdns</c>. Runs hidden, output
    /// discarded, exit code decides. Bounded (5 s) so a stuck shell can never
    /// hang the ferry's synchronous start path, and any exception is swallowed
    /// — see the non-fatal contract on <see cref="FlushWithDiagnostics"/>.
    /// </summary>
    private static bool FlushViaIpconfig()
    {
        try
        {
            var startInfo = new ProcessStartInfo("ipconfig", "/flushdns")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using var process = Process.Start(startInfo);
            if (process is null)
                return false;

            // Truncating WaitForExit is deliberate: a flush that needs more
            // than five seconds is a broken machine state, not something to
            // block START for.
            if (!process.WaitForExit(5000))
                return false;

            return process.ExitCode == 0;
        }
        catch (Exception)
        {
            // ipconfig missing / blocked by policy — the diagnostics line
            // already carries the P/Invoke error, so silence is fine here.
            return false;
        }
    }

    /// <summary>Best-effort message for a Win32 error code (never throws).</summary>
    private static string Win32Message(int error)
    {
        try
        {
            return new Win32Exception(error).Message;
        }
        catch (Exception)
        {
            return $"unknown ({error})";
        }
    }
}
