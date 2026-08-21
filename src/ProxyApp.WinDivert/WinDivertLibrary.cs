using System.Runtime.InteropServices;

namespace ProxyApp.WinDivert;

/// <summary>
/// Resolves the native WinDivert.dll from a configurable location.
///
/// WinDivert.dll is a native dependency of this assembly. It may live next to
/// the application, in a known install directory, or at a path supplied via the
/// <c>PROXYAPP_WINDIVERT_DIR</c> environment variable. This resolver lets the
/// ferry load it at runtime instead of requiring it on the standard DLL search
/// path. It is registered via <see cref="NativeLibrary.SetDllImportResolver"/>.
/// </summary>
internal static class WinDivertLibrary
{
    private static int _registered;

    /// <summary>
    /// Registers the resolver for this assembly. Idempotent: only the first call
    /// registers; subsequent calls are no-ops (SetDllImportResolver throws if
    /// called twice for the same assembly).
    /// </summary>
    public static void EnsureRegistered()
    {
        if (Interlocked.Exchange(ref _registered, 1) == 1)
            return;

        NativeLibrary.SetDllImportResolver(
            typeof(WinDivertLibrary).Assembly,
            static (libraryName, assembly, searchPath) => Resolve(libraryName));
    }

    private static IntPtr Resolve(string libraryName)
    {
        if (!string.Equals(libraryName, "WinDivert.dll", StringComparison.OrdinalIgnoreCase))
            return IntPtr.Zero;

        // 1. Environment variable override.
        var envDir = Environment.GetEnvironmentVariable("PROXYAPP_WINDIVERT_DIR");
        if (!string.IsNullOrWhiteSpace(envDir))
        {
            var candidate = Path.Combine(envDir, "WinDivert.dll");
            if (File.Exists(candidate))
                return NativeLibrary.Load(candidate);
        }

        // 2. App base directory.
        var appDir = AppContext.BaseDirectory;
        var appCandidate = Path.Combine(appDir, "WinDivert.dll");
        if (File.Exists(appCandidate))
            return NativeLibrary.Load(appCandidate);

        // 3. Standard search (DLL alongside the process / system path).
        if (NativeLibrary.TryLoad(libraryName, out var handle))
            return handle;

        return IntPtr.Zero;
    }
}