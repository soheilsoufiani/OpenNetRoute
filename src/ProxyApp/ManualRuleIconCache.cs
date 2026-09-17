using System.Collections.Concurrent;
using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ProxyApp;

/// <summary>
/// Resolves and caches the executable icon shown next to each manual exe rule
/// (EXECUTABLE column). Extraction uses the plain system icon via
/// <see cref="System.Drawing.Icon.ExtractAssociatedIcon"/> (first-party
/// System.Drawing, already referenced for the tray icon) and converts it to a
/// frozen <see cref="BitmapSource"/> so it can be used as an ImageSource from
/// any thread. A real executable icon is deliberately theme-independent
/// (it is artwork from the exe itself, not part of the app's palette).
/// Name-only rules and paths whose icon cannot be extracted fall back to
/// <see cref="PlaceholderIconSource"/>, a neutral light-gray two-window
/// outline that reads as "unknown executable" in both themes.
/// </summary>
public sealed class ManualRuleIconCache
{
    public static ManualRuleIconCache Instance { get; } = new();

    /// <summary>
    /// Extracted icons keyed by full path (case-insensitive, like the rule
    /// dedup). Null values are cached too, so unreadable paths are not
    /// re-probed on every add/restore.
    /// </summary>
    private readonly ConcurrentDictionary<string, ImageSource?> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    private ManualRuleIconCache()
    {
    }

    /// <summary>
    /// Returns the executable's icon, or null when none could be extracted
    /// (missing file, access denied, not an executable image).
    /// </summary>
    public ImageSource? GetIcon(string executablePath) =>
        _cache.GetOrAdd(executablePath, ExtractIcon);

    /// <summary>
    /// Drops the cached entry for a path so the next resolution re-extracts
    /// (e.g. a file with the same path was replaced on disk).
    /// </summary>
    public void Invalidate(string executablePath) =>
        _cache.TryRemove(executablePath, out _);

    private static ImageSource? ExtractIcon(string path)
    {
        try
        {
            if (!File.Exists(path))
                return null;

            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (icon is null)
                return null;

            var bitmap = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                icon.Handle,
                System.Windows.Int32Rect.Empty,
                BitmapSizeOptions.FromEmptyOptions());
            bitmap.Freeze();
            return bitmap;
        }
        catch (Exception)
        {
            // Unreadable or non-executable file — the placeholder stands in.
            return null;
        }
    }

    /// <summary>
    /// Neutral stand-in icon for rules that cannot show a real executable
    /// icon: name-only rules and paths whose icon could not be extracted.
    /// Light-gray (theme-neutral) two-window outline on a 16×16 grid, frozen
    /// so the single instance can be shared by every row.
    /// </summary>
    public static readonly ImageSource PlaceholderIconSource = CreatePlaceholder();

    private static ImageSource CreatePlaceholder()
    {
        // Front window (full outline) + back sheet (right and bottom edges),
        // the classic "unknown application" glyph.
        const string front =
            "M5.5,1.5 L12.5,1.5 A1.5,1.5 0 0 1 14,3 L14,8 A1.5,1.5 0 0 1 12.5,9.5 " +
            "L5.5,9.5 A1.5,1.5 0 0 1 4,8 L4,3 A1.5,1.5 0 0 1 5.5,1.5 Z";
        const string back =
            "M11.5,11.5 L12.5,11.5 A1.5,1.5 0 0 0 14,10 L14,6 " +
            "M2.5,6.5 L2.5,13 A1.5,1.5 0 0 0 4,14.5 L10,14.5 A1.5,1.5 0 0 0 11.5,13 L11.5,12.5";

        var geometry = Geometry.Parse($"{front} {back}");
        var pen = new Pen(new SolidColorBrush(System.Windows.Media.Color.FromRgb(0x99, 0x9B, 0x9F)), 1.5)
        {
            StartLineCap = PenLineCap.Round,
            EndLineCap = PenLineCap.Round,
            LineJoin = PenLineJoin.Round
        };
        var image = new DrawingImage(new GeometryDrawing { Geometry = geometry, Pen = pen });
        image.Freeze();
        return image;
    }
}
