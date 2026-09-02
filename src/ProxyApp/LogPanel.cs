using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Windows.Threading;

namespace ProxyApp;

/// <summary>
/// Thread-safe bounded log ring buffer for the Debug/Log panel.
///
/// The ferry's trace sink fires on background threads (capture loop, per-flow
/// consumers, upstream pumps) and MUST never block or allocate heavily. This
/// sink appends a pre-formatted string to a <see cref="ConcurrentQueue{T}"/>
/// (fire-and-forget, bounded at <see cref="MaxLines"/>), and a
/// <see cref="DispatcherTimer"/> drains the queue in batches onto the UI
/// thread (default 250ms), appending to the bound
/// <see cref="ObservableCollection{T}"/> (also bounded). No UI work or I/O
/// ever happens inline in the trace callback.
/// </summary>
public sealed class LogPanel
{
    /// <summary>Maximum lines retained (ring buffer bound).</summary>
    public const int MaxLines = 2000;

    /// <summary>The lines displayed in the panel (UI thread only).</summary>
    public ObservableCollection<LogLine> Lines { get; } = new();

    /// <summary>
    /// Raised on the panel's dispatcher thread whenever the flattened text view
    /// of the log changed: lines were appended, ring-buffer overflow trimmed
    /// lines from the front, or the whole log was cleared. Text-view consumers
    /// (the Debug window) apply the delta instead of rebuilding everything.
    /// </summary>
    public event EventHandler<PlainLogChangedEventArgs>? TextLogChanged;

    private readonly ConcurrentQueue<string> _pending = new();
    private readonly DispatcherTimer _timer;
    private readonly Dispatcher _dispatcher;

    /// <summary>
    /// Creates the panel and starts the 250ms batch-drain timer on the given
    /// dispatcher (the UI thread).
    /// </summary>
    public LogPanel(Dispatcher dispatcher)
    {
        _dispatcher = dispatcher;
        _timer = new DispatcherTimer(DispatcherPriority.Background, dispatcher)
        {
            Interval = TimeSpan.FromMilliseconds(250)
        };
        _timer.Tick += (_, _) => DrainPending();
        _timer.Start();
    }

    /// <summary>
    /// Appends a line to the ring buffer. Safe to call from any thread; never
    /// blocks (bounded queue, drop-oldest on overflow).
    /// </summary>
    public void Append(string line)
    {
        // Drop-oldest when the queue is full so the panel always shows the
        // most recent activity under burst (e.g. a browser opening 30
        // connections at once).
        while (_pending.Count >= MaxLines)
            _pending.TryDequeue(out _);
        _pending.Enqueue(line);
    }

    /// <summary>
    /// Convenience for app-level events: formats with a timestamp and level,
    /// then appends.
    /// </summary>
    public void Log(string level, string message)
    {
        Append($"{DateTime.Now:HH:mm:ss.fff} [{level}] {message}");
    }

    /// <summary>Clears both the displayed lines and any pending queue.</summary>
    public void Clear()
    {
        while (_pending.TryDequeue(out _)) { }
        Lines.Clear();
        TextLogChanged?.Invoke(this, PlainLogChangedEventArgs.Cleared);
    }

    /// <summary>
    /// Copies the current displayed lines to the clipboard as one text block.
    /// Called from the UI thread (button handler).
    /// </summary>
    public void CopyToClipboard()
    {
        var text = string.Join(Environment.NewLine, Lines.Select(l => $"{l.Timestamp} {l.Level} {l.Message}"));
        if (text.Length > 0)
            System.Windows.Clipboard.SetText(text);
    }

    /// <summary>Stops the drain timer (window closing).</summary>
    public void Shutdown() => _timer.Stop();

    private void DrainPending()
    {
        // Drain up to a batch bound per tick so a huge burst cannot stall the
        // UI thread; the queue keeps the rest for the next tick.
        var batch = 0;
        List<LogLine>? added = null;
        while (batch < 500 && _pending.TryDequeue(out var line))
        {
            var parsed = ParseLine(line);
            Lines.Add(parsed);
            (added ??= []).Add(parsed);
            batch++;
        }

        if (added is null)
            return;

        // Keep the bound on the displayed collection too; text-view consumers
        // need the count so they can trim their own front the same way.
        var removed = 0;
        while (Lines.Count > MaxLines)
        {
            Lines.RemoveAt(0);
            removed++;
        }

        TextLogChanged?.Invoke(this, new PlainLogChangedEventArgs(added, removed, reset: false));
    }

    /// <summary>
    /// Splits a raw trace line ("[TcpFerry] msg" / "HH:mm:ss.fff [LEVEL] msg")
    /// into timestamp + level + message for display. Lines without a level
    /// default to [TRACE].
    /// </summary>
    private static LogLine ParseLine(string line)
    {
        // Already-formatted app event: "12:34:56.789 [ERR] msg".
        if (line.Length >= 21 &&
            line[2] == ':' && line[5] == ':' && line[8] == '.' &&
            line[12] == '[')
        {
            var ts = line.Substring(0, 12);
            var level = line.Substring(13, line.IndexOf(']', 13) - 13);
            var msg = line.Substring(line.IndexOf(']', 13) + 2);
            return new LogLine(ts, level, msg);
        }

        // Raw ferry trace: "[TcpFerry] msg".
        return new LogLine(DateTime.Now.ToString("HH:mm:ss.fff"), "TRACE", line);
    }
}

/// <summary>
/// Delta applied to a flattened text view of the <see cref="LogPanel"/>
/// contents. Raised only on the panel's dispatcher thread (the drain timer /
/// UI-thread callers), so consumers may touch UI directly.
/// </summary>
public sealed class PlainLogChangedEventArgs : EventArgs
{
    /// <summary>Shared "the whole log was cleared" notification.</summary>
    public static readonly PlainLogChangedEventArgs Cleared =
        new(Array.Empty<LogLine>(), 0, reset: true);

    public PlainLogChangedEventArgs(IReadOnlyList<LogLine> added, int removedFromFront, bool reset)
    {
        Added = added;
        RemovedFromFront = removedFromFront;
        Reset = reset;
    }

    /// <summary>Lines newly appended to the end of the log (empty on reset).</summary>
    public IReadOnlyList<LogLine> Added { get; }

    /// <summary>How many lines were trimmed from the FRONT by ring-buffer overflow.</summary>
    public int RemovedFromFront { get; }

    /// <summary>True when the whole view must be cleared.</summary>
    public bool Reset { get; }
}
