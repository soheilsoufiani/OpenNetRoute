using System.Collections.Concurrent;
using System.Text;
using System.Windows;
using System.Windows.Threading;

namespace ProxyApp;

/// <summary>
/// The Debug / Log window. Shows the ferry's trace output (and app-level
/// events) as a plain-text, monospace, scrollable log with Copy and Clear.
///
/// The trace sink fires on background threads; it appends a line to a bounded
/// <see cref="ConcurrentQueue{T}"/> (fire-and-forget, never blocks the capture
/// path). A <see cref="DispatcherTimer"/> drains the queue onto the UI thread
/// in batches, so the window stays responsive even under a browser burst.
/// </summary>
public partial class DebugWindow : Window
{
    /// <summary>Maximum lines retained (ring buffer bound).</summary>
    public const int MaxLines = 2000;

    private readonly ConcurrentQueue<string> _pending = new();
    private readonly DispatcherTimer _timer;
    private readonly StringBuilder _text = new();

    public DebugWindow()
    {
        InitializeComponent();
        _timer = new DispatcherTimer(DispatcherPriority.Background, Dispatcher)
        {
            Interval = TimeSpan.FromMilliseconds(250)
        };
        _timer.Tick += (_, _) => DrainPending();
        _timer.Start();
    }

    /// <summary>
    /// The trace sink: appends a line to the ring buffer. Safe from any thread;
    /// never blocks (drop-oldest on overflow).
    /// </summary>
    public void Append(string line)
    {
        while (_pending.Count >= MaxLines)
            _pending.TryDequeue(out _);
        _pending.Enqueue(line);
    }

    private void DrainPending()
    {
        var batch = 0;
        while (batch < 500 && _pending.TryDequeue(out var line))
        {
            _text.AppendLine(line);
            batch++;
        }
        if (batch > 0)
        {
            // Rebuild + set once per batch; auto-scroll to the latest line.
            LogTextBox.Text = _text.ToString();
            LogTextBox.ScrollToEnd();
        }

        // Keep the bound (drop the oldest lines when the buffer overflows).
        while (LineCount(_text) > MaxLines)
            TrimFirstLine(_text);
    }

    private static int LineCount(StringBuilder sb)
    {
        var count = 0;
        for (var i = 0; i < sb.Length; i++)
            if (sb[i] == '\n') count++;
        return count;
    }

    private static void TrimFirstLine(StringBuilder sb)
    {
        var idx = sb.ToString().IndexOf('\n');
        if (idx >= 0)
            sb.Remove(0, idx + 1);
        else
            sb.Clear();
    }

    private void OnCopyClicked(object sender, RoutedEventArgs e)
    {
        if (_text.Length > 0)
            Clipboard.SetText(_text.ToString());
    }

    private void OnClearClicked(object sender, RoutedEventArgs e)
    {
        _text.Clear();
        LogTextBox.Text = "";
    }

    protected override void OnClosed(EventArgs e)
    {
        _timer.Stop();
        base.OnClosed(e);
    }
}
