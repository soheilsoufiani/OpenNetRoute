using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace ProxyApp;

/// <summary>
/// One line in the Debug/Log panel: timestamp + level + message.
/// Immutable after creation; displayed in a virtualized list.
/// </summary>
public sealed class LogLine : INotifyPropertyChanged
{
    public string Timestamp { get; }
    public string Level { get; }
    public string Message { get; }

    public LogLine(string timestamp, string level, string message)
    {
        Timestamp = timestamp;
        Level = level;
        Message = message;
    }

    // The list is a plain ObservableCollection<LogLine>; the binding reads the
    // properties once per row. INotifyPropertyChanged is not strictly needed
    // (lines are never mutated) but kept for consistency with the other rows.
    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
