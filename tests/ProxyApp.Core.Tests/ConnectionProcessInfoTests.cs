using ProxyApp.Core.Processes;

namespace ProxyApp.Core.Tests;

/// <summary>
/// Tests for the <see cref="ConnectionProcessInfo"/> record returned by
/// process attribution. The ExecutablePath member is optional (null when the
/// path cannot be read).
/// </summary>
public class ConnectionProcessInfoTests
{
    [Fact]
    public void Constructor_WithPath_SetsAllMembers()
    {
        var info = new ConnectionProcessInfo(
            1234, "curl.exe", @"C:\Tools\curl.exe");

        Assert.Equal(1234, info.ProcessId);
        Assert.Equal("curl.exe", info.ExecutableName);
        Assert.Equal(@"C:\Tools\curl.exe", info.ExecutablePath);
    }

    [Fact]
    public void Constructor_WithoutPath_DefaultsToNull()
    {
        var info = new ConnectionProcessInfo(1234, "curl.exe");

        Assert.Equal(1234, info.ProcessId);
        Assert.Equal("curl.exe", info.ExecutableName);
        Assert.Null(info.ExecutablePath);
    }

    [Fact]
    public void Records_WithSameValues_AreEqual()
    {
        var a = new ConnectionProcessInfo(1, "a.exe", @"C:\a.exe");
        var b = new ConnectionProcessInfo(1, "a.exe", @"C:\a.exe");

        Assert.Equal(a, b);
    }

    [Fact]
    public void Records_WithDifferentPath_AreNotEqual()
    {
        var a = new ConnectionProcessInfo(1, "a.exe", @"C:\a.exe");
        var b = new ConnectionProcessInfo(1, "a.exe", null);

        Assert.NotEqual(a, b);
    }
}
