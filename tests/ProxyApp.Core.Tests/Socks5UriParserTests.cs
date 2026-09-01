using ProxyApp.Core.Configuration;

namespace ProxyApp.Core.Tests;

public class Socks5UriParserTests
{
    [Theory]
    [InlineData("socks5://user:secret@proxy.example.com:1080")]
    public void ParsesFullUri_WithCredentials(string input)
    {
        Assert.True(Socks5UriParser.TryParse(input, out var proxy));
        Assert.Equal(ProxyProtocol.Socks5, proxy.Protocol);
        Assert.Equal("proxy.example.com", proxy.Host);
        Assert.Equal(1080, proxy.Port);
        Assert.Equal("user", proxy.Username);
        Assert.Equal("secret", proxy.Password);
        Assert.Equal(ProxyAuthenticationType.UsernamePassword, proxy.AuthenticationType);
        Assert.True(proxy.Enabled);
    }

    [Fact]
    public void ParsesUri_WithoutAuth()
    {
        Assert.True(Socks5UriParser.TryParse("socks5://10.0.0.5", out var proxy));
        Assert.Equal("10.0.0.5", proxy.Host);
        Assert.Equal(Socks5UriParser.DefaultPort, proxy.Port); // default port
        Assert.Null(proxy.Username);
        Assert.Null(proxy.Password);
        Assert.Equal(ProxyAuthenticationType.None, proxy.AuthenticationType);
    }

    [Fact]
    public void ParsesUri_LoopbackIp_IsAccepted_LocalProxy()
    {
        // The user-facing regression: "socks5://127.0.0.1:10808" (v2ray/Xray-style
        // local inbound) must parse. Loopback is safe — the ferry's capture filter
        // ("... and not loopback") never intercepts the app's own loopback
        // upstream connection, so no interception loop is possible.
        Assert.True(Socks5UriParser.TryParse("socks5://127.0.0.1:10808", out var proxy));
        Assert.Equal("127.0.0.1", proxy.Host);
        Assert.Equal(10808, proxy.Port);
        Assert.Null(proxy.Username);
        Assert.Null(proxy.Password);
        Assert.Equal(ProxyAuthenticationType.None, proxy.AuthenticationType);
    }

    [Fact]
    public void ParsesUri_LoopbackIp_WithCredentials()
    {
        Assert.True(Socks5UriParser.TryParse("socks5://u:p@127.0.0.1:10808", out var proxy));
        Assert.Equal("127.0.0.1", proxy.Host);
        Assert.Equal(10808, proxy.Port);
        Assert.Equal("u", proxy.Username);
        Assert.Equal("p", proxy.Password);
    }

    [Fact]
    public void ParsesUri_Ipv6Loopback_IsAccepted()
    {
        Assert.True(Socks5UriParser.TryParse("socks5://[::1]:1080", out var proxy));
        Assert.Equal("::1", proxy.Host);
        Assert.Equal(1080, proxy.Port);
        Assert.Null(proxy.Username);
    }

    [Fact]
    public void ParsesUri_UsernameOnly()
    {
        Assert.True(Socks5UriParser.TryParse("socks5://alice@1.2.3.4:9050", out var proxy));
        Assert.Equal("alice", proxy.Username);
        Assert.Null(proxy.Password);
        Assert.Equal(ProxyAuthenticationType.UsernamePassword, proxy.AuthenticationType);
    }

    [Fact]
    public void ParsesUri_PercentEncodedCredentials_AreDecoded()
    {
        // user "weird@user" / pass "p@ss:word" percent-encoded
        var uri = "socks5://weird%40user:p%40ss%3Aword@proxy.example.com:2080";
        Assert.True(Socks5UriParser.TryParse(uri, out var proxy));
        Assert.Equal("weird@user", proxy.Username);
        Assert.Equal("p@ss:word", proxy.Password);
    }

    [Fact]
    public void ParsesUri_EmptyPasswordIsPermitted_Rfc1929()
    {
        Assert.True(Socks5UriParser.TryParse("socks5://bob:@proxy.example.com", out var proxy));
        Assert.Equal("bob", proxy.Username);
        Assert.Equal("", proxy.Password);
        Assert.Equal(ProxyAuthenticationType.UsernamePassword, proxy.AuthenticationType);
    }

    [Fact]
    public void AcceptsWhitespaceAroundInput()
    {
        Assert.True(Socks5UriParser.TryParse("   socks5://1.2.3.4:1080 \r\n", out var proxy));
        Assert.Equal("1.2.3.4", proxy.Host);
    }

    [Fact]
    public void PicksTheFirstParsableLine_FromMultiLinePaste()
    {
        var lines = "some notes\r\nsocks5://u:p@5.6.7.8:1180\r\nmore junk";
        foreach (var line in lines.Split('\n'))
        {
            if (Socks5UriParser.TryParse(line.Trim(), out var proxy))
            {
                Assert.Equal("5.6.7.8", proxy.Host);
                Assert.Equal(1180, proxy.Port);
                return;
            }
        }
        Assert.Fail("No line parsed.");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("http://user:pass@host:8080")]      // wrong scheme
    [InlineData("socks5://")]                        // no host
    [InlineData("socks5://localhost:1080")]          // forbidden host (validator set)
    [InlineData("socks5://0.0.0.0:1080")]            // forbidden host (validator set)
    [InlineData("just some text")]
    public void RejectsInvalidInput(string? input)
    {
        Assert.False(Socks5UriParser.TryParse(input, out _));
    }

    [Fact]
    public void AutoNamesProfile_HostPort()
    {
        Assert.True(Socks5UriParser.TryParse("socks5://1.2.3.4:1080", out var proxy));
        Assert.Equal("1.2.3.4:1080", proxy.Name);
    }
}
