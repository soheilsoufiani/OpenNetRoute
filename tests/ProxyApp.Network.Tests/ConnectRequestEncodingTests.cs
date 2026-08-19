namespace ProxyApp.Network.Tests;

/// <summary>
/// Tests for the pure wire-encoding logic of a SOCKS5 CONNECT request
/// (<see cref="Socks5Client.BuildConnectRequest"/>). No network I/O involved.
/// </summary>
public class ConnectRequestEncodingTests
{
    [Fact]
    public void Ipv4Destination_EncodesAsAtypIpv4()
    {
        var bytes = Socks5Client.BuildConnectRequest(new Socks5Destination("192.168.1.10", 443));

        // VER=5, CMD=CONNECT, RSV=0, ATYP=1 (IPv4), then 4 address bytes, then port.
        Assert.Equal(new byte[] { 0x05, 0x01, 0x00, 0x01 }, bytes[..4]);
        Assert.Equal(new byte[] { 192, 168, 1, 10 }, bytes[4..8]);
        Assert.Equal(new byte[] { 0x01, 0xBB }, bytes[8..10]); // 443 = 0x01BB
    }

    [Fact]
    public void Ipv6Destination_EncodesAsAtypIpv6()
    {
        var bytes = Socks5Client.BuildConnectRequest(new Socks5Destination("::1", 80));

        // VER=5, CMD=CONNECT, RSV=0, ATYP=4 (IPv6), then 16 address bytes, then port.
        Assert.Equal(new byte[] { 0x05, 0x01, 0x00, 0x04 }, bytes[..4]);
        Assert.Equal(16, bytes.Length - 4 - 2);
        // ::1 = fifteen 0x00 bytes then 0x01.
        Assert.Equal(0x00, bytes[4]);
        Assert.Equal(0x01, bytes[19]);
        Assert.Equal(new byte[] { 0x00, 0x50 }, bytes[^2..]); // 80 = 0x0050
    }

    [Fact]
    public void DomainDestination_EncodesAsAtypDomain()
    {
        var bytes = Socks5Client.BuildConnectRequest(new Socks5Destination("example.com", 1080));

        // VER, CMD, RSV, ATYP=3(domain), then length-prefixed name, then port.
        Assert.Equal(new byte[] { 0x05, 0x01, 0x00, 0x03 }, bytes[..4]);
        Assert.Equal(11, bytes[4]); // "example.com" length
        Assert.Equal("example.com", System.Text.Encoding.ASCII.GetString(bytes, 5, 11));
        Assert.Equal(new byte[] { 0x04, 0x38 }, bytes[^2..]); // 1080 = 0x0438
    }

    [Fact]
    public void HostAndPort_RoundTripThroughEncoding()
    {
        foreach (var host in new[] { "127.0.0.1", "10.0.0.5", "example.org", "a.b.c" })
        {
            var bytes = Socks5Client.BuildConnectRequest(new Socks5Destination(host, 1234));
            Assert.Equal(5, bytes[0]);
            Assert.Equal(1, bytes[1]);
            Assert.Equal(0, bytes[2]);
            Assert.Equal(new byte[] { 0x04, 0xD2 }, bytes[^2..]); // 1234 = 0x04D2
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void OutOfRangePort_Throws(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => Socks5Client.BuildConnectRequest(new Socks5Destination("example.com", port)));
    }

    [Fact]
    public void NullHost_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => Socks5Client.BuildConnectRequest(new Socks5Destination(null!, 80)));
    }
}