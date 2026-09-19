using System.Net;
using System.Net.Sockets;

namespace ProxyApp.Network.Tests.TestInfrastructure;

/// <summary>
/// A SOCKS5 UDP ASSOCIATE relay peer for the client tests: pairs a
/// <see cref="Socks5TestServer"/> (the TCP control leg — greeting, method
/// selection, the CMD 3 request, the success reply with the relay endpoint)
/// with a real local UDP relay socket. Every datagram the client relays is
/// unwrapped (RSV/FRAG/ATYP/ADDR/PORT header), echoed as a DNS-style reply
/// (echoed ID + question, A=192.0.2.1) addressed to the ORIGINAL query target,
/// re-wrapped, and sent back to the client — a genuine protocol peer, no fakes.
/// </summary>
public sealed class Socks5UdpAssociateTestServer : IDisposable
{
    private readonly Socks5TestServer _control;
    private readonly UdpClient _relay;
    private readonly CancellationTokenSource _cts = new();

    /// <summary>Number of datagrams the UDP relay has received (diagnostics).</summary>
    public int DatagramsReceived { get; private set; }

    /// <summary>Optional diagnostics sink.</summary>
    public Action<string>? TraceSink { get; set; }

    private void Log(string message) => TraceSink?.Invoke($"[test-relay] {message}");

    public Socks5UdpAssociateTestServer()
    {
        _relay = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var relayPort = ((IPEndPoint)_relay.Client.LocalEndPoint!).Port;

        _control = new Socks5TestServer(async (request, stream, ct) =>
        {
            // UDP ASSOCIATE success reply: BND.ADDR = 127.0.0.1, BND.PORT = relay port.
            await Socks5TestServer.WriteReplyAsync(
                stream, 0x00, Socks5TestServer.AtypIpv4,
                new byte[] { 127, 0, 0, 1 }, relayPort, ct);
        });

        _ = Task.Run(() => RelayLoopAsync(_cts.Token));
    }

    /// <summary>The TCP control port of the SOCKS5 server.</summary>
    public int ControlPort => _control.Port;

    private async Task RelayLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var received = await _relay.ReceiveAsync(ct);
                DatagramsReceived++;
                Log($"received {received.Buffer.Length} bytes from {received.RemoteEndPoint}");

                // Unwrap the RFC 1928 datagram header: RSV(2), FRAG(1), ATYP(1), ADDR, PORT(2).
                var unwrapped = UnwrapDatagram(received.Buffer);
                if (unwrapped is null)
                {
                    Log("unwrap FAILED (frag/atyp/length)");
                    continue;
                }

                // DNS-style reply: echo ID+question, QR=1, A=192.0.2.1.
                // STUN binding requests (type 0x0001) get a Binding Success
                // Response (0x0101) with the 12-byte transaction ID echoed —
                // lets the client tests pin the STUN correlation path.
                var reply = IsStunBinding(unwrapped.Value.Dns)
                    ? BuildStunReply(unwrapped.Value.Dns)
                    : BuildDnsReply(unwrapped.Value.Dns);
                if (reply is null)
                {
                    Log("build-reply FAILED (qdcount/length)");
                    continue;
                }

                var wrapped = WrapDatagram(reply, unwrapped.Value.DstIp, unwrapped.Value.DstPort);
                await _relay.SendAsync(wrapped, received.RemoteEndPoint);
                Log($"sent {wrapped.Length} bytes back to {received.RemoteEndPoint}");
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException)
            {
                // transient — keep serving
            }
            catch (ObjectDisposedException)
            {
                break;
            }
        }
    }

    /// <summary>Strips the RFC 1928 datagram header, returning the DNS payload and target.</summary>
    private static (byte[] Dns, byte[] DstIp, int DstPort)? UnwrapDatagram(byte[] datagram)
    {
        if (datagram.Length < 4 + 1 + 2 + 12) return null;
        var frag = datagram[2];
        if (frag != 0) return null;
        var atyp = datagram[3];
        switch (atyp)
        {
            case 0x01:
                {
                    if (datagram.Length < 10) return null;
                    var dstIp = datagram[4..8];
                    var dstPort = (datagram[8] << 8) | datagram[9];
                    return (datagram[10..], dstIp, dstPort);
                }
            case 0x03:
                {
                    var len = datagram[4];
                    var headerLen = 4 + 1 + len + 2;
                    if (datagram.Length < headerLen + 12) return null;
                    // Target = loopback for the echo (the test never egresses).
                    var dstPort = (datagram[5 + len] << 8) | datagram[6 + len];
                    return (datagram[headerLen..], new byte[] { 127, 0, 0, 1 }, dstPort);
                }
            default:
                return null;
        }
    }

    /// <summary>Builds a DNS reply: echoed ID+question, QR|RA, one A record 192.0.2.1.</summary>
    private static byte[]? BuildDnsReply(byte[] query)
    {
        if (query.Length < 12) return null;
        var qdcount = (ushort)((query[4] << 8) | query[5]);
        if (qdcount == 0) return null;

        var qStart = 12;
        var p = qStart;
        while (p < query.Length && query[p] != 0) { p += 1 + query[p]; }
        if (p >= query.Length) return null;
        var qEnd = p + 1 + 4;

        var answer = new byte[]
        {
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04, 192, 0, 2, 1
        };
        var resp = new byte[12 + (qEnd - qStart) + answer.Length];
        resp[0] = query[0]; resp[1] = query[1];
        resp[2] = 0x81; resp[3] = 0x80;
        resp[5] = 0x01;
        resp[7] = 0x01;
        Array.Copy(query, qStart, resp, 12, qEnd - qStart);
        Array.Copy(answer, 0, resp, 12 + (qEnd - qStart), answer.Length);
        return resp;
    }

    /// <summary>True when the payload looks like a STUN Binding Request (type 0x0001).</summary>
    private static bool IsStunBinding(byte[] payload) =>
        payload.Length >= 20 && payload[0] == 0x00 && payload[1] == 0x01;

    /// <summary>
    /// Minimal STUN Binding Success Response: type 0x0101, message length
    /// echoed, magic cookie + 12-byte transaction ID copied verbatim.
    /// </summary>
    private static byte[] BuildStunReply(byte[] request)
    {
        var reply = new byte[Math.Max(20, request.Length)];
        Array.Copy(request, reply, request.Length);
        reply[0] = 0x01;
        reply[1] = 0x01; // Binding Success Response
        return reply;
    }

    private static byte[] WrapDatagram(byte[] dns, byte[] dstIp, int dstPort)
    {
        // RSV(2) FRAG(1) ATYP(1) ADDR PORT(2) payload — no extra byte.
        var datagram = new byte[4 + dstIp.Length + 2 + dns.Length];
        datagram[3] = 0x01; // ATYP IPv4
        dstIp.CopyTo(datagram, 4);
        var portPos = 4 + dstIp.Length;
        datagram[portPos] = (byte)(dstPort >> 8);
        datagram[portPos + 1] = (byte)dstPort;
        dns.CopyTo(datagram, portPos + 2);
        return datagram;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _relay.Dispose();
        _control.Dispose();
        _cts.Dispose();
    }
}
