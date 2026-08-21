using System.Runtime.InteropServices;

namespace ProxyApp.WinDivert;

/// <summary>
/// WinDivert layer identifiers. Only the Network and Flow layers are used by
/// this application.
/// </summary>
internal enum WinDivertLayer : uint
{
    /// <summary>Captures/injects IP packets on the network stack path.</summary>
    Network = 0,

    /// <summary>Captures/injects packets on the forwarding path.</summary>
    NetworkForward = 1,

    /// <summary>Observes TCP/UDP connection events (FLOW_ESTABLISHED, FLOW_DELETED).</summary>
    Flow = 2,

    /// <summary>Observes socket events.</summary>
    Socket = 3,

    /// <summary>Reflection of packets back to the caller.</summary>
    Reflect = 4
}

/// <summary>
/// WinDivert 2.2 WINDIVERT_ADDRESS, matching the native layout. The bitfield
/// (Layer/Event/flags) occupies a UINT64 at offset 8; the union occupies
/// offset 16. This struct is 80 bytes on x64; the fields used here align with
/// the native definition.
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 80)]
internal struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;

    /// <summary>
    /// Packed bitfield (UINT64): Layer(8) | Event(8) | Sniffed(1) | Outbound(1) |
    /// Loopback(1) | Impostor(1) | IPv6(1) | IPChecksum(1) | TCPChecksum(1) |
    /// UDPChecksum(1) | Reserved.
    /// </summary>
    [FieldOffset(8)] public ulong LayerEventFlags;

    // Network layer (union at offset 16).
    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;

    // Flow/Socket layer (overlaps Network via the union).
    [FieldOffset(16)] public ulong Flow_EndpointId;
    [FieldOffset(24)] public ulong Flow_ParentEndpointId;
    [FieldOffset(32)] public uint Flow_ProcessId;
    [FieldOffset(36)] public uint Flow_LocalAddr0;
    [FieldOffset(40)] public uint Flow_LocalAddr1;
    [FieldOffset(44)] public uint Flow_LocalAddr2;
    [FieldOffset(48)] public uint Flow_LocalAddr3;
    [FieldOffset(52)] public uint Flow_RemoteAddr0;
    [FieldOffset(56)] public uint Flow_RemoteAddr1;
    [FieldOffset(60)] public uint Flow_RemoteAddr2;
    [FieldOffset(64)] public uint Flow_RemoteAddr3;
    [FieldOffset(68)] public ushort Flow_LocalPort;
    [FieldOffset(70)] public ushort Flow_RemotePort;
    [FieldOffset(72)] public byte Flow_Protocol;

    /// <summary>Layer identifier (bits 0–7).</summary>
    public byte Layer => (byte)(LayerEventFlags & 0xFF);

    /// <summary>Event identifier (bits 8–15).</summary>
    public byte Event => (byte)((LayerEventFlags >> 8) & 0xFF);

    /// <summary>True when the packet was captured in SNIFF mode (bit 16).</summary>
    public bool Sniffed => ((LayerEventFlags >> 16) & 1) != 0;

    /// <summary>True for an outbound packet, false for inbound (bit 17).</summary>
    public bool Outbound => ((LayerEventFlags >> 17) & 1) != 0;

    /// <summary>True for a loopback packet (bit 18).</summary>
    public bool Loopback => ((LayerEventFlags >> 18) & 1) != 0;

    /// <summary>True when injected by another driver (bit 19).</summary>
    public bool Impostor => ((LayerEventFlags >> 19) & 1) != 0;

    /// <summary>True for an IPv6 packet (bit 20).</summary>
    public bool IPv6 => ((LayerEventFlags >> 20) & 1) != 0;

    /// <summary>True when the IPv4 checksum is valid (bit 21).</summary>
    public bool IpChecksumValid => ((LayerEventFlags >> 21) & 1) != 0;

    /// <summary>True when the TCP checksum is valid (bit 22).</summary>
    public bool TcpChecksumValid => ((LayerEventFlags >> 22) & 1) != 0;

    /// <summary>True when the UDP checksum is valid (bit 23).</summary>
    public bool UdpChecksumValid => ((LayerEventFlags >> 23) & 1) != 0;
}

/// <summary>
/// P/Invoke surface for the WinDivert 2.2 user-mode library.
/// </summary>
internal static class WinDivertNative
{
    private const string Dll = "WinDivert.dll";

    /// <summary>Open a WinDivert handle for capture and/or injection.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    internal static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        WinDivertLayer layer,
        short priority,
        ulong flags);

    /// <summary>Receive a captured packet/event from a handle.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    internal static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ref WinDivertAddress pAddr);

    /// <summary>Send (re-inject) a packet on a handle.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    internal static extern bool WinDivertSend(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        IntPtr pSendLen,
        ref WinDivertAddress pAddr);

    /// <summary>Close a handle, releasing its capture/injection resources.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    internal static extern bool WinDivertClose(IntPtr handle);

    /// <summary>Set a handle parameter (e.g. queue length, queue time, queue size).</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    internal static extern bool WinDivertSetParam(IntPtr handle, uint param, ulong value);

    /// <summary>Recalculate IP/TCP/UDP checksums and update the address checksum flags.</summary>
    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    internal static extern bool WinDivertHelperCalcChecksums(
        byte[] pPacket,
        uint packetLen,
        ref WinDivertAddress pAddr,
        ulong flags);

    /// <summary>WinDivert handle flags.</summary>
    internal static class Flags
    {
        /// <summary>Sniff mode: copy the packet rather than drop-and-divert.</summary>
        internal const ulong Sniff = 0x1;

        /// <summary>Receive-only: disables WinDivertSend.</summary>
        internal const ulong ReceiveOnly = 0x4;

        /// <summary>Sniff + receive-only (passive observer).</summary>
        internal const ulong SniffAndReceiveOnly = Sniff | ReceiveOnly;
    }

    /// <summary>WinDivert handle parameters (queue tuning).</summary>
    internal static class Params
    {
        internal const uint QueueLength = 0;
        internal const uint QueueTime = 1;
        internal const uint QueueSize = 2;
    }
}
