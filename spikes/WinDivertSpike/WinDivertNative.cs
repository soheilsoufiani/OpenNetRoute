using System.Runtime.InteropServices;

namespace WinDivertSpike;

/// <summary>
/// P/Invoke surface for WinDivert 2.2, matching the official windivert.h.
/// This is spike-only code, isolated from production. The layout follows the
/// official header (verified against the WinDivert 2.2 source).
/// </summary>
internal enum WinDivertLayer : uint
{
    Network = 0,
    NetworkForward = 1,
    Flow = 2,
    Socket = 3,
    Reflect = 4
}

/// <summary>
/// WinDivert 2.2 WINDIVERT_ADDRESS (86 bytes total):
///   INT64 Timestamp
///   UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1,
///          IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8
///   UINT32 Reserved2
///   union { Network | Flow | Socket | Reflect } [64 bytes]
/// </summary>
[StructLayout(LayoutKind.Explicit, Size = 88)]
internal struct WinDivertAddress
{
    [FieldOffset(0)] public long Timestamp;

    [FieldOffset(8)] public uint LayerEventFlags;

    [FieldOffset(12)] public uint Reserved2;

    // ---- Network layer (union at offset 16) ----
    [FieldOffset(16)] public uint IfIdx;
    [FieldOffset(20)] public uint SubIfIdx;

    // ---- Flow/Socket layer (overlaps Network via union; offset 16..80) ----
    [FieldOffset(16)] public ulong EndpointId;
    [FieldOffset(24)] public ulong ParentEndpointId;
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

    public byte Layer => (byte)((LayerEventFlags >> 0) & 0xFF);
    public byte Event => (byte)((LayerEventFlags >> 8) & 0xFF);
    public bool Sniffed => ((LayerEventFlags >> 16) & 1) != 0;
    public bool Outbound => ((LayerEventFlags >> 17) & 1) != 0;
    public bool Loopback => ((LayerEventFlags >> 18) & 1) != 0;
    public bool IPv6 => ((LayerEventFlags >> 20) & 1) != 0;
}

internal static class WinDivertNative
{
    private const string Dll = "WinDivert.dll";

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern IntPtr WinDivertOpen(
        [MarshalAs(UnmanagedType.LPStr)] string filter,
        WinDivertLayer layer,
        short priority,
        ulong flags);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertRecv(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        ref uint pRecvLen,
        ref WinDivertAddress pAddr);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertSend(
        IntPtr handle,
        byte[] pPacket,
        uint packetLen,
        IntPtr pSendLen,
        ref WinDivertAddress pAddr);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertClose(IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertSetParam(IntPtr handle, uint param, ulong value);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertGetParam(IntPtr handle, uint param, out ulong value);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl, SetLastError = true)]
    public static extern bool WinDivertHelperCalcChecksums(
        byte[] pPacket,
        uint packetLen,
        ref WinDivertAddress pAddr,
        ulong flags);
}