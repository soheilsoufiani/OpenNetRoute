namespace ProxyApp.WinDivert;

/// <summary>
/// The relay decision for a captured client payload segment, produced by
/// <see cref="RelaySequencer.Plan"/>: how many leading bytes are duplicates to
/// skip and whether the segment starts beyond the expected sequence (a gap).
/// The new-byte count is the payload length minus <see cref="SkipBytes"/>.
/// </summary>
internal readonly record struct RelayPlan(int SkipBytes, bool IsGap);

/// <summary>
/// Sequence-space planning for the client→upstream relay.
///
/// WHY THIS EXISTS (2026-08 Speedtest finding): the relay previously wrote
/// EVERY captured payload packet verbatim into the upstream stream. TCP makes
/// that incorrect: retransmissions duplicate bytes, and keepalive/persist
/// probes carry one byte of ALREADY-ACKED data at seq-1 — relaying either
/// corrupts the byte stream (e.g. TLS records) and the far end kills the
/// connection. Under upload saturation the local proxy backpressures the
/// ferry's writes, the client stalls and sends persist probes, and every probe
//  byte was injected as fresh data — the observed "upload gave an error".
///
/// Exactly-once invariant: only the bytes at or after the expected sequence
/// (<see cref="FlowState.NextClientAck"/>) are ever relayed; duplicates are
/// dropped (with a fresh ACK so the client does not stall), partially
/// overlapping segments are sliced, and gap segments (should not occur —
/// same-flow packets are serialized and nothing else skips data) are dropped
/// in favor of the expected retransmission.
///
/// Pure functions; no WinDivert state; unit-testable without a handle.
/// </summary>
internal static class RelaySequencer
{
    /// <summary>
    /// Plans how to relay a segment of <paramref name="payloadLen"/> bytes at
    /// <paramref name="segSeq"/> when <paramref name="expectedSeq"/> is the
    /// next byte the ferry has NOT yet written upstream. All arithmetic is
    /// wraparound-safe (32-bit sequence space).
    /// </summary>
    public static RelayPlan Plan(uint expectedSeq, uint segSeq, int payloadLen)
    {
        if (payloadLen <= 0)
            return new RelayPlan(0, false);

        // Distance from expected to segment start, interpreted as signed via
        // the sequence-space half-window.
        var delta = segSeq - expectedSeq; // uint subtraction wraps correctly
        if (delta < 0x80000000u)
        {
            if (delta != 0)
                return new RelayPlan(payloadLen, true); // gap ahead: drop, ACK, await retransmit
            return new RelayPlan(0, false);             // exact continuation
        }

        var overlap = (int)(expectedSeq - segSeq);
        return overlap >= payloadLen
            ? new RelayPlan(payloadLen, false)          // fully old (retransmit/probe)
            : new RelayPlan(overlap, false);            // partial overlap: slice prefix
    }
}
