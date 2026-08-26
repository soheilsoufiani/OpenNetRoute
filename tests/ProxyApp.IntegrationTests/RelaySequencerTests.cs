using ProxyApp.WinDivert;

namespace ProxyApp.IntegrationTests;

/// <summary>
/// Tests for the client→upstream relay sequencer: the exactly-once planning
/// that drops retransmissions, keepalive probes and gap segments instead of
/// corrupting the upstream byte stream (the Speedtest upload failure).
/// </summary>
public class RelaySequencerTests
{
    private const uint Expected = 1000; // NextClientAck-style expected sequence

    [Fact]
    public void ExactContinuation_RelaysEverything()
    {
        var plan = RelaySequencer.Plan(Expected, Expected, 536);
        Assert.False(plan.IsGap);
        Assert.Equal(0, plan.SkipBytes);
    }

    [Fact]
    public void FullyOldRetransmit_IsDropped()
    {
        // Retransmission of the segment [900, 1000) — entirely below expected.
        var plan = RelaySequencer.Plan(Expected, 900, 100);
        Assert.False(plan.IsGap);
        Assert.Equal(100, plan.SkipBytes); // nothing new to relay
    }

    [Fact]
    public void KeepaliveProbe_IsDropped()
    {
        // Windows keepalive/persist probe: one byte at seq-1 carrying
        // already-ACKed data.
        var plan = RelaySequencer.Plan(Expected, Expected - 1, 1);
        Assert.False(plan.IsGap);
        Assert.Equal(1, plan.SkipBytes);
    }

    [Fact]
    public void PartialOverlap_SlicesToTheNewTail()
    {
        // Segment [950, 1050): first 50 bytes already relayed.
        var plan = RelaySequencer.Plan(Expected, 950, 100);
        Assert.False(plan.IsGap);
        Assert.Equal(50, plan.SkipBytes);
    }

    [Fact]
    public void SegmentAheadOfExpected_IsAGap()
    {
        var plan = RelaySequencer.Plan(Expected, Expected + 200, 100);
        Assert.True(plan.IsGap);
    }

    [Fact]
    public void ZeroLengthSegment_IsNotRelayed()
    {
        var plan = RelaySequencer.Plan(Expected, Expected - 500, 0);
        Assert.Equal(0, plan.SkipBytes);
        Assert.False(plan.IsGap);
    }

    [Fact]
    public void SequenceWraparound_IsHandled()
    {
        // Expected near the top of the 32-bit space; segment wraps past zero.
        const uint nearTop = 0xFFFFFF00u;
        var plan = RelaySequencer.Plan(nearTop, unchecked(nearTop + 300), 100);
        Assert.True(plan.IsGap);

        var exact = RelaySequencer.Plan(nearTop, nearTop, 512);
        Assert.False(exact.IsGap);
        Assert.Equal(0, exact.SkipBytes);

        // Old segment just before wraparound.
        var old = RelaySequencer.Plan(nearTop, unchecked(nearTop - 10), 10);
        Assert.False(old.IsGap);
        Assert.Equal(10, old.SkipBytes);
    }

    [Theory]
    [InlineData(1000, 1000, 536, false, 0)]   // in order
    [InlineData(1000, 900, 100, false, 100)]  // fully duplicate
    [InlineData(1000, 990, 20, false, 10)]    // partial overlap
    [InlineData(1000, 1100, 40, true, 40)]    // gap ahead
    public void PlanningMatrix_MatchesTcpSemantics(
        uint expected, uint seq, int len, bool isGap, int skip)
    {
        var plan = RelaySequencer.Plan(expected, seq, len);
        Assert.Equal(isGap, plan.IsGap);
        Assert.Equal(skip, plan.SkipBytes);
    }
}

public class SequenceComparisonTests
{
    [Theory]
    [InlineData(1000u, 1000u, true)]    // equal
    [InlineData(1500u, 1000u, true)]    // ahead
    [InlineData(500u, 1000u, false)]    // behind
    [InlineData(100u, 0xFFFFFF00u, true)]  // wrapped past 2^32: 0x64 is after 0xFFFFFF00
    [InlineData(0xFFFFFF00u, 100u, false)] // and the reverse
    public void SequenceAtLeast_IsWraparoundSafe(uint a, uint b, bool expected)
        => Assert.Equal(expected, TcpFerry.SequenceAtLeast(a, b));
}
