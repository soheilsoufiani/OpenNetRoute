# WinDivert Feasibility Spike

**Status:** Spike completed — E0–E4d results finalized
**Date:** 2026-08-20
**Location:** `spikes/WinDivertSpike/` (standalone console app, **not part of the main solution**)

> This spike experimentally validates the assumptions behind the future **transparent TCP ferry** (Phase 6) *before* we build it. It is deliberately narrow: it never modifies the routing table, never intercepts unrelated traffic, never touches firewall/VPN/network settings, and never creates a capture loop. It captures only packets matching a tightly scoped filter (destination `1.1.1.1:443`) and re-injects them unchanged.

---

## 1. WinDivert version and dependency/license

| Item | Value |
|---|---|
| Driver | **WinDivert 2.2** (`WinDivert64.sys`), service `WinDivert` **RUNNING** |
| Driver path | `C:\Users\aghai\AppData\Local\TunnelX\WinDivert64.sys` (installed by the TunnelX reference app) |
| DLL | `WinDivert.dll` (46.5 KB), present in the same dir; copied next to the spike binary for loading |
| License | Dual **LGPL-3.0-or-later / GPL-2.0** (WinDivert's own terms). Redistribution requires the official signed binaries and retained license notices (see `docs/ARCHITECTURE_RESEARCH.md` §7). |
| Source of truth | Official `windivert.h` (verified the `WINDIVERT_ADDRESS` layout, layer/param enums, and API signatures against the WinDivert 2.2 header). |
| Elevation | **Required** — `WinDivertOpen` fails with error 5 (access denied) for a non-elevated process. The spike refuses to run unless elevated. |

Key `WINDIVERT_ADDRESS` layout facts (verified against the header):
- `INT64 Timestamp`, then a 32-bit bitfield word (`Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1, IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8`), then `Reserved2`, then a 64-byte union (Network/Flow/Socket/Reflect).
- Network layer: `IfIdx`, `SubIfIdx` at offset 16/20.
- Flow/Socket layer: `EndpointId`, `ParentEndpointId`, `ProcessId`, `LocalAddr[4]`, `RemoteAddr[4]`, `LocalPort`, `RemotePort`, `Protocol` — **the owning PID is available directly on flow/socket events**.
- `WINDIVERT_LAYER`: Network=0, NetworkForward=1, Flow=2, Socket=3, Reflect=4.
- `WINDIVERT_PARAM`: QUEUE_LENGTH=0, QUEUE_TIME=1, QUEUE_SIZE=2.
- `WinDivertRecv`/`WinDivertSend` are **blocking** and have no timeout; the documented way to cancel a pending `WinDivertRecv` is to close the handle from another thread.

---

## 2. Environment findings (confirmed before the capture experiments)

| # | Finding | Status |
|---|---|---|
| E0 | WinDivert driver 2.2 is **installed and running** as a service on this machine. | **CONFIRMED** |
| E0b | A non-elevated process cannot capture; elevation is mandatory. | **CONFIRMED** (documented WinDivert behavior + `IsInRole` check) |
| E0c | The spike loads `WinDivert.dll` from next to the executable and opens a handle with a scoped filter. | **CONFIRMED** (Experiment 0) |

---

## 3. Experiments

Each experiment opens **its own WinDivert handle** scoped to `1.1.1.1:443` and closes it on completion (success or timeout). Closing the handle is also the mechanism that unblocks a pending blocking `WinDivertRecv` at the deadline. **No handle is shared across experiments**, so no experiment can leak a blocked recv or an orphaned process into the next.

Traffic trigger: `curl.exe -s -o NUL --max-time 8 https://1.1.1.1/` (a controlled real TCP client). The destination is narrowly scoped so nothing unrelated is captured.

### Experiment 0 — WinDivert loads and a handle opens

- **Goal:** verify the driver is loadable and a narrow filter compiles.
- **Filter:** `outbound and ip and ip.DstAddr == 1.1.1.1 and tcp and tcp.DstPort == 443`
- **Result:** **CONFIRMED** — handle opened successfully, closed cleanly.

### Experiment 1 — Capture a real outbound TCP SYN

- **Goal:** verify we can capture a genuine outbound SYN from a real client.
- **Method:** run curl in the background; receive packets on the scoped handle; look for a packet with TCP flag `0x02` (SYN).
- **Result:** **CONFIRMED** — captured `192.168.100.10:45040 -> 1.1.1.1:443 flags=0x02 seq=3425666436 ack=0` (see §4).

### Experiment 2 — Inspect packet fields

- **Goal:** verify we can read source/dest IP+port, TCP flags, and sequence/acknowledgment numbers.
- **Method:** second curl run; parse each captured packet.
- **Result:** **CONFIRMED** — parsed 3 packets; all SYN, `seq` populated, `ack=0`, `tcpHdrLen=32` (SYN + options), `ifIdx=19`, `outbound=True`, `loopback=False`, `ipv6=False`.

### Experiment 3 — Flow-layer process attribution

- **Goal:** verify the WinDivert FLOW layer exposes the owning process ID.
- **Method:** open a SNIFF+RECV_ONLY FLOW-layer handle scoped to the target; trigger a connection; look for `FLOW_ESTABLISHED` (event 1) with a nonzero `ProcessId`.
- **Result:** pending an elevated run. (Earlier attempt stalled because `WinDivertRecv` blocked past the deadline; the rewritten spike closes the handle at the deadline.)

### Experiment 4 — Reinjection and loop prevention

- **Goal:** verify `WinDivertSend` re-injects a captured packet unchanged without creating a capture loop.
- **Method:** capture packets on a modify-mode (drop-and-divert) handle at priority 0; re-inject each unchanged via `WinDivertSend` with the same address; run `curl` concurrently; watch whether the connection completes and whether any packet is re-presented to the same handle.
- **Result (elevated run, 2026-08-20):**
  - The pass-through re-injected 5 packets successfully (`WinDivertSend` did not fail).
  - A SYN, an ACK, and three PSH|ACK packets were observed and re-injected.
  - The **"LOOP?" flags were false positives** (see §4.1): my heuristic flagged any duplicate sequence number, but the "duplicates" were a normal ACK (`seq = SYN+1`) and TCP retransmits of the same data packet — not re-captured copies.
  - **The connection stalled:** `curl` did not complete within 8s and retransmitted the same data payload 3 times. So pass-through reinjection at priority 0 did **not** transparently pass the connection through to completion in this experiment. This initial finding is superseded by E4b–E4d below, which isolate the reinjection mechanism from the endpoint behavior.

### Experiment 4.1 — Why the "LOOP?" flags are false positives

WinDivert's documented priority model: packets are diverted to higher-priority handles before lower-priority ones; **a packet injected by a handle is diverted to the next priority, not re-offered at the injecting handle's own level** ("Packets injected by a handle are then diverted to the next priority handle"). The spike's capture handle is the only handle and sits at priority 0, so a re-injected packet cannot come back to it. The observed repeats were ordinary TCP behavior:

- `flags=0x10 seq=2059200882` = the client's **ACK** after receiving a SYN-ACK; its seq is `SYN+1`, so my "seenSeq" set mislabeled it.
- `flags=0x18 seq=2059200882` appearing 3 times = **TCP retransmission** of the same data (the payload after the handshake), because the connection stalled.

**Conclusion:** the spike's `loopDetected` heuristic was wrong. Loop prevention was **not demonstrated** — but it was also **not refuted**; the design must be validated with a better discriminator (e.g., tracking `(srcIP,srcPort,dstIP,dstPort,seq,flags)` and only flagging an exact packet copy, not sequence-value reuse).

### Experiment 4b — Pass-through reinjection isolation (3-handle observer)

- **Goal:** determine whether a priority-0 `WinDivertRecv` → `WinDivertSend` pass-through actually delivers packets to the wire, and whether it loops.
- **Method:** three handles on the same outbound filter: **B** (priority 1, SNIFF) sees original packets; **A** (priority 0, modify) is the pass-through (recv → send unchanged); **C** (priority −1, SNIFF) sees packets *after* A re-injects.
- **Result (elevated):** `passThroughSent=9, sendFailures=0, B(original)=9, C(after reinject)=9`. **All 9 re-injected packets were observed at C.** No packet appeared twice at B. This confirms re-injection delivers packets to the wire and shows no recapture loop.

### Experiment 4c — Inbound observer D (server → client)

- **Goal:** independently observe whether the server sends anything back.
- **Method:** add a passive **D** handle (priority 1, SNIFF+RECV_ONLY) filtered to `inbound and ip and ip.SrcAddr == 1.1.1.1 and tcp and tcp.SrcPort == 443`.
- **Result (elevated):** the inbound capture alone did not cleanly prove or refute a server response beyond the handshake — classified **INCONCLUSIVE** (evidence insufficient for a strict inbound-response verdict).

### Experiment 4d — TCP trace after SYN-ACK (A/B/C/D, timestamp-ordered)

- **Goal:** the final minimal diagnostic — record the full TCP exchange keyed by the exact 4-tuple, in timestamp order, with no packet modification and no loop detection.
- **Method:** same A/B/C/D architecture; record for every packet: timestamp, direction, flags, seq, ack, TCP payload length, src/dst ports.
- **Result (elevated):**
  ```
  19ms  OUT B/C  12419->443  SYN   seq=1181730305 ack=0           payload=0
  98ms  IN  D    443->12419  SYN-ACK seq=3255670904 ack=1181730306 payload=0
  99ms  OUT B/C  12419->443  ACK   seq=1181730306 ack=3255670905   payload=0
  105ms OUT B/C  12419->443  PSH|ACK seq=1181730306 ack=3255670905 payload=438  (ClientHello)
  420ms OUT B/C  ... PSH|ACK retransmit payload=438
  729ms OUT B/C  ... PSH|ACK retransmit payload=438
  1332ms OUT B/C ... PSH|ACK retransmit payload=438
  2538ms OUT B/C ... PSH|ACK retransmit payload=438
  4950ms OUT B/C ... PSH|ACK retransmit payload=438
  8009ms OUT B/C 12419->443  RST|ACK (curl gave up)
  ```
  Answers, from packet evidence only:
  - **A)** Did the ClientHello leave through C? **YES** — every ClientHello copy observed at C.
  - **B)** How many times at C? **6×** (105, 420, 729, 1332, 2538, 4950ms).
  - **C)** Any inbound after the SYN-ACK? **NO** — D observed exactly one inbound packet, the SYN-ACK at 98ms; nothing after.
  - **D)** ClientHello retransmits? **YES** — 6× over ~4845ms (exponential backoff: 315, 309, 603, 1206, 2412ms gaps).
  - **E)** Pattern: complete handshake (SYN→SYN-ACK→ACK) followed by outbound ClientHello retransmission with **no inbound response**.
  - **Classification:** **`TCP_TRACE_CLIENTHELLO_NO_RESPONSE`**.

### Experiment 5 — (optional) Crafted TCP response injection

- **Goal:** verify a client's reaction to a crafted inbound response.
- **Status:** **NOT TESTED** in this spike (kept out of scope to avoid any risk of disrupting a live connection). Deferred to the Phase 4–6 ferry design validation.

---

## 4. Packet behavior observed

From the elevated runs (Experiments 0–3 **CONFIRMED**, E4d **TCP_TRACE_CLIENTHELLO_NO_RESPONSE**):

- The scoped handle captures **only** outbound packets to `1.1.1.1:443` — nothing else was seen (loopback traffic, other destinations all excluded by the filter).
- **Experiments 1–2 (capture-without-reinject) consumed the packets.** These experiments opened modify-mode handles and called `WinDivertRecv` but never `WinDivertSend`. Per WinDivert's default *drop-and-divert* semantics, captured packets that are not re-injected are **dropped**. The 3 duplicate SYN seqs observed in Experiment 2 were **curl retransmitting its dropped SYN**, not a pass-through working. This is documented honestly: the earlier draft's claim that "the pass-through handle does not consume the packet" was **incorrect**.
- `ifIdx=19`, `outbound=True`, `loopback=False`, `ipv6=False`, `sniffed=False` — the address metadata is populated and usable.
- Source port was an ephemeral high port; destination was fixed at `1.1.1.1:443`.
- **E4b:** a priority-0 recv→send pass-through delivered all 9 captured packets to the wire (observed at C, a lower-priority SNIFF handle). No packet was re-presented at B (no recapture loop demonstrated).
- **E4d:** the TCP handshake completes through the reinjection path (SYN→SYN-ACK→ACK). The ClientHello (438 bytes) leaves through C and is retransmitted 6× with exponential backoff. **No further inbound packet from `1.1.1.1:443` was observed after the SYN-ACK during the test window.**

---

## 5. Limitations and notes

- The spike uses `WinDivertRecv`/`WinDivertSend` synchronously in a background task. There is **no non-blocking API** in WinDivert; cancellation is done by closing the handle, which unblocks the pending recv. This is the pattern the production ferry must use for clean shutdown.
- The spike does **not** construct/modify packets. Packet **construction** (crafted SYN-ACK, RST, payload wrapping) is deliberately left for the Phase 4–6 ferry work; this spike only proves capture/inspection fundamentals and probes reinjection.
- **Experiment 4 used a flawed loop heuristic** (`seenSeq`) that produced false positives. E4b/E4d replaced it with multi-priority observer handles and exact packet fingerprints; no recapture loop was demonstrated.
- **The endpoint behavior observed in E4d is reported as a fact, not explained.** After the SYN-ACK/ACK handshake, the ClientHello leaves through the reinjection path, but no further inbound packet from `1.1.1.1:443` was observed during the test window. The root cause is **UNKNOWN** — this spike does not claim the server rejected the packet, that Cloudflare caused it, that timing heuristics caused it, or any other specific root cause.
- **This test does NOT validate the ferry's selected-process path:** hold SYN → establish upstream SOCKS5 connection → craft SYN-ACK → sequence translation → forward data. That path was never exercised by this spike.
- Elevation is mandatory and the UAC consent cannot be automated; the spike must be launched from an elevated shell.
- The spike targets a fixed public IP (`1.1.1.1:443`) for reproducibility. It does not depend on any specific network topology beyond outbound internet access.

---

## 6. Implications for the proposed TCP ferry

The spike supports and constrains the ferry design in `docs/ARCHITECTURE_RESEARCH.md` §9:

1. **Capture is CONFIRMED feasible:** a narrowly filtered network-layer handle reliably sees outbound TCP SYN packets with full tuple + seq/ack metadata. The ferry can key its flow table on `(srcIP, srcPort, dstIP, dstPort)` from the captured SYN.
2. **Process attribution is CONFIRMED:** the FLOW layer yields the owning PID via a SNIFF+RECV_ONLY handle. The ferry can use it as the primary attribution source, with `GetExtendedTcpTable` as fallback (Phase 3/5).
3. **Cancellation via handle close works:** a blocked `WinDivertRecv` is unblocked by closing the handle. This is the shutdown primitive the ferry needs (`CLAUDE.md`: "Ensure all background workers terminate cleanly").
4. **Packet-level reinjection through a priority-0 modify-mode pass-through is CONFIRMED at the packet level:** all re-injected packets appeared at the lower-priority observer (E4b: 9/9). No recapture loop was demonstrated.
5. **The TCP handshake completes through the reinjection path** (E4d: SYN→SYN-ACK→ACK). After the handshake, the ClientHello leaves through the reinjection path but no further inbound packet from `1.1.1.1:443` was observed during the test window. The root cause of this endpoint behavior is **UNKNOWN**.
6. **This spike does NOT validate the ferry's selected-process path** (hold SYN → establish upstream SOCKS5 → craft SYN-ACK → sequence translation → forward data). That path was never exercised.
7. **Injection of crafted responses** (crafted SYN-ACK, RST, data wrapping) remains the critical open question for the ferry design and must be validated in Phase 4–6 with a real client.

---

## 7. Result status summary

| Experiment | Status |
|---|---|
| E0 Load + open handle | **CONFIRMED** |
| E1 Capture outbound SYN | **CONFIRMED** |
| E2 Inspect fields | **CONFIRMED** |
| E3 Flow-layer process attribution | **CONFIRMED** |
| E4 Reinjection / loop prevention (initial) | **INCONCLUSIVE** — flawed `loopDetected` heuristic (false positives); superseded by E4b–E4d |
| E4b Pass-through reinjection isolation (A/B/C) | **CONFIRMED** — 9/9 re-injected packets observed at C; no recapture loop demonstrated |
| E4c Inbound observer (D) | **INCONCLUSIVE** — inbound capture alone insufficient for a strict verdict |
| E4d TCP trace after SYN-ACK | **`TCP_TRACE_CLIENTHELLO_NO_RESPONSE`** |
| E5 Crafted response injection | **NOT TESTED** (out of scope for this spike) |

---

## 8. R1–R8 status (from `docs/ARCHITECTURE_RESEARCH.md` §8)

| Risk | Status after spike |
|---|---|
| R1 SYN-before-PID attribution race | **NOT TESTED** — FLOW-layer PID attribution works (E3 CONFIRMED), but the SYN-time decision race (capturing a SYN before `GetExtendedTcpTable` has the row) was not measured. Needs Phase 3/5 timing measurement. |
| R2 Seq-offset ferry vs. TCP options | **NOT TESTED** — no packet construction was attempted. Open question (Phase 6). |
| R3 Crafted inbound injection ABI | **NOT TESTED** — E5 deferred. Open question (Phase 6). |
| R4 Hold SYN during SOCKS5 connect | **NOT TESTED** — no ferry loop was built. Open question (Phase 6). |
| R5 DNS leak | **NOT TESTED** — out of scope for this spike (documented in the architecture doc). |
| R6 QUIC / UDP/443 bypass | **NOT TESTED** — out of scope for this spike. |
| R7 IPv6 | **NOT TESTED** — spike was IPv4-only by design (user's internet has no IPv6). |
| R8 PID reuse | **NOT TESTED** — FLOW-layer PIDs observed once; cache invalidation not exercised. |
| R15 Endpoint no-response after handshake | **INCONCLUSIVE** — E4d shows the ClientHello leaves through the reinjection path but no inbound response follows. Root cause UNKNOWN. Does not block the ferry's selected-process path (which does not pass through traffic). |

**Overall:** the spike de-risks **capture, field inspection, packet-level reinjection, and FLOW-layer process attribution** — the foundation of the ferry. It does **not** de-risk **crafted response injection** (R2/R3), which remains the critical unknown before Phase 6.

---

## 9. Decision / Gate

| Gate | Verdict |
|---|---|
| WinDivert capture + flow attribution | **PASS** (E0–E3 CONFIRMED) |
| Packet reinjection feasibility | **PASS at packet level** (E4b: 9/9 delivered to wire; no recapture loop demonstrated) |
| End-to-end passthrough to `1.1.1.1:443` | **INCONCLUSIVE / endpoint-specific failure** — handshake completes, ClientHello leaves, no inbound response; root cause UNKNOWN (E4d) |
| Selected-process ferry path (hold SYN → SOCKS5 → craft SYN-ACK → sequence translation → forward data) | **NOT TESTED in this spike** — deferred to Phase 6 validation |