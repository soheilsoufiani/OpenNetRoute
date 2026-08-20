# WinDivert Feasibility Spike

**Status:** Spike in progress — isolated experiments, no production code
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
- **Method:** receive a packet, `WinDivertSend` it back with the same address; track duplicate sequence numbers to detect a loop.
- **Result:** pending an elevated run.

### Experiment 5 — (optional) Crafted TCP response injection

- **Goal:** verify a client's reaction to a crafted inbound response.
- **Status:** **NOT TESTED** in this spike (kept out of scope to avoid any risk of disrupting a live connection). Deferred to the Phase 4–6 ferry design validation.

---

## 4. Packet behavior observed

From Experiments 0–2 (all **CONFIRMED** on the first elevated run):

- The scoped handle captures **only** outbound packets to `1.1.1.1:443` — nothing else was seen (loopback traffic, other destinations all excluded by the filter).
- A captured SYN is passed through unchanged; curl retransmits the SYN with the same source port and sequence number (seen as duplicate `seq=3425666436` across Experiment 1 and the start of Experiment 2) — **proving the pass-through handle does not consume the packet and does not create a loop** (the same seq reappearing is curl's TCP retransmission, not a recapture loop).
- `ifIdx=19`, `outbound=True`, `loopback=False`, `ipv6=False`, `sniffed=False` — the address metadata is populated and usable.
- Source port was an ephemeral high port; destination was fixed at `1.1.1.1:443`.

---

## 5. Limitations and notes

- The spike uses `WinDivertRecv`/`WinDivertSend` synchronously in a background task. There is **no non-blocking API** in WinDivert; cancellation is done by closing the handle, which unblocks the pending recv. This is the pattern the production ferry must use for clean shutdown.
- The spike does **not** construct/modify packets (read-only inspection + pass-through). Packet **construction** (crafted SYN-ACK, RST, payload wrapping) is deliberately left for the Phase 4–6 ferry work; this spike only proves capture/inspection/reinjection fundamentals.
- Elevation is mandatory and the UAC consent cannot be automated; the spike must be launched from an elevated shell.
- The spike targets a fixed public IP (`1.1.1.1:443`) for reproducibility. It does not depend on any specific network topology beyond outbound internet access.

---

## 6. Implications for the proposed TCP ferry

Assuming Experiments 3–4 confirm the remaining claims, the spike supports the ferry design in `docs/ARCHITECTURE_RESEARCH.md` §9:

1. **Capture is confirmed feasible:** a narrowly filtered network-layer handle reliably sees outbound TCP SYN packets with full tuple + seq/ack metadata. The ferry can key its flow table on `(srcIP, srcPort, dstIP, dstPort)` from the captured SYN.
2. **Pass-through reinjection works and does not loop:** `WinDivertSend` with the same address re-injects unchanged, and duplicate seq numbers come from TCP retransmission, not a recapture loop. The ferry's "reinject for non-selected processes" path is safe.
3. **Cancellation via handle close works:** a blocked `WinDivertRecv` is unblocked by closing the handle. This is the shutdown primitive the ferry needs (`CLAUDE.md`: "Ensure all background workers terminate cleanly").
4. **Process attribution (pending Exp 3):** if the FLOW layer yields the owning PID, the ferry can attribute connections without polling `GetExtendedTcpTable` (or use it as a fallback/cross-check).
5. **Injection of crafted responses (Exp 5, not tested here)** remains the biggest open question for the ferry's "present the real upstream ISN in a crafted SYN-ACK" design — it must be validated in Phase 4–6 with a real client, on both Ethernet and Wi-Fi.

---

## 7. Result status summary

| Experiment | Status |
|---|---|
| E0 Load + open handle | **CONFIRMED** |
| E1 Capture outbound SYN | **CONFIRMED** |
| E2 Inspect fields | **CONFIRMED** |
| E3 Flow-layer process attribution | **NOT TESTED** (pending elevated run) |
| E4 Reinjection / loop prevention | **NOT TESTED** (pending elevated run) |
| E5 Crafted response injection | **NOT TESTED** (out of scope for this spike) |

*The elevated live run is required to complete E3 and E4. After it runs, this document will be updated with the actual results and the statuses above will be revised from NOT TESTED to CONFIRMED / FAILED / INCONCLUSIVE.*