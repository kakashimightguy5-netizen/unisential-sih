# 01 — Problem Definition

## IP Traffic

IP traffic is the set of packets exchanged between hosts using the Internet Protocol.
Each packet carries addressing (source/destination IP), a transport header
(TCP/UDP/…), and a payload. In an OT/ICS setting the payload is frequently an
industrial protocol such as Modbus/TCP, DNP3, or IEC-104 carrying register reads,
writes, and function codes.

## Bidirectional Communication

Normal IP communication is **bidirectional**: a client sends a request, a server
replies; TCP establishes a connection with a three-way handshake and acknowledges
every segment. Most network security analytics rely on seeing *both* directions:

- request/response correlation (did this query get an expected answer?)
- connection state tracking (SYN → SYN/ACK → ACK, teardown)
- round-trip timing
- byte-count symmetry / asymmetry between the two half-flows

## Unidirectional Communication

In **unidirectional** communication only one direction is observable. Packets flow
one way across a boundary and *nothing* comes back — not because of a firewall rule
that could be changed, but because the transport path physically carries light/signal
in one direction only.

Consequences for analysis:

- No response to correlate a request against.
- No handshake or ACKs — TCP-style state machines are meaningless.
- No round-trip time.
- The observer sees a *stream of egress packets* and must reason from that alone.

## Data-Diode Concept

A **data diode** (unidirectional security gateway) is a hardware device that permits
data to flow from one network to another in exactly one direction and makes the
reverse direction *physically impossible* (e.g. a fibre link with a transmitter on
one side and a receiver on the other, and no transmitter on the return path).

Typical deployment: a high-assurance / protected network (the "high side") needs to
send telemetry out to a business network or historian (the "low side") without ever
accepting anything back. The diode guarantees:

- **Inbound to the protected network: physically impossible. A hard guarantee, not a
  probability.**
- Outbound from the protected network: permitted, and therefore a potential covert
  exit path if an internal device is already compromised.

## OT / ICS Context

Operational Technology (OT) and Industrial Control Systems (ICS) run physical
processes — gas pipelines, power substations, water treatment. They favour
unidirectional gateways because:

- The protected process network must be shielded from any external influence.
- Regulators / security architectures (e.g. IEC 62443 zone-and-conduit models,
  nuclear sector guidance) explicitly endorse diodes for high-integrity boundaries.
- Telemetry still has to reach historians, dashboards, and analytics on the low side.

The traffic is typically a **steady polling loop**: a master polls RTUs/PLCs on a
fixed cycle, so the normal profile is highly regular and periodic. This project's
dataset (`04_DATASET_PLAN.md`) is exactly such a polling capture.

## Why Standard Bidirectional / Session-Based Analysis Becomes Limited

| Technique | Why it breaks on one-way traffic |
|---|---|
| Request/response correlation | There is no response to see. |
| TCP session reassembly / state | No handshake, no ACKs, no teardown observable. |
| RTT / latency anomaly | No round trip. |
| Flow symmetry ratios | Only one half-flow exists. |
| Signature IDS tuned to client↔server exchanges | Half the exchange is absent. |

What *remains* observable, and what this system uses:

- Egress packet timing (inter-arrival times) and rates.
- Packet/frame sizes and byte volume.
- Protocol identity and function/operation codes in the payload.
- Payload byte distribution (entropy).
- Source identity of the emitting device.

## Exact Detection Problem We Are Solving

> Given only the **egress** packet stream crossing a unidirectional boundary, detect
> behavioural signs that an **internal device is already compromised** and is
> **exfiltrating data or signalling covertly** through the legitimate outbound
> channel — **without** any ability to observe or rely on return traffic.

We are **not** solving:

- Prevention or detection of inbound attacks — the diode makes inbound physically
  impossible (`03_THREAT_MODEL.md`).
- Detection of the initial compromise of the internal device (removable media,
  insider, supply chain) — that happens off this channel.
- Attacker attribution beyond flagging anomalous egress behaviour.

## Assumptions

1. A true data diode is in place; inbound is impossible. The detector runs on the
   low-side observer tap.
2. The protected network's *normal* egress behaviour is stable enough to learn a
   baseline from a labelled-normal training period.
3. Enough normal-labelled egress traffic exists to train an unsupervised model;
   attack examples are rare/absent at training time and used only for evaluation.
4. The emitting device(s) and protocol(s) are known well enough to define
   "valid protocol / valid function code".
5. Timestamps in the capture are at sufficient resolution to build 5-second windows
   and compute IAT statistics. (Confirmed for the project dataset: microsecond
   resolution, strictly increasing — `04_DATASET_PLAN.md`.)
6. The unidirectional constraint in experiments is **simulated** by direction
   filtering a bidirectional dataset. This is not real diode data.

## Limitations

1. **No real diode dataset exists publicly.** Results are *indicative*, not
   definitive, of real diode-observer performance.
2. **Entropy signal is limited** — padding/fragmentation can defeat it; it is used
   only as one feature among several.
3. **Tier 1 feature set cannot catch every attack class.** Covert storage channels,
   malformed-structure attacks, and replay attacks are Tier 3 (documented, not
   implemented). Detection rates are reported per attack type, honestly
   (`06_AI_MODEL_EVALUATION_PLAN.md`).
4. **Single-source dataset.** The project dataset is effectively one polling source
   (`address` is near-constant), so "per-source" grouping collapses to one logical
   source in MVP validation. The per-source design is retained for generality
   (PCAP inputs with many devices) but is not exercised at scale by the dataset.
5. **Simulated direction filter.** Egress = `command response == 0` (response =
   outbound telemetry), confirmed verbatim by the Turnipseed (2015) thesis
   (BLOCKER 2 resolved). `== 1` is retained as a config-selectable sensitivity run.
6. This is a **research prototype IDS**, not a certified production security
   appliance (`SECURITY_AND_ETHICS_BOUNDARIES.md`).

## Architecture Diagram (context view)

```
        PROTECTED OT / ICS NETWORK (HIGH SIDE)
    ┌─────────────────────────────────────────────┐
    │  PLC / RTU / HMI / historian client         │
    │  (one may be ALREADY COMPROMISED)           │
    └───────────────────────┬─────────────────────┘
                            │  egress only
                            ▼
                 ╔═══════════════════════╗
                 ║      DATA DIODE       ║   inbound = physically impossible
                 ║  (one-way hardware)   ║   (hard guarantee)
                 ╚═══════════┬═══════════╝
                             │  one-way flow
                             ▼
        LOW SIDE (business / historian / monitoring)
    ┌─────────────────────────────────────────────┐
    │  Observer tap  ──►  THIS SYSTEM             │
    │                                             │
    │  PCAP ingest → direction filter (egress) →  │
    │  5s windows/src → Tier 1 features →         │
    │  Isolation Forest (+ naive baseline) →      │
    │  explainability → alerts → API → dashboard  │
    └─────────────────────────────────────────────┘
```

Full module-level architecture: `07_SYSTEM_ARCHITECTURE.md`.
Trust boundaries: `03_THREAT_MODEL.md`.
