# 03 — Threat Model

Consistent with `01_PROBLEM_DEFINITION.md` and `00_PROJECT_CHARTER.md`. Tier tags
match those documents: **[T1]** MVP, **[T2]** stretch, **[T3]** documented future
work only.

## System Elements

### Protected OT network (high side)
The industrial process network: PLCs, RTUs, HMIs, engineering workstations, a polling
master, local historians. Runs Modbus-style polling. **This is where a compromise
would already reside.**

### Data-diode boundary
A hardware unidirectional gateway between the protected network and the low side.
**Enforces one-way flow physically.** Inbound to the protected network is
**impossible** — see "Attacker capabilities".

### Monitoring network (low side)
Business / historian / SOC segment that legitimately receives the outbound telemetry.
Hosts the observer tap and this detection system.

### Observer
A passive tap / SPAN port on the low side that copies the one-way flow to the
detection system. Passive: it cannot inject anything and has no path back to the high
side.

### Detection system (this project)
Ingest → direction filter → windowing → Tier 1 features → Isolation Forest (+ naive
baseline) → explainability → alerts → API → dashboard. Runs entirely on the low side,
offline.

## Attacker Capabilities

**Hard physical guarantee (not probabilistic):**

> The attacker **cannot send anything inbound through the diode under any
> circumstances.** There is no misconfiguration, no exploit, no timing trick that
> creates a return path — the reverse direction has no transmitter. Inbound attacks
> (external scanning, inbound exploitation, inbound C2) are therefore **out of scope
> by construction**, not by mitigation.

**The one capability in scope:**

> An internal device on the protected network is **already compromised** (via
> removable media, insider action, supply-chain implant, or a pre-existing foothold —
> the initial-compromise vector itself is out of scope). The compromised device can
> **modulate the legitimate outbound flow** — its timing, volume, framing, protocol
> fields, or payload content — to **exfiltrate data or signal covertly** to a
> receiver on the low side.

The attacker is assumed to:

- Know that a diode is present and that only egress is observable.
- Prefer to stay hidden inside normal-looking traffic (low and slow, entropy shaping,
  timing that mimics the polling loop).
- Not be able to see the detector's model or thresholds (no feedback channel).

## Trusted Components

- The data diode hardware (one-way enforcement).
- The passive observer tap (assumed not compromised; passive by design).
- The detection host and its offline environment.
- The labelled-normal training data's "normal" label (once BLOCKER 1 is resolved).

## Untrusted Components

- Every device on the protected network (any one may be the compromised source).
- The content, timing, and framing of the outbound stream.
- Any live capture input until validated (format, completeness).
- The unlabelled raw payload text file (provenance undocumented — BLOCKER 3).

## Assets Being Protected

- **Confidential process data / configuration / IP** on the protected network that
  must not leak out.
- **Integrity of the monitoring picture** — the SOC's ability to trust that "green"
  means no exfiltration in progress.
- **The isolation guarantee's value** — a diode is only as useful as the assurance
  that nothing is tunnelling out through the permitted channel.

## Data Visible to the Detector

- Egress packet timestamps (→ IAT, rates).
- Egress packet / frame sizes (→ byte volume, frame-length checks).
- Protocol identity and function/operation codes (→ validity, frequency
  distribution).
- Payload bytes where present (→ Shannon entropy). **Note:** absent from the
  authoritative ARFF; only in the unlabelled text file (BLOCKER 3), so entropy is
  currently *computable but not evaluable* against ground truth.
- Source identifier of the emitting device (near-constant in the project dataset).
- Header/protocol field values (available to Tier 3 covert-storage-channel work; not
  used in MVP).

## Data NOT Visible to the Detector

- Any return / inbound traffic (does not exist).
- Request/response pairing, ACKs, connection state, RTT.
- Anything happening on the protected network that does not cross the diode.
- The initial-compromise event.
- Application-layer semantics beyond what the parsed protocol fields expose.
- Ground-truth attribution of which device is compromised.

## Threat Scenarios (tagged by tier)

| # | Scenario | What the detector keys on | Tier |
|---|---|---|---|
| TS-1 | **Unauthorised protocol / function code** — compromised device emits function codes or protocol operations not in the normal profile | function-code validity flag; per-source function-code frequency distribution shift | **T1** |
| TS-2 | **Unusual destination service / port** — egress to a service the protected network never normally talks to | destination port/service vs learned normal set (from packet model; limited on the project dataset — see note) | **T1** |
| TS-3 | **Burst / volume anomaly** — staged or bulk exfiltration inflates packet/byte rate in a window | packets/sec, bytes/sec, packet count vs baseline | **T1** |
| TS-4 | **Timing anomaly (naive threshold baseline only at T1)** — covert timing channel or paced exfiltration shifts IAT | mean/std/min/max IAT; naive rule "IAT > 2× training mean" as the **baseline** comparator; Isolation Forest also sees the IAT features | **T1** (naive baseline); richer timing-channel detection is **T2/T3** |
| TS-5 | **Abnormal payload entropy** — compressed/encrypted exfil data raises entropy above the low-entropy telemetry norm | Shannon entropy mean/std — **one signal among several, never alone**; evadable by padding/fragmentation | **T1** |
| TS-6 | **Unauthorised device / source** — a source identifier never seen in the normal baseline starts emitting | "source id not in training set" check | **T2** if time allows, else **T3** |
| TS-7 | **Covert storage channel** — data hidden in header / protocol fields (unused bits, sequence numbers, reserved fields) | field-level conformance / statistical checks on header fields | **T3 — documented only, not implemented** |
| TS-8 | **Malformed / non-standard packet structure** — protocol-violating frame structure used as a channel or as evasion | protocol-conformance / structural validation | **T3 — documented only, not implemented** |
| TS-9 | **Replay / repetition** — replayed frames used to signal, or to mask a channel | sequence/payload repetition and periodicity analysis | **T3 — documented only, not implemented** |

**Note on TS-2:** the project (gas-pipeline) dataset does not richly expose
destination-port diversity; TS-2 is fully expressible on general PCAP input but is
demonstrated in a limited form on the dataset. This limitation is recorded in
`04_DATASET_PLAN.md` and `EXPERIMENT_LOG.md`.

## Detection Expectation Honesty

The Tier 1 feature set can *plausibly* distinguish TS-1, TS-3, TS-5, and the timing
component of TS-4 when the attack perturbs rate / function mix / entropy / gross
timing. It **cannot** be expected to catch TS-7, TS-8, TS-9 (not implemented), and
will catch TS-4 only weakly when the covert channel is shaped to mimic the normal
timing distribution. `06_AI_MODEL_EVALUATION_PLAN.md` and `EXPERIMENT_LOG.md` report
detection **per attack type**, not as a single aggregate that would hide this.

## Trust-Boundary Diagram

```
   ┌───────────────────────────── PROTECTED OT NETWORK (HIGH SIDE) ─────────────────────────────┐
   │  TRUST BOUNDARY A: everything inside is UNTRUSTED to the detector                          │
   │                                                                                           │
   │   [PLC]   [RTU]   [HMI]   [ENG WKSTN]   [POLL MASTER]   ← one of these may be COMPROMISED  │
   │       \      \       |        /             /                                              │
   │        \      \      |       /             /                                               │
   │                 outbound telemetry stream                                                  │
   └───────────────────────────────────┬───────────────────────────────────────────────────────┘
                                       │
              ┌════════════════════════▼════════════════════════┐
              ║  TRUST BOUNDARY B: DATA DIODE (TRUSTED HARDWARE) ║
              ║  egress: PERMITTED        inbound: IMPOSSIBLE    ║
              ╚════════════════════════┬════════════════════════╝
                                       │  one-way flow
   ┌───────────────────────────────────▼─────────────── LOW SIDE (MONITORING) ──────────────────┐
   │  TRUST BOUNDARY C: detector's observable world starts here                                 │
   │                                                                                           │
   │   [Passive observer tap] ──► [Ingest] ──► [Egress filter] ──► [5s windows/src] ──►         │
   │        (TRUSTED, passive)      [Tier1 features] ──► [Isolation Forest (+naive baseline)]   │
   │                               ──► [Explainability] ──► [Alert store] ──► [API] ──► [SOC]   │
   │                                                                                           │
   │   Detection host: TRUSTED, OFFLINE, no outbound connections                                │
   └───────────────────────────────────────────────────────────────────────────────────────────┘

   Data crossing B and reaching C is the ONLY data the detector ever sees.
   Nothing the detector does can cross B back toward the high side.
```
