# SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Smart India Hackathon 2026 · National Technical Research Organisation (NTRO)**
Internal hackathon milestone: **2026-09-15**

---

## Problem

Critical-infrastructure (OT/ICS) networks are often isolated behind a **data diode** —
hardware that makes inbound traffic to the protected network *physically impossible*.
That already solves the inbound-attack problem. The **residual real risk** is
**outbound**: an already-compromised internal device exfiltrating data or signalling
covertly inside otherwise-legitimate egress traffic. A diode observer sees only
**one direction** and cannot use request/response correlation, TCP session state, or
round-trip timing. This project detects **signs of compromise in the one-way outbound
flow**.

## Solution

Offline PCAP / dataset → **egress-only** direction filter (all inbound discarded) →
**5-second windows per source** → a small, defensible **Tier 1 feature set**
(packet/byte rates; IAT mean/std/min/max; protocol/function-code validity + frequency
distribution; Shannon payload entropy — *one signal among several, never alone*) →
**Isolation Forest** trained on **normal-only** traffic → a **naive threshold rule**
alongside it *purely as a comparison baseline* → **explainable** alerts (which
feature deviated, observed value vs baseline value) → local REST API + minimal SOC
dashboard.

**Novelty:** to the best of our knowledge of the literature, no published work has
reframed the Turnipseed / MSU SCADA gas-pipeline dataset as a **one-way / diode
-observer** anomaly-detection problem with no bidirectional correlation. See
`docs/00_PROJECT_CHARTER.md` and `docs/04_DATASET_PLAN.md`.

## Architecture

```
PCAP / authorised capture / dataset adapter
   → Packet Parser → Direction Filter (egress-only) → Window Builder (5s/src)
   → Feature Extraction (Tier 1; Tier 2 pluggable/off)
   → AI Detection Engine (naive baseline + Isolation Forest)
   → Explainability Engine → Alert Engine → Backend API → Database → SOC Dashboard
```

Full detail: `docs/07_SYSTEM_ARCHITECTURE.md`.

## Tech Stack

- **Language:** Python 3
- **ML:** scikit-learn (Isolation Forest), NumPy, pandas
- **Packet handling:** a pcap library (e.g. scapy / dpkt) + an ARFF dataset adapter
- **Backend:** a lightweight local REST framework (e.g. FastAPI) + SQLite
- **Frontend:** minimal **Streamlit / Gradio** single-page app (not a bespoke web
  app); pre-agreed fallback to CLI + matplotlib plots if the core pipeline is not
  validated by the 2026-09-11 go/no-go
- **All offline.** No runtime network access; CPU-only; ≤ 8 GB RAM.

## Current Status

**Specification phase. No implementation started.** Nothing is past `planned`.

- Documentation: **complete** (this pass) — see below.
- Dataset: verified and hash-recorded (`data/raw/IanArffDataset.arff`, 274,628
  instances). Blocker status (`docs/04_DATASET_PLAN.md`, `docs/00-dataset-provenance.md`):
  **BLOCKER 1 (label codebook) — RESOLVED** from the Turnipseed (2015) thesis
  (label tables transcribed + cited in `docs/00-dataset-provenance.md`, cross-checked
  against the local ARFF); metric gate lifted. **BLOCKER 2 (direction) — RESOLVED,
  confirmed by primary source** (thesis §3.5.2 p.34: `command response == 0` =
  response = egress). BLOCKER 3 (payload↔label join) — resolved by
  decision (no ARFF join; but the raw TXT is self-labelled, so on the TXT egress path
  entropy IS a headline detector feature — pre-reg §2 amended 2026-09-04, EXP-0002).
  BLOCKER 4 (licence) — mitigated (raw data stays out of public repos; citation
  mandatory; team verifies terms before public release).
- No model trained, no threshold selected, no metric computed. Every performance
  figure in the docs reads `[TBD — pending experiment]`.

Status vocabulary used everywhere: `planned` → `implemented` → `tested` →
`validated`.

## Directory Structure

```
SIH26145/
├── README.md
├── docs/
│   ├── 00_PROJECT_CHARTER.md           charter, objective, tiering, novelty, MVP definition
│   ├── 01_PROBLEM_DEFINITION.md         one-way traffic, diodes, OT/ICS, exact problem
│   ├── 02_REQUIREMENTS_SPEC.md          functional + non-functional, tiered
│   ├── 03_THREAT_MODEL.md               boundaries, attacker capabilities, threat scenarios
│   ├── 04_DATASET_PLAN.md               dataset record, simulation method, leakage controls
│   ├── 05_FEATURE_ENGINEERING_SPEC.md   feature table (Tier 1/2/3)
│   ├── 06_AI_MODEL_EVALUATION_PLAN.md   baseline, Isolation Forest, metrics, thresholding
│   ├── 07_SYSTEM_ARCHITECTURE.md        modules, responsibilities, interfaces
│   ├── 08_API_DATA_SCHEMA.md            JSON schemas + REST endpoints
│   ├── 09_TEST_VALIDATION_PLAN.md       test cases with pass/fail conditions
│   ├── 10_DEMO_SUCCESS_CRITERIA.md      2026-09-15 demo script + success criteria
│   ├── SECURITY_AND_ETHICS_BOUNDARIES.md
│   ├── DECISION_LOG.md
│   ├── EXPERIMENT_LOG.md
│   └── (00-…–07-… lowercase recon docs — verified dataset measurements, referenced above)
├── data/            raw (read-only) + processed + reconnaissance
├── packet_engine/   parsing, direction filter, windowing
├── ml/              features, training, detection, explainability
├── backend/         API, alerting, storage
├── frontend/        SOC dashboard
└── tests/           automated test cases (docs/09)
```

## How Development Will Proceed

1. **Tier 1 first (MVP, committed for 2026-09-15).** Direction filter → 5 s
   per-source windows → Tier 1 features → instrumentation-artifact audit → Isolation
   Forest on normal-only → naive baseline for comparison → feature-level
   explainability → evaluation harness → API + alert store →
   **[go/no-go 2026-09-11]** → Streamlit/Gradio dashboard *or* CLI + matplotlib
   plots → demo script. Dashboard work does not start until the core pipeline has a
   validated `docs/EXPERIMENT_LOG.md` entry.
2. **Tier 2 only if Tier 1 is fully working and validated with days to spare.**
   IAT histogram distance, per-source rolling profiles, frame-length anomaly,
   address/point entropy, unseen-source check.
3. **Tier 3 is documented as future work and is NOT implemented in the prototype:**
   epsilon-similarity of adjacent IATs, IAT multimodality / covert-symbol estimate,
   approximate entropy of the IAT sequence, Kolmogorov/compressibility estimate,
   autoencoder / LSTM-AE, IF+AE ensemble, covert storage channel detection,
   malformed-structure / protocol-conformance checking, replay/repetition detection.

Development does **not** begin until the documentation consistency review passes
(`docs/DECISION_LOG.md`).

## Honesty Notes (binding)

- The unidirectional constraint is **simulated** by direction-filtering a
  bidirectional dataset. **These are not real data-diode captures** and no such
  public dataset exists.
- Payload entropy is **one signal among several**, never a sole decision basis
  (evadable by padding/fragmentation).
- The naive threshold rule is a **known-brittle comparison baseline**, not the
  detector.
- Detection performance is reported **per attack type**, honestly, including the
  attack types the Tier 1 feature set cannot be expected to catch.
- This is a **research prototype IDS**, not a certified production appliance.
