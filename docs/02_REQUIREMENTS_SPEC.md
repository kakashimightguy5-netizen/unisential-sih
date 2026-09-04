# 02 — Requirements Specification

Tier tags: **[T1]** = MVP (committed), **[T2]** = stretch (only if T1 validated
early), **[T3]** = future work (documented, not implemented). Tiers must match
`00_PROJECT_CHARTER.md`.

Status legend: `planned` / `implemented` / `tested` / `validated`. Everything below
is `planned`.

---

## Functional Requirements

### FR-1 — Data ingestion

- **FR-1.1 [T1]** Ingest offline PCAP / PCAPNG files.
- **FR-1.2 [T1]** Ingest the project dataset (Turnipseed gas-pipeline ARFF) via an
  adapter that maps its records to the internal packet/record model.
- **FR-1.3 [T2]** Support authorised **offline** live capture from a local interface
  in an isolated lab (never third-party networks — `SECURITY_AND_ETHICS_BOUNDARIES.md`).
- **FR-1.4 [T1]** Reject and clearly report corrupted, truncated, or empty inputs
  without crashing (`09_TEST_VALIDATION_PLAN.md`).

### FR-2 — Direction handling

- **FR-2.1 [T1]** Identify traffic direction for each record (egress vs inbound).
- **FR-2.2 [T1]** Keep **egress only**; discard all inbound. Record the count
  discarded.
- **FR-2.3 [T1]** For the project dataset, the egress direction is
  `command response == 0` (response = outbound telemetry — thesis-confirmed,
  BLOCKER 2 resolved). The filter value stays a config parameter so `== 1` can be run
  as a labelled sensitivity check.

### FR-3 — Windowing

- **FR-3.1 [T1]** Group egress records into fixed **5-second** time windows.
- **FR-3.2 [T1]** Window per **source** (source identifier from the record model;
  for the single-source project dataset this is one logical group — see
  `01_PROBLEM_DEFINITION.md` limitation 4).
- **FR-3.3 [T1]** Windows never span a train/validation/test boundary; boundary
  windows are dropped or flagged, never zero-filled (`04_DATASET_PLAN.md`).

### FR-4 — Feature extraction

- **FR-4.1 [T1]** Extract the Tier 1 feature set per window:
  packet count; packets/sec; bytes/sec; mean IAT; std-dev IAT; min IAT; max IAT;
  function-code validity flag; function-code frequency distribution per source;
  payload entropy mean; payload entropy std-dev.
- **FR-4.2 [T1]** Payload entropy is recorded and used as **one feature among
  several**. No decision path may treat entropy as sufficient on its own.
- **FR-4.3 [T2]** Optional/pluggable extra features: IAT histogram distance
  (chi-square/KS) to a learned normal histogram; per-source rolling behavioural
  profile + deviation scores; frame-length anomaly; address/point distribution
  entropy.
- **FR-4.4 [T3]** Documented-only features: epsilon-similarity of adjacent IATs;
  IAT multimodality / covert-symbol-count indicators; approximate entropy of the IAT
  sequence; Kolmogorov-complexity / compressibility estimate. **Not implemented.**
- **FR-4.5 [T1]** Feature extraction is bounded by fields the dataset actually
  supports. A feature whose source field is absent is documented as unsupported, not
  synthesised.

### FR-5 — Detection

- **FR-5.1 [T1]** Run an **Isolation Forest** trained on **normal-only** egress
  feature vectors and produce a continuous anomaly score per window.
- **FR-5.2 [T1]** Run a **naive statistical threshold baseline** (e.g. IAT > 2× the
  training mean) **in parallel, as a comparison only**. It is never the primary
  detector and is never used to raise the operational alert on its own.
- **FR-5.3 [T1]** Compute a normalised anomaly score per window.
- **FR-5.4 [T1]** Classify severity (e.g. INFO / LOW / MEDIUM / HIGH / CRITICAL) from
  the score via validation-set-calibrated thresholds.
- **FR-5.5 [T2]** Unauthorised-source check ("source id never seen in training").
- **FR-5.6 [T3]** Autoencoder / LSTM-AE; hybrid IF+AE ensemble; covert storage
  channel detection; malformed-structure / protocol-conformance checking; replay /
  repetition detection. **Not implemented.**

### FR-6 — Explainability (mandatory for everything implemented)

- **FR-6.1 [T1]** Every alert lists the feature(s) that deviated most from the
  learned normal baseline.
- **FR-6.2 [T1]** For each contributing feature, the alert shows the **observed
  value** and the **baseline value** (and the deviation, e.g. z-score or ratio).
- **FR-6.3 [T1]** An alert must never be presented as only a bare score.

### FR-7 — Alerting & history

- **FR-7.1 [T1]** Generate a structured alert per anomalous window
  (`08_API_DATA_SCHEMA.md`).
- **FR-7.2 [T1]** Persist alert history (queryable by time, severity, source).
- **FR-7.3 [T1]** Persist per-window feature vectors and model results for audit and
  for the demo timeline view.

### FR-8 — API

- **FR-8.1 [T1]** Expose a local REST API for: recent alerts, alert detail, window
  detail, system health, replay control (`08_API_DATA_SCHEMA.md`).
- **FR-8.2 [T1]** API is local/offline only; no external calls.

### FR-9 — Dashboard

- **FR-9.1 [T1]** Minimal SOC dashboard **built as a Streamlit or Gradio
  single-page app** reading from the backend API / SQLite store (**not** a bespoke
  web app — see `DECISION_LOG.md` 2026-09-02 "dashboard downgraded to
  Streamlit/Gradio"). Shows: live/replayed traffic stats, current anomaly score,
  severity indicator (green/red), alert timeline, per-alert explanation panel.
- **FR-9.2 [T1]** Baseline-vs-ML comparison view for the demo
  (`10_DEMO_SUCCESS_CRITERIA.md`).
- **FR-9.3 [T2]** Historical filtering, per-source drill-down, profile visualisation.
- **FR-9.4 [T1] — HARD GATE.** Dashboard work does not start until the core pipeline
  has produced a validated `EXPERIMENT_LOG.md` entry. **Go/no-go checkpoint:
  2026-09-11.** If no validated entry exists by then, the dashboard falls back to
  **CLI output + matplotlib static plots** for the demo. This fallback is pre-agreed
  (`DECISION_LOG.md`) and is not re-litigated later.

### FR-10 — Demo replay

- **FR-10.1 [T1]** Replay a stored egress capture at controllable speed to drive the
  dashboard through a normal → attack transition.
- **FR-10.2 [T1]** Switch between a "normal" clip and an "attack" clip on demand.

---

## Non-Functional Requirements

### NFR-1 — Latency [T1]

- Per-window scoring (feature extraction + IF inference + explanation) target
  **< 200 ms** on a developer laptop. Exact target confirmed after first benchmark;
  no number is asserted as achieved until measured (`06_AI_MODEL_EVALUATION_PLAN.md`).

### NFR-2 — Throughput [T1]

- Offline batch processing of the full gas-pipeline dataset (~275k records) in
  **minutes, not hours**, on a single machine. Replay for the demo runs at ≥ real
  time.

### NFR-3 — Reproducibility [T1]

- All randomness seeded and recorded. Split boundaries recorded as absolute
  timestamps. Every reported metric traceable to an `EXPERIMENT_LOG.md` entry with
  dataset hash, feature set, model params, and split. Raw data is read-only; outputs
  go only to `data/processed/`.

### NFR-4 — Reliability [T1]

- Malformed/empty/unknown-protocol inputs produce a logged error and a clean exit
  code, never a stack-trace crash (`09_TEST_VALIDATION_PLAN.md`).
- If the model artifact is missing/unloadable, the system reports "model unavailable"
  and continues to run the naive baseline in a clearly-degraded mode.

### NFR-5 — Security [T1]

- Offline operation only. No outbound network connections from any component.
- Only authorised datasets, offline PCAPs, synthetic traffic, and isolated lab
  captures are used (`SECURITY_AND_ETHICS_BOUNDARIES.md`).
- No destructive payloads, no scanning, no third-party targeting.
- Dataset provenance and licence documented before any public artifact.

### NFR-6 — Offline operation [T1]

- The full pipeline (ingest → features → model → API → dashboard) runs on an
  air-gapped machine with no package installs at run time.

### NFR-7 — Resource consumption [T1]

- Runs within **8 GB RAM** and on CPU only (no GPU required). Model artifact and
  dependencies small enough to carry on a USB stick for an air-gapped demo.

### NFR-8 — Explainability [T1]

- 100% of alerts carry a feature-level explanation with observed vs baseline values
  (see FR-6). An alert without an explanation is a defect.

### NFR-9 — Usability [T1]

- An analyst unfamiliar with the model can read an alert and understand *why* it
  fired within ~10 seconds.
- Dashboard state (green/red) is unambiguous from across a room for the demo.

### NFR-10 — Honesty / anti-fabrication [T1]

- No performance number, dataset fact, or capability claim is stated as fact until
  produced by a recorded run. Planned / implemented / tested / validated are kept
  distinct everywhere.

---

## MVP vs Stretch vs Future — summary

| Capability | Tier |
|---|---|
| Egress direction filter, 5s per-source windows | T1 |
| Packet/byte rate, IAT mean/std/min/max | T1 |
| Function-code validity + frequency distribution | T1 |
| Payload entropy mean/std (one signal among several) | T1 |
| Isolation Forest (normal-only training) | T1 |
| Naive threshold baseline (comparison only) | T1 |
| Feature-level explainability (value vs baseline) | T1 |
| Alert history, REST API, minimal Streamlit/Gradio dashboard (gated; CLI+plots fallback), replay | T1 |
| IAT histogram distance; rolling per-source profiles; frame-length anomaly; address/point entropy | T2 |
| Unauthorised-source check | T2 (cheap bolt-on) / else T3 |
| epsilon-similarity; IAT multimodality; ApEn; Kolmogorov/compressibility | T3 |
| Autoencoder / LSTM-AE; IF+AE ensemble | T3 |
| Covert storage channel; malformed-structure checking; replay/repetition detection | T3 |
