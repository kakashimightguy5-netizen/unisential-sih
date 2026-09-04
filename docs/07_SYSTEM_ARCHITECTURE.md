# 07 — System Architecture

Tier tags match `00_PROJECT_CHARTER.md`. Tier 1 modules are the MVP. Tier 2 feature
modules are **pluggable and optional**. Tier 3 is not built.

## Data-Flow Overview

```
        PCAP / authorised offline capture / dataset adapter        [T1]
                              │
                              ▼
                    ┌───────────────────┐
                    │   Packet Parser   │                          [T1]
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │  Direction Filter │  egress-only; drop inbound[T1]
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │   Window Builder  │  5s windows per source    [T1]
                    └─────────┬─────────┘
                              ▼
                    ┌─────────────────────────────────────┐
                    │        Feature Extraction           │
                    │  Tier 1 extractors (always on)      │        [T1]
                    │  Tier 2 extractors (pluggable/off)  │        [T2]
                    └─────────┬───────────────────────────┘
                              ▼
                    ┌─────────────────────────────────────┐
                    │        AI Detection Engine          │
                    │  • naive threshold baseline (compare)│       [T1]
                    │  • Isolation Forest (primary)        │       [T1]
                    └─────────┬───────────────────────────┘
                              ▼
                    ┌───────────────────┐
                    │ Explainability    │  top-k feature deviations [T1]
                    │ Engine            │  observed vs baseline
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │   Alert Engine    │  score→severity, dedupe   [T1]
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │   Backend API     │  local REST              [T1]
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │     Database      │  alerts, windows, results [T1]
                    └─────────┬─────────┘
                              ▼
                    ┌───────────────────┐
                    │   SOC Dashboard   │  stats, score, timeline,  [T1]
                    │  (Streamlit/Gradio)│  explanation, baseline-vs-ML
                    └───────────────────┘  GATED on validated EXP entry (go/no-go 09-11;
                                           fallback: CLI + matplotlib plots)

   Offline training path (not in the live flow):
   dataset adapter → filter → window → Tier1 features → SPLIT → train IF on
   TRAIN-normal → calibrate threshold on VALIDATION → freeze artifact → (used above)
```

## Module Responsibilities & Interfaces

Interfaces are described as function-level contracts; concrete schemas are in
`08_API_DATA_SCHEMA.md`. Language/runtime: Python (see README tech stack).

### 1. Ingestion / Packet Parser `[T1]` — `packet_engine/`
- **Responsibility:** read an input source and yield a uniform stream of packet
  records. Sources: PCAP/PCAPNG (via a pcap library), the gas-pipeline **dataset
  adapter** (ARFF → records), and (Tier 2) an offline live capture.
- **Handles:** corrupted / truncated files, empty files, unknown protocols — emits a
  structured error, never crashes (`09_TEST_VALIDATION_PLAN.md`).
- **Output interface:** iterator of `PacketRecord` =
  `{ts: float (epoch s), src_id: str, dst_id: str|null, protocol: str,
  l4_port: int|null, frame_len: int, function_code: int|null,
  payload_bytes: bytes|null, direction_hint: str|null, raw_fields: {...}}`.
- **Dataset-adapter mapping:** `ts`←`time`; `frame_len`←`length`;
  `function_code`←`function`; `src_id`←synthetic index (labelled synthetic, since
  `address` is near-constant); `direction_hint`←`command response`;
  `payload_bytes`←null for the ARFF. Label fields are passed only on a separate
  side-channel for evaluation, **never** into the feature path.

### 2. Direction Filter `[T1]` — `packet_engine/`
- **Responsibility:** classify each record as egress or inbound and **keep egress
  only**. Count and log discards.
- **Config:** `egress_selector` — for PCAP, a direction rule (protected-subnet CIDR);
  for the dataset, `command response == 0` (response = egress; thesis-confirmed,
  BLOCKER 2 resolved). Kept as a config parameter for the `== 1` sensitivity run.
- **Interface:** `filter(iter[PacketRecord], config) -> iter[PacketRecord]` +
  `DiscardStats`.

### 3. Window Builder `[T1]` — `packet_engine/`
- **Responsibility:** bucket egress records into fixed **5 s** windows keyed by
  `src_id`. Emit a `TrafficWindow` when a window closes.
- **Rules:** windows never span a split-block boundary (offline path); first-window
  incomplete-history records are dropped/flagged.
- **Interface:** `build(iter[PacketRecord], window_s=5) -> iter[TrafficWindow]`.
  `TrafficWindow` = `{window_id, src_id, t_start, t_end, packets: [PacketRecord],
  block_id|null}`.

### 4. Feature Extraction `[T1 core + T2 plugins]` — `ml/features/`
- **Responsibility:** turn a `TrafficWindow` into a `FeatureVector`. Tier 1
  extractors always run. Tier 2 extractors are registered plugins, **off by
  default**, each behind a config flag.
- **Depends on:** frozen baseline artifact (train-normal means/stds, valid
  function-code set, normal function-code distribution).
- **Interface:** `extract(TrafficWindow, baseline) -> FeatureVector`.
  `FeatureVector` schema in `08_API_DATA_SCHEMA.md`; fields exactly the Tier 1 list
  in `05_FEATURE_ENGINEERING_SPEC.md`.

### 5. AI Detection Engine `[T1]` — `ml/detect/`
- **Responsibility:** score a `FeatureVector`.
  - **Naive baseline:** applies the fixed threshold rule(s); returns a boolean +
    which rule fired. **Comparison only.**
  - **Isolation Forest:** loads the frozen model artifact; returns raw + normalized
    anomaly score.
- **Degraded mode:** if the IF artifact is missing/unloadable → return
  `model_available=false`, still run the baseline, and the Alert Engine marks the
  system state degraded (`09_TEST_VALIDATION_PLAN.md` MODEL-unavailable test).
- **Interface:** `score(FeatureVector) -> ModelResult`
  = `{if_score_raw, if_score_norm, model_available, baseline_fired, baseline_rules}`.

### 6. Explainability Engine `[T1]` — `ml/explain/`
- **Responsibility:** for a window at/over threshold, compute top-k standardized
  feature deviations vs the frozen baseline and render human phrases
  (`06_AI_MODEL_EVALUATION_PLAN.md`).
- **Interface:** `explain(FeatureVector, ModelResult, baseline, k=3)
  -> [FeatureContribution]` where `FeatureContribution` =
  `{feature, value, baseline, deviation, phrase}`.

### 7. Alert Engine `[T1]` — `backend/alerting/`
- **Responsibility:** apply the calibrated threshold + severity bands, attach
  explanations, de-duplicate consecutive identical alerts from the same source,
  construct the `Alert` object, hand it to storage.
- **Interface:** `evaluate(FeatureVector, ModelResult, [FeatureContribution])
  -> Alert|null`.

### 8. Backend API `[T1]` — `backend/api/`
- **Responsibility:** local REST over the database + replay control. No outbound
  calls. Endpoints in `08_API_DATA_SCHEMA.md`.
- **Interface:** HTTP/JSON on `127.0.0.1`.

### 9. Database `[T1]` — `backend/store/`
- **Responsibility:** persist `TrafficWindow` summaries, `FeatureVector`s,
  `ModelResult`s, `Alert`s, `ReplaySession`s, `SystemHealth` snapshots. SQLite for
  the MVP (single file, offline, zero-config).
- **Interface:** repository functions; schema mirrors `08_API_DATA_SCHEMA.md`.

### 10. SOC Dashboard `[T1]` — `frontend/`
- **Implementation:** a **Streamlit or Gradio single-page app** (not a bespoke
  React/Vue app — `DECISION_LOG.md` 2026-09-02). Chosen for ~½ the build cost and
  near-zero charting boilerplate.
- **Responsibility:** render live/replayed traffic stats, current normalized anomaly
  score + severity (green/red), alert timeline, per-alert explanation panel, and the
  **baseline-vs-ML comparison view**. Polls the API (or reads the SQLite store
  directly — both are local).
- **Interface:** consumes the REST endpoints (or the DB) only. No outbound calls.
- **HARD GATE:** this module is not started until the offline training pipeline has
  produced a validated `EXPERIMENT_LOG.md` entry. **Go/no-go: 2026-09-11.** On miss,
  it is replaced for the demo by **CLI output + matplotlib static plots**
  (`docs/07-scope-and-cuts.md` original position) — a pre-agreed fallback.

### Offline Training Pipeline `[T1]` — `ml/train/`
- **Responsibility:** dataset adapter → filter → window → Tier1 features →
  **contiguous time-block split** → artifact audit on TRAIN → fit Isolation Forest on
  TRAIN-normal → fit baseline stats → calibrate threshold + severity bands on
  VALIDATION → evaluate once on TEST → write `EXPERIMENT_LOG.md` entry → emit frozen
  artifacts (`model.pkl`, `baseline.json`).
- **Not part of the live flow.** Produces the artifacts modules 4–7 depend on.

## Cross-Cutting

- **Config** — one file; all blocker-affected values (`egress_value`, split cut
  points, threshold, severity bands, window size) are explicit parameters.
- **Reproducibility** — dataset sha256, seeds, split cut points, and artifact hashes
  recorded with every run (`NFR-3`).
- **No component opens an outbound network connection** (`NFR-5`, `NFR-6`).
- **Tier 2 modules** plug into Feature Extraction only; enabling them must not change
  Tier 1 behaviour or outputs.
