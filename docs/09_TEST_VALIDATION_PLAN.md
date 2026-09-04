# 09 — Test & Validation Plan

Covers Tier 1 (MVP) only. Tier 2 tests are added if/when Tier 2 features are built.
Status legend: `planned` / `implemented` / `tested` / `validated` — all cases below
are `planned`.

Each case: **Input · Expected processing · Expected output · Pass/fail condition.**

Test data lives under `data/processed/test_fixtures/` (small, hand-checked, egress
-filtered, provenance recorded). Synthetic fixtures are labelled synthetic.

---

## A — Functional / pipeline correctness

### T-01 · NORMAL traffic
- **Input:** an egress-filtered clip of dataset windows drawn from the TRAIN-normal
  time range (but held out of training).
- **Expected processing:** parse → all egress kept → 5 s windows → Tier 1 features →
  IF score low → below threshold.
- **Expected output:** 0 alerts; `SystemHealth.state = OK`; dashboard green.
- **Pass/fail:** PASS if alert count == 0 and every window's `if_score_norm` <
  `threshold_norm`. FAIL on any alert.

### T-02 · PROTOCOL anomaly (TS-1)
- **Input:** normal clip with a subset of windows carrying `function` codes outside
  the learned valid set / a strongly shifted function-code distribution.
- **Expected processing:** the **deterministic rule layer** (`ml/rules.py`) fires on
  any window containing a function code outside the learned valid set or a novel
  address (independent of the IF — EXP-0002); a shifted-but-valid function-code *mix*
  instead raises `function_code_dist_divergence` and the IF score.
- **Expected output:** alerts on the affected windows; `reasons[0]` is the rule hit
  (`invalid_function_code=0x..` / `novel_address=..`) or, for a mix shift,
  `function_code_dist_divergence` with observed vs baseline.
- **Pass/fail:** PASS if ≥ 1 affected window alerts **and** the top reason is the
  function-code rule hit or the distribution-divergence feature. FAIL otherwise.

### T-03 · PORT / destination-service anomaly (TS-2)
- **Input:** synthetic PCAP fixture (not the gas dataset — see
  `03_THREAT_MODEL.md` note) with egress to a service absent from the learned normal
  set.
- **Expected processing:** unseen `l4_port`/service raises the relevant feature /
  IF score.
- **Expected output:** alert with a port/service reason.
- **Pass/fail:** PASS if the window alerts with a destination-service reason.
  Documented limitation: on the gas dataset alone this test is marked
  **N/A — insufficient port diversity**, recorded in `EXPERIMENT_LOG.md`.

### T-04 · VOLUME anomaly (TS-3)
- **Input:** normal clip with an injected burst (packet/byte rate ≫ baseline) in a
  known window range.
- **Expected processing:** `packets_per_sec` / `bytes_per_sec` / `packet_count`
  deviate strongly; IF score above threshold.
- **Expected output:** alerts on the burst windows; top reason is a rate feature
  with a multiple-of-baseline phrase.
- **Pass/fail:** PASS if the burst windows alert and the top reason is a rate
  feature. FAIL if the burst is missed.

### T-05 · TIMING anomaly — naive-threshold baseline path (TS-4)
- **Input:** normal clip modified so `iat_mean` in a window range exceeds 2× the
  training-normal mean.
- **Expected processing:** the **naive baseline rule fires**; IF also sees the IAT
  features.
- **Expected output:** `ModelResult.baseline_fired = true` with the fired rule and
  observed/threshold values; if the IF also crosses threshold, an `Alert` from
  `isolation_forest` with an IAT reason; `baseline_comparison.baseline_would_fire =
  true`.
- **Pass/fail:** PASS if `baseline_fired == true` for the modified windows and the
  comparison is recorded. (This test validates the **baseline mechanism and the
  comparison plumbing**, not that the baseline is a good detector — its weakness is
  documented, not tested away.)

### T-06 · ENTROPY anomaly (TS-5)
- **Input:** payload-bearing fixture (from the raw text file's frames, or synthetic)
  with a window range of high-entropy payloads.
- **Expected processing:** `payload_entropy_mean` / `_std` deviate; IF score
  contribution from entropy features.
- **Expected output:** alert(s); if entropy is the **only** contributing feature,
  `explanation_confidence = "low"`.
- **Pass/fail:** PASS if the high-entropy windows alert **and** an entropy-only alert
  is marked low-confidence. Note in `EXPERIMENT_LOG.md`: not evaluable against
  dataset labels (BLOCKER 3) — this is a mechanism test on fixtures.

---

## B — Robustness / failure handling

### T-07 · CORRUPTED PCAP
- **Input:** a truncated / byte-mangled PCAP file.
- **Expected processing:** parser detects the corruption, stops cleanly, logs a
  structured error.
- **Expected output:** non-zero exit code (CLI) / `4xx` (API) with a clear message;
  no partial/garbage alerts; no stack trace to the user.
- **Pass/fail:** PASS if the process exits cleanly with an error and produces 0
  alerts. FAIL on crash or on emitting alerts.

### T-08 · EMPTY PCAP
- **Input:** a valid but zero-packet PCAP.
- **Expected processing:** parser yields 0 records; windowing yields 0 windows.
- **Expected output:** "no traffic" status; 0 alerts; `SystemHealth.state = OK`
  with `windows_processed = 0`.
- **Pass/fail:** PASS if handled as empty (not an error, not a crash).

### T-09 · UNKNOWN protocol
- **Input:** egress packets of a protocol the parser has no dissector for.
- **Expected processing:** records pass through with `protocol = "UNKNOWN"`,
  `function_code = null`; rate/timing/entropy features still computed; function-code
  features degrade gracefully (validity treated as not-applicable, not 0).
- **Expected output:** windows processed; alerts only if rate/timing/entropy deviate;
  no crash.
- **Pass/fail:** PASS if windows are processed and function-code features are marked
  N/A rather than forcing a false anomaly.

### T-10 · HIGH traffic rate (throughput / stability)
- **Input:** a large egress capture (≥ full dataset volume, or a synthetic
  high-rate stream).
- **Expected processing:** streaming windowing keeps memory bounded; throughput
  meets `NFR-2`.
- **Expected output:** full run completes; `windows_per_sec` recorded; memory within
  `NFR-7` (8 GB).
- **Pass/fail:** PASS if the run completes within the `NFR-2` wall-clock target and
  under the memory cap. Numbers recorded, not asserted in advance.

### T-11 · MODEL unavailable
- **Input:** start the system with the Isolation Forest artifact missing / unreadable.
- **Expected processing:** detection engine returns `model_available = false`; the
  naive baseline still runs; Alert Engine marks state `DEGRADED`.
- **Expected output:** `SystemHealth.state = "DEGRADED"`,
  `degraded_reason = "model unavailable — baseline only"`; dashboard shows a degraded
  banner; baseline verdicts still visible.
- **Pass/fail:** PASS if the system runs degraded (no crash) and clearly signals it.

---

## C — Split / leakage / artifact validation (gating — must pass before any metric)

### T-12 · Split integrity
- **Check:** 0 rows shared between TRAIN/VALIDATION/TEST; `time` ranges disjoint; 0
  feature windows spanning a boundary; guard gap ≥ largest feature window discarded.
- **Pass/fail:** PASS only if all four hold. Recorded in `EXPERIMENT_LOG.md`.

### T-13 · Training-set purity
- **Check:** the IF training set contains only normal-labelled egress windows from
  the TRAIN block (needs BLOCKER 1). No label field present in any feature vector.
- **Pass/fail:** PASS only if training data is normal-only and label-free.

### T-14 · Threshold provenance
- **Check:** the operational threshold's `threshold_source` names the VALIDATION
  block and an experiment ID; it was never computed against TEST.
- **Pass/fail:** PASS only if provenance is present and points at VALIDATION.

### T-15 · Instrumentation-artifact audit
- **Check:** run the audit from `docs/03-data-split-protocol.md` on the TRAIN block
  (`crc rate` label-correlation, `length` templates, tail function-code
  per-class breakdown, field-presence bitmask cross-tab, exactly-40 pattern
  contiguity, boundary sanity). Record raw output.
- **Pass/fail:** PASS if no excluded attribute is silently informative and any
  "too clean" separation is explained. Any FAIL → attribute stays excluded, recorded
  here. Blocked on BLOCKER 1 for the label-dependent checks.

### T-16 · Reproducibility
- **Check:** re-running the offline pipeline with the recorded seed + dataset hash +
  split cut points reproduces the same artifacts (hash-equal or metric-equal within
  tolerance).
- **Pass/fail:** PASS if a second run reproduces the reported numbers.

---

## D — Evaluation reporting (after C passes and BLOCKER 1 resolved)

### T-17 · Per-attack-type detection reporting
- **Check:** the evaluation output reports recall **per attack type**, with a
  pre-registered table of which attack types the Tier 1 features can/cannot be
  expected to catch (`06_AI_MODEL_EVALUATION_PLAN.md`).
- **Pass/fail:** PASS if per-type numbers exist and the can/cannot table was written
  before the numbers.

### T-18 · Baseline-vs-ML comparison
- **Check:** every metric is reported for both detectors; at least one concrete
  window exists where the baseline is wrong and the IF is right.
- **Pass/fail:** PASS if the paired report exists and the demo case is identified.

---

## Test execution

- `tests/` holds automated cases for T-01..T-11 (fixture-driven) and T-12..T-16
  (pipeline assertions). T-17/T-18 are report checks run at evaluation time.
- CI is local/offline. No test reaches the network.
- A test run writes a summary to `EXPERIMENT_LOG.md` when it accompanies a model run.
