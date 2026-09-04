# 06 — AI Model & Evaluation Plan

No performance numbers appear in this document. None exist yet. Every quantitative
result must come from a recorded `EXPERIMENT_LOG.md` entry. Status legend:
`planned` / `implemented` / `tested` / `validated` — everything here is `planned`.

---

## Stage: BASELINE — naive statistical threshold rule

- **What:** a single hand-set rule, e.g. **"flag the window if `iat_mean` > 2× the
  training-normal mean IAT"** (and optionally the analogous rule on `packets_per_sec`
  / `bytes_per_sec`).
- **Role:** **comparison point only.** It is implemented so the demo and the
  evaluation can show, concretely, what a simple rule gets right and wrong versus the
  ML model. **It is never the primary detector and never raises the operational alert
  on its own.**
- **Documented weakness (state this in the report and the demo):** simple threshold
  rules on timing are **brittle and evadable**. An adaptive covert channel that
  shapes its inter-arrival times to mimic the normal timing distribution — e.g. an
  IP time-replay / timing-replay channel — stays under a fixed multiple-of-the-mean
  threshold while still carrying data. The threshold also false-alarms on benign
  bursts (maintenance polls, batch historian syncs). This brittleness is the *reason*
  the ML stage exists.
- **Tier:** T1 (as a baseline).

## Stage: MODEL 1 (MVP) — Isolation Forest

- **What:** `sklearn`-style Isolation Forest on the **Tier 1 IF feature vector**
  (`05_FEATURE_ENGINEERING_SPEC.md`), trained on **normal-only** egress windows from
  the TRAIN block. Runs OR-ed with the **deterministic rule layer**
  (invalid function code / novel address → immediate flag), which is not an IF input.
- **Headline-metric input set (amended 2026-09-04, `EXPERIMENT_LOG.md` pre-reg §2 /
  `DECISION_LOG.md` 2026-09-04):** the headline IF **includes**
  `payload_entropy_mean` / `payload_entropy_std`. The earlier exclusion assumed no
  payload↔label linkage (BLOCKER 3); that is void on the TXT egress path, which is
  self-labelled. Entropy is measured signal there (EXP-0001: recall 0.027 → 0.132).
  `function_code_valid` is **removed** from the IF input set — it is exactly constant
  on normal traffic so the IF cannot split on it; it moved to the deterministic rule
  layer.
- **Why Isolation Forest** (rationale carried from `docs/04-model-and-threshold.md`):
  unsupervised / normal-only training; handles mixed continuous features with little
  preprocessing; fast to train and score within a 14-day window; anomaly score from
  average path length gives a natural per-sample score to pair with the feature-level
  explanation.
- **Alternatives considered and rejected for MVP:** One-Class SVM (kernel/param
  sensitivity, tuning cost); Local Outlier Factor (no natural scoring of unseen
  points without recomputation); Autoencoder (extra training/tuning surface — Tier 3).
- **Hyperparameters** — sweep candidates, none hardcoded without recorded rationale:
  `n_estimators` `[TBD]`, `max_samples` `[TBD]`, `contamination` `[TBD]` (note:
  `contamination` sets sklearn's internal offset — do **not** double-count it with
  the explicit validation-calibrated threshold below).
- **Output:** continuous anomaly score per window + normalized score in [0,1].
- **Tier:** T1.

## Stage: MODEL 2 (stretch / future) — Autoencoder

- **Documented as future work. NOT implemented in the MVP.** A reconstruction-error
  autoencoder (and, further out, an LSTM-AE for sequence modelling, and an IF+AE
  ensemble) is the natural next model once Tier 1 is validated. It is out of MVP
  scope because it adds a training/tuning surface that the timeline does not support
  and because a poorly-tuned AE would produce misleading results.
- **Tier:** T3.

---

## Evaluation Metrics

BLOCKER 1 (label codebook) is **resolved** (`00-dataset-provenance.md`); metrics are
computed once the artifact audit (`docs/03-data-split-protocol.md`,
`09_TEST_VALIDATION_PLAN.md`) has passed and is recorded in the same
`EXPERIMENT_LOG.md` entry.

| Metric | Definition | Notes |
|---|---|---|
| Precision | TP / (TP + FP) | window-level |
| Recall | TP / (TP + FN) | window-level and **per attack type** (see below) |
| F1 | harmonic mean of precision & recall | |
| False Positive Rate | FP / (FP + TN) | primary operational cost — SOC alert fatigue |
| False Negative Rate | FN / (FN + TP) | missed exfiltration |
| PR-AUC | area under precision–recall curve | preferred over ROC given class imbalance |
| ROC-AUC | area under ROC curve | reported where meaningful |
| **Per-attack-type detection rate** | recall computed separately for each attack type present in the TEST block | **reported honestly — see honesty rule below** |
| Inference latency | ms per window (feature extraction + IF score + explanation) | target `< 200 ms`, confirmed by benchmark, not asserted |
| Throughput | windows/sec in offline batch; full dataset wall-clock | |

### Honesty rule for per-attack-type reporting

Do **not** force every attack-labelled window to count as a required detection.
The Tier 1 feature set can only plausibly distinguish an attack from normal when the
attack perturbs rate, function-code mix, gross timing, or entropy. For attack types
that do not (covert storage channels, malformed-structure attacks, replay — all Tier
3 / not implemented; and timing channels shaped to mimic the normal distribution),
report them as **"not expected to be detectable by the Tier 1 feature set"** and
exclude them from the headline recall, while still listing their observed detection
rate. `EXPERIMENT_LOG.md` must contain an explicit table of *which attack types the
MVP can and cannot reasonably be expected to catch*, written **before** the numbers
are seen, so the split is not post-hoc.

### Recall is structurally bimodal by attack category — not a tuning gap (EXP-0002)

The headline combined detector (`EXPERIMENT_LOG.md` EXP-0002) has a window-level
**recall of ≈ 0.14** on the TEST block. That single number is **not a target to be
raised by tuning.** It is the class-mix-weighted average of two structurally distinct
regimes, and which regime an attack falls into is fixed by the **one-way,
egress-only observability model**, not by hyperparameters, feature scaling, or IF
settings:

| Category | EXP-0002 TEST recall (combined) | Regime | Why |
|---|---|---|---|
| **MFCI**, **Recon** | ~100 % | **at the achievable ceiling** | These manipulate the *protocol* itself — out-of-profile Modbus function codes, device / function-code scans. Directly wire-observable; caught deterministically by the rule layer (`ml/rules.py`), not the IF. Nothing above 100 % to gain. |
| **MSCI**, **MPCI**, **CMRI**, **NMRI** | ~2 – 10 % | **near-zero by design** | The discriminating signal is the *payload content* — a manipulated setpoint / gain / pump / solenoid state, or a fabricated sensor value, inside an otherwise well-formed frame at a normal rate. The diode-observer model **deliberately excludes payload values** (`04_DATASET_PLAN.md` §Novelty; `05_FEATURE_ENGINEERING_SPEC.md`). No IF tuning recovers a signal the feature set does not carry. The small non-zero rate is incidental framing/timing perturbation, not detection of the attack's intent. |
| **DoS** (Bad-CRC) | ~1 % | **near-zero — pending verification** | Recorded as **CANNOT (egress)** in the pre-registered CAN/CANNOT table: the Bad-CRC flood is entirely *inbound*, and the RTU's egress replies during a DoS episode are byte-identical to normal replies. Whether any egress-side *timing* signature exists is being measured in **EXP-0003** before this verdict is treated as final. |

**Basis:** the EXP-0002 combined per-category table, and the EXP-0002 decision line —
> *"No further IF tuning without a genuinely new signal."*

**Reporting rule:** an aggregate or "headline" recall figure **must** be presented
together with this per-category breakdown. An un-annotated *"recall = 0.14"* is a
misleading number — it invites the reader to treat a design boundary as an
unfinished optimisation.

### Comparison reporting

Every metric is reported **twice** side by side: **naive baseline** vs **Isolation
Forest**. The demo (`10_DEMO_SUCCESS_CRITERIA.md`) must include at least one concrete
case where the baseline misses or false-alarms and the Isolation Forest is correct.

---

## Threshold Selection

- The anomaly-score → alert threshold is selected **only on the VALIDATION block**
  (`04_DATASET_PLAN.md`), never on TEST, never on TRAIN.
- **Method:** choose the threshold at a target **false-positive rate** on the
  validation-normal windows (e.g. the 99th or 99.5th percentile of validation-normal
  anomaly scores), then report the recall this FPR buys on TEST — **broken out per
  attack category**, never as an aggregate alone (see "Recall is structurally bimodal
  …" above). EXP-0002 used the 99th percentile (1 % target FPR; ≈ 3 % observed on
  TEST-normal, the difference being validation→test drift over the 3.2-day capture).
- If validation-block labels are available, an alternative is a precision/recall
  trade-off point on validation; the choice and its justification are recorded in
  `EXPERIMENT_LOG.md`.
- **Severity mapping** (INFO/LOW/MEDIUM/HIGH/CRITICAL) is a set of score bands above
  the alert threshold, also calibrated on validation. `[bands TBD]`.
- Any threshold value that appears in code or docs **must cite the split and the
  experiment ID it came from.**

---

## Explainability Method

For each window that crosses the alert threshold:

1. Compute the per-feature **standardized deviation** from the frozen train-normal
   baseline: `dev_i = (observed_i - baseline_mean_i) / baseline_std_i` (for the
   function-code distribution, use the divergence scalar and the single most
   over-represented code).
2. Rank features by `|dev_i|`; take the top-k (default k = 3).
3. Emit, per contributing feature: `feature`, `observed value`, `baseline value`,
   `deviation` (and a human phrase, e.g. "packet rate 8.4× baseline",
   "payload entropy 7.2 vs 2.4 baseline", "unknown function code 0x2B").
4. If the only contributing features are entropy features, mark the explanation
   **low-confidence** (documented entropy weakness).
5. The alert JSON carries this list in `reasons` / `feature_contributions`
   (`08_API_DATA_SCHEMA.md`).

This is a deviation-from-baseline explanation, not a full SHAP/attribution analysis —
sufficient for Tier 1, honest about what it is. (Model-internal attributions such as
per-tree path contributions are Tier 3.)

---

## Realistic-Expectations Statement

- No accuracy figure is quoted unless a recorded `EXPERIMENT_LOG.md` run produced it.
- **Measured (EXP-0002):** the combined detector reliably catches only the
  protocol-manipulation categories (**MFCI, Recon** — ~100 %, via the deterministic
  rule layer). **MSCI / MPCI / CMRI / NMRI** sit near zero because their signal is
  payload content the egress-only view excludes by design; **DoS** near zero because
  the attack is inbound-only (**confirmed by EXP-0003**). This split is
  **structural**, it matched the pre-registered CAN/CANNOT table, and it is not
  closed by tuning — see "Recall is structurally bimodal …" above.
- The Isolation Forest, once entropy was admitted and dead features removed
  (EXP-0002), went from recall 0.027 to 0.136 standalone but still barely beats the
  naive baseline on the combined number — the ceiling is the feature set, not the
  model.
- The instrumentation-artifact audit may still rule features out and *reduce* the
  numbers above — that is correct behaviour, not a regression.
- A result that looks "too clean" (near-perfect separation) is treated as a suspected
  instrumentation artifact until the audit explains it. The MFCI/Recon ~100 % is
  *explained*: an out-of-profile function code on the wire is a real, deterministic
  signal, not an artifact.

### EXP-0003 forecloses the Tier 2 IAT rationale for the payload-content categories

The stretch plan (`DECISION_LOG.md` 2026-09-02 tiering entry) listed Tier 2 IAT
features — IAT histogram distance, per-source rolling profile — as the next lever for
the low-recall categories. **EXP-0003 removes that rationale:**

- **DoS:** measured — no egress inter-arrival-time separation at all (Cohen's d
  ≤ 0.15 on every IAT statistic; raw inter-frame-gap distributions identical,
  Kolmogorov–Smirnov p = 0.65). A finer IAT feature has nothing finer to find.
- **CMRI / NMRI:** by the same logic. Their attack signal is a manipulated *value*
  inside a well-formed frame emitted at the normal polling cadence — there is no
  timing perturbation for an IAT-histogram or rolling-profile feature to pick up any
  more than the mean/std already do. (CMRI is *designed* to hold timing constant;
  NMRI's occasional hits in EXP-0002 come from frame-length / rare-code artefacts,
  not timing.)

**Consequence.** Tier 2 IAT work is **not pursued** (Phase 4 held). Meaningful recall
on MSCI / MPCI / CMRI / NMRI / DoS would require a **new signal type that has not
been identified** — not incremental tuning or elaboration of the existing rate/timing/
function-code/entropy features. Recorded so this is not re-litigated as an
optimisation task. If a new signal is proposed it gets its own pre-registered
experiment.
