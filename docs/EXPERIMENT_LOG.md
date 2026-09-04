# Experiment Log

Every model run, split, audit, and benchmark gets an entry here. **No entry yet** —
no experiment has been run. All performance values elsewhere in the docs read
`[TBD — pending experiment]` until an entry here produces them.

Entry template:

```
### EXP-XXXX
- Experiment ID:
- Date:
- Dataset:            (name + sha256 + row count)
- Direction filter:   (command response == ?  — BLOCKER 2 status)
- Split:              (TRAIN / VALIDATION / TEST cut points as epoch + ISO 8601; guard gap)
- Features:           (exact list; tier)
- Model:              (Isolation Forest / naive baseline / other)
- Parameters:         (n_estimators, max_samples, contamination, seed, ...)
- Training subset:    (normal-only? row count; BLOCKER 1 status)
- Artifact audit:     (T-15 result per check: PASS / FAIL / NEEDS DOCUMENTATION)
- Threshold:          (value + method + which split it was chosen on)
- Metrics:            (precision, recall, F1, FPR, FNR, PR-AUC, ROC-AUC,
                       per-attack-type recall, inference latency, throughput)
- Baseline comparison:(same metrics for the naive rule; ≥1 window where they differ)
- Observations:
- Decision:           (what changes as a result)
```

---

## Pre-registered: attack types the Tier 1 MVP feature set CAN vs CANNOT be expected to catch

Written **before** any metric is computed, so the per-attack-type split in
`06_AI_MODEL_EVALUATION_PLAN.md` is not post-hoc. **BLOCKER 1 (label codebook) is
RESOLVED** from the Turnipseed (2015) thesis (`docs/00-dataset-provenance.md`); the
families below now map to `categorized result` {1..7} = NMRI/CMRI/MSCI/MPCI/MFCI/
DoS/Recon and this table is final.

| Attack family (`categorized result`, thesis Table 3.5 p.36) | Tier 1 expectation | Reasoning |
|---|---|---|
| **MFCI (5)** — malicious function code (specific 19,21,22) | **CAN** | `function_code_valid` / function-code distribution divergence. |
| **MPCI (4)** — malicious parameter (specific 1–12) | **PARTIAL** | Only if it perturbs rate or function-mix; a single in-range write may be invisible to Tier 1. Process-param columns (`setpoint`…) stay EXCLUDED (see scope note below). |
| **MSCI (3)** — malicious state command (specific 13–17) | **PARTIAL** | Same as MPCI — Tier 1 sees rate/function-mix, not `pump`/`solenoid`/`system_mode` values (EXCLUDED). |
| **NMRI (1)** — naive response injection (specific 29–32) | **PARTIAL / CAN** | Often shifts value patterns and sometimes rate/timing; Tier 1 sees rate/timing, not value semantics. |
| **CMRI (2)** — complex response injection (specific 25–28,33–35) | **PARTIAL** | Designed to look normal; Tier 1 catches it only if framing/timing/rate drift. |
| **Recon (7)** — reconnaissance (specific 20,23,24) | **CAN** | Typically raises packet rate / address spread / function-code spread. |
| **DoS (6)** — denial of service (specific 18) | **CANNOT (egress) — MEASURED (EXP-0003)** | Revised by EXP-0001 (threat-model reasoning), **verified by EXP-0003** (direct measurement, TEST split): no egress IAT separation — Cohen's d = +0.135 / +0.120 / +0.009 / +0.146 on `iat_mean/std/min/max`, raw inter-frame-gap distributions identical (d = +0.036, Kolmogorov–Smirnov p = 0.65). Best IAT threshold buys 8.7 % DoS recall at +5 % Normal FPR (= noise). The 203 Bad-CRC egress frames are byte-identical to a normal `0x10` echo response. The attack is entirely *inbound*; a data diode blocks the flood in hardware, so there is no egress signature. Originally pre-registered "CAN" on an assumption of rate deviation the data does not show. |
| TS-5 — payload entropy anomaly | **NOT EVALUABLE** | Mechanism demonstrated on fixtures/TXT frames; no join key to labels (BLOCKER 3). Excluded from headline recall; entropy features not in the headline model. |
| Covert timing channel shaped to mimic normal IAT distribution | **CANNOT (reliably)** | Tier 1 IAT mean/std can be held constant by the attacker; histogram-distance (Tier 2) and Tier 3 timing features are needed. |
| Covert storage channel (header/protocol field encoding) | **CANNOT** | Not implemented (Tier 3). |
| Malformed / non-standard packet structure | **CANNOT** | Conformance checking not implemented (Tier 3). |
| Replay / repetition | **CANNOT** | Repetition detection not implemented (Tier 3). |
| Unauthorised device/source | **CANNOT in Tier 1** | `unseen_source_flag` is Tier 2; also weak on this single-source dataset. |

Headline recall in the evaluation is computed over the **CAN** and **PARTIAL / CAN**
rows only; **CANNOT** and **NOT EVALUABLE** rows are reported with their observed
detection rate (where one exists) but excluded from the headline, with this table
cited.

---

## PRE-REGISTRATION — governing constraints for EXP-0001 onward (recorded 2026-09-02)

These are fixed **before** the first experiment so results cannot be retrofitted.
Every future `### EXP-` entry must reference this block and state any deviation.

1. **Direction filter (BLOCKER 2 resolution).** The egress stream is
   `command response == 0` (the response/telemetry direction). **CONFIRMED BY PRIMARY
   SOURCE** — Turnipseed (2015) §3.5.2 p.34, verbatim: *"The value can either be a
   '0' for response or '1' for command."* This also agrees with the earlier data
   evidence (Modbus exception codes 128–142 occur exclusively under value 0; mean
   frame `length` 30.901 vs 50.383). The opposite direction (`== 1`) is run once as a
   **labelled sensitivity check**, never as the headline. The prior "egress direction
   assumed, not primary-source confirmed" caveat is **withdrawn** — no longer required
   on metric entries.

2. **Payload-entropy exclusion — ~~AMENDED 2026-09-04~~ WITHDRAWN.**
   *Original (2026-09-02):* no join key links the labelled ARFF to the payload TXT, so
   `payload_entropy_mean` / `payload_entropy_std` are not IF headline inputs and TS-5
   is not in headline recall.
   *Amendment (2026-09-04, `DECISION_LOG.md` 2026-09-04 entry; basis EXP-0001):* the
   stated premise is **void** — `data/raw/gas_pipeline_raw.txt` is confirmed
   self-labelled (`00-dataset-provenance.md` §"CORRECTION (2026-09-04)"), so on the
   **TXT egress path** payload bytes and labels are in the same file and entropy **is**
   evaluable against ground truth. Per EXP-0001, entropy lifts IF recall 0.027 → 0.132
   and precision to 0.82 — measured signal, not leakage.
   **Now in force:** `payload_entropy_mean` / `payload_entropy_std` **ARE** headline IF
   inputs on the TXT path (EXP-0002 onward). TS-5 is evaluable and counted in headline
   recall on the TXT path. The "never sufficient alone / low-confidence if entropy is
   the only contributor" discipline still applies. On the **ARFF path** (no payload
   bytes) entropy stays a described-only mechanism.

3. **Label-based metrics are now permitted** (precision, recall, F1, FPR, FNR,
   PR-AUC, ROC-AUC, per-attack-type detection). **BLOCKER 1 is RESOLVED** — the
   Turnipseed (2015) label tables are transcribed and cited in
   `docs/00-dataset-provenance.md`, and cross-checked exactly against the local ARFF
   `categorized × specific` cross-tab. Each metric must still be recorded in the same
   `### EXP-` entry as the split (`03-data-split-protocol.md`) and the
   instrumentation-artifact audit (item 4) that it depends on. Normal-only training
   subset = `binary result == 0` (equivalently `categorized result == 0`).

4. **Split + artifact audit** (`docs/03-data-split-protocol.md`, `09` T-12..T-16)
   must pass and be recorded in the same `### EXP-` entry as any metric it
   accompanies.

---

## Blocker status (mirror of `04_DATASET_PLAN.md`)

| Blocker | Needed for | Status (2026-09-03) | Resolved by / date |
|---|---|---|---|
| BLOCKER 1 — label codebook | normal-only training subset, all label-dependent audit checks, every metric | **RESOLVED** — full codebook transcribed + cited in `00-dataset-provenance.md`; exact cross-check vs local ARFF cross-tab | Turnipseed (2015) thesis, §3.4–3.5 / Tables 3.5–3.8, 2026-09-02 |
| BLOCKER 2 — `command response` direction semantics | fixing egress filter value, final split boundaries | **RESOLVED — CONFIRMED BY PRIMARY SOURCE** (`== 0` = response = egress) | Turnipseed (2015) §3.5.2 p.34, verbatim, 2026-09-02 |
| BLOCKER 3 — text↔ARFF join key | pairing payload entropy with ground truth | **RESOLVED BY DECISION** — no join; entropy excluded from headline metrics | decision, 2026-09-02 |
| BLOCKER 4 / LICENSE | any *public* submission / repo push | **PARTIALLY RESOLVED** — mitigation active; team verification before public release | web check + mitigation, 2026-09-02 |

BLOCKER 1 and BLOCKER 2 are resolved, so label-based metrics and a fixed egress
filter value (`command response == 0`) are both permitted. Every metric must still be
entered in the same `### EXP-` entry as the split and artifact audit it depends on.
BLOCKER 3 is designed around (entropy out of headline metrics); BLOCKER 4 affects
public artifacts only.

---

## Diagnostics (NON-HEADLINE — not `### EXP-` experiments)

Supervised or exploratory probes run to size the problem. Their numbers are **not**
project results and must not appear on slides as detector performance. They inform
scope; they do not validate anything.

### DIAG-0001 · XGBoost supervised ceiling on frame-level TXT features (2026-09-04)
- **Code:** `ml/features_txt.py`, `ml/xgb_txt_diagnostic.py`. Report:
  `data/experiments/xgb_txt_diagnostic_report.md`.
- **Purpose:** establish the upper bound on how much of each attack **category** is
  separable from diode-observable *frame-level* features, given the payload-value
  fields are excluded by the diode-observability decision. The approved unsupervised
  detector will not exceed this.
- **Dataset:** `data/raw/gas_pipeline_raw.txt`, 209,668 frames (labelled — see
  `00-dataset-provenance.md` §"CORRECTION (2026-09-04)").
- **Split:** contiguous time-block, 75 % earliest train / 25 % latest test, 2 s guard
  band. Boundary ts 1418841651.27. **Not** a random split.
- **Features (11):** address, function_code, frame_len_bytes, is_request,
  start_register, quantity, byte_count, length_anomaly, rare_function_code,
  interarrival_seconds, message_entropy_bits_per_byte. `source`/`destination`/
  `specific_attack`/absolute `timestamp` excluded (leakage / not wire-observable).
- **Model:** `XGBClassifier` multi:softprob, 8 classes, 400 trees, depth 6, lr 0.1.
- **Result (test-block recall):** Normal .97, MFCI **1.00**, Recon **.98**,
  NMRI .24, CMRI .13, MPCI .14, MSCI **.01**, DoS **.00**. Weighted-F1 .76,
  macro-F1 .46. Top features by gain: `rare_function_code` .50, `start_register` .16,
  `is_request` .12, `frame_len_bytes` .09. `length_anomaly` gain 0 (no malformed-length
  frames in this capture); entropy & interarrival ~0.
- **Reading:** protocol-manipulation attacks (function-code injection, scans) are
  near-perfectly separable at the frame level. Process-value attacks (MSCI, MPCI,
  most CMRI/NMRI) are near-invisible — their signal is the payload value, which the
  diode-observability decision removes. DoS (Bad-CRC, specific 18) is invisible to a
  *frame-level* view: structurally-normal frames, and the trailing bytes don't
  validate as Modbus CRC-16. DoS is expected to recover with **windowed** packet-rate
  / CRC-error-rate features (the Tier-1 windowed spec), which this probe omits.
- **Consistency with pre-registration:** matches the "attack types Tier 1 CAN/CANNOT
  catch" table above, except DoS underperformed its "CAN" expectation because this
  probe is frame-level, not windowed. **Superseded by EXP-0001** — the windowed
  detector shows DoS is undetectable on egress for a structural reason, so the
  pre-registered table IS updated (see EXP-0001).

---

## Experiments

### EXP-0001 · Isolation Forest egress anomaly detector (windowed, TXT egress) — 2026-09-04
- **Code:** `ml/features_windowed.py`, `ml/iforest_detector.py`. Report:
  `data/experiments/iforest_detector_report.md`.
- **Dataset:** `data/raw/gas_pipeline_raw.txt`, labelled (see provenance §CORRECTION
  2026-09-04). Egress filter: `destination == 1` (slave→master telemetry = the diode
  low-side view; BLOCKER 2 = egress is the response direction). 104,627 egress frames
  → **35,935** 5-second tumbling windows (16,995 attack / 18,940 normal; window is
  "attack" if any frame in it is attack-labelled).
- **Split:** contiguous time-block, 60 / 20 / 20 by window index, 1-window guard gap
  discarded at each boundary. Train 21,560 / val 7,185 / test 7,186 (3,610 normal /
  3,576 attack). **Not random.** *(Counts corrected 2026-09-04 during EXP-0002 —
  earlier prose read 21,540 / 12,769 / 7,186, a transcription slip; the recorded TEST
  metrics below were computed on this split and are unchanged, verified by the
  confusion counts.)*
- **Training subset:** train-block **normal-only** windows (11,368); IF and the
  standardiser (train-normal mean/std, frozen) fitted on these. Attack windows in the
  train block discarded.
- **Model:** `sklearn` IsolationForest, 300 trees, `max_samples="auto"`,
  `contamination="auto"` (not used for thresholding), seed 0.
- **Features (16 total):** packet_count, packets_per_sec, bytes_per_sec,
  mean_frame_len, iat_{mean,std,min,max}, frac_func_{valid,read,write},
  rare_func_rate, distinct_frame_ratio, repeat_frame_rate, payload_entropy_{mean,std}.
  **Headline model = 14 features, entropy EXCLUDED** per the pre-registration §2.
- **Threshold:** 99th percentile of VALIDATION-normal anomaly scores (target FPR 1%).
  Headline thr 0.6680; +entropy thr 0.6454. TEST scored once.
- **Artifact audit (T-15 / 03-split §):**
  - Boundary sanity — PASS (disjoint 5 s buckets, split on index + guard gap).
  - Headline IF flags almost only `packet_count == 4` windows (benign polling jitter,
    ~equally common in normal & attack) → this is noise, not signal. FLAG.
  - `frac_func_valid` / `rare_func_rate` are exactly constant in normal traffic, so
    IsolationForest never splits on them — the strongest MFCI/Recon signal is
    invisible to the IF. **Action item:** these belong in a deterministic rule, not as
    IF features (contradicts `05_FEATURE_ENGINEERING_SPEC.md` — spec change proposed).
  - MFCI/Recon attack windows have *lower* packet rate + near-zero `iat_std`: real and
    wire-observable, but partly a fixed-cadence injection-tool artifact. FLAG, not
    excluded.
  - DoS: no feature separates it (iat_mean 1.712 vs 1.729; frac_func_valid 0.999 vs
    1.000).
- **Metrics (TEST, window-level, binary attack/normal):**

  | detector | precision | recall | F1 | FPR | PR-AUC |
  |---|---|---|---|---|---|
  | Stage 0 naive baseline | 1.000 | 0.113 | 0.203 | 0.000 | — |
  | Stage 1 IF — **headline (no entropy)** | 0.466 | **0.027** | 0.051 | 0.031 | 0.539 |
  | Stage 1 IF — +entropy (sensitivity) | 0.817 | 0.132 | 0.228 | 0.029 | 0.623 |
  | Combined: baseline ∨ IF+entropy | 0.826 | 0.141 | 0.240 | 0.029 | — |

- **Per-category detection rate (combined baseline ∨ IF+entropy, TEST):**
  Normal (FPR) 2.9 % · NMRI 7.3 % · CMRI 9.6 % · MSCI 2.6 % · MPCI 3.0 % ·
  **MFCI 100 %** · DoS 1.1 % · **Recon 100 %**.
- **Baseline comparison:** the naive function-code rule already gets MFCI/Recon at
  100 % with perfect precision; the IF adds only a few percent of NMRI/CMRI on top and
  costs 3 % FPR. On this dataset the unsupervised IF barely beats the trivial rule.
- **Reading:** the approved egress-only unsupervised detector reliably catches **only
  protocol-violation attacks (MFCI, Recon)**, and those are caught by a one-line rule.
  Value-manipulation attacks (MSCI, MPCI, and most NMRI/CMRI) are near-invisible
  because the diode-observability decision removes the payload values that carry their
  signal. DoS is invisible because the Bad-CRC attack is entirely inbound and leaves
  no egress signature — **a data diode already blocks it in hardware**, so there is
  nothing for an egress detector to catch. This is the honest capability envelope.
- **Decisions / action items:**
  1. **Pre-registered CAN/CANNOT table updated below** — DoS moves to CANNOT (egress,
     structural); MFCI/Recon confirmed CAN (via rule, not IF).
  2. **Pre-registration §2 (entropy exclusion) basis is void for the TXT path** — its
     stated reason was "no label linkage (BLOCKER 3)", but the TXT is self-labelled.
     Recommend the planner formally amend §2 to admit entropy into the headline model
     for the TXT-based evaluation (it roughly 5×'s recall: 0.027 → 0.132). Not done
     unilaterally — pre-registration changes need sign-off.
  3. **Spec change proposed for `05_FEATURE_ENGINEERING_SPEC.md`:** `function_code_valid`
     (and any feature constant in normal traffic) must be a deterministic rule, not an
     Isolation Forest input.

  *Action items 2 and 3 were both accepted and applied in **EXP-0002** below
  (`DECISION_LOG.md` 2026-09-04). Action item 1 (CAN/CANNOT table) was applied in this
  entry.*

---

### EXP-0002 · Detector with pre-reg §2 amended + deterministic rule layer — 2026-09-04
- **References:** EXP-0001 (above); `DECISION_LOG.md` 2026-09-04 entry
  ("Payload entropy admitted to the headline model; `function_code_valid` moved to a
  deterministic rule"); pre-registration §2 (amended).
- **Code:** `ml/features_windowed.py` (+ `IF_FEATURES` / `RULE_LAYER_FEATURES`),
  `ml/rules.py` (new — `DeterministicRuleLayer`), `ml/iforest_detector.py` (rewritten).
  Report: `data/experiments/iforest_detector_report.md`.
- **Unchanged from EXP-0001:** dataset (`gas_pipeline_raw.txt`, egress = `destination
  == 1`), 5 s windows, 35,935 windows, contiguous 60/20/20 split (train 21,560 / val
  7,185 / test 7,186 = 3,610 normal / 3,576 attack), train-normal-only fit (11,368
  windows), `IsolationForest` 300 trees seed 0, threshold = val-normal 99 % quantile,
  TEST scored once. **DoS and the payload-value categories (MSCI/MPCI/CMRI/NMRI) not
  revisited** — EXP-0001 findings stand.
- **Change 1 — entropy in the headline IF.** Pre-reg §2's premise ("payload TXT has no
  label linkage") is void: the TXT is self-labelled. `payload_entropy_mean/std` are now
  IF inputs.
- **Change 2 — deterministic rule layer.** `frac_func_valid` and `rare_func_rate` (both
  *exactly* constant on train-normal → IF cannot split on them) removed from the IF
  feature set. New `ml/rules.py`: flags a window if any frame carries a function code
  ∉ {0x03, 0x10} or a slave address ∉ {4} (sets frozen from train-normal). Runs OR-ed
  with the IF, not as an input.
- **IF feature set (14, entropy included):** packet_count, packets_per_sec,
  bytes_per_sec, mean_frame_len, iat_{mean,std,min,max}, frac_func_{read,write},
  distinct_frame_ratio, repeat_frame_rate, payload_entropy_{mean,std}.
- **Artifact audit:** boundary sanity PASS. Rule layer is a frozen membership test (not
  fitted to attack data); it fires on **0.00 % of Normal test windows** (0/3610) — adds
  no false positives. `packet_count==4` noise channel from EXP-0001 is diluted now that
  the IF has entropy to work with.
- **Metrics (TEST), EXP-0002 vs EXP-0001:**

  | detector | precision | recall | F1 | FPR | PR-AUC |
  |---|---|---|---|---|---|
  | Stage 0 naive baseline | 1.000 | 0.113 | 0.203 | 0.000 | — |
  | Deterministic rule layer only | 1.000 | 0.113 | 0.203 | 0.000 | — |
  | Stage 1 IF only (14 feat, entropy in) | 0.816 | **0.136** (EXP-0001 IF headline 0.027) | 0.234 | 0.030 | 0.610 |
  | **Combined: rule ∨ IF ← EXP-0002 HEADLINE** | 0.821 | 0.141 | 0.241 | 0.030 | — |
  | *(EXP-0001 combined: baseline ∨ IF+entropy)* | *0.826* | *0.141* | *0.240* | *0.029* | — |

  Combined confusion (TEST): TN 3500 · FP 110 · FN 3072 · TP 504.
- **Per-category flag rate (combined, TEST) vs EXP-0001:** Normal 3.0 % (was 2.9) ·
  NMRI 7.3 % (=) · CMRI 9.7 % (was 9.6) · MSCI 2.6 % (=) · MPCI 3.0 % (=) ·
  **MFCI 100 % (=)** · DoS 1.1 % (=) · **Recon 100 % (=)**.
- **MFCI / Recon check (explicitly verified, not assumed):** moving `function_code_valid`
  from an IF input to a deterministic rule did **not** change MFCI/Recon detection —
  both still **100 %** combined (rule-layer alone catches 100 % of each), and the rule
  adds **0 %** to the Normal false-positive rate. Confirmed: Stage 0 was already
  catching these at 100 % precision, and the explicit rule reproduces that exactly.
- **Reading:** the combined *operational* number barely moves (EXP-0001 already had a
  `baseline ∨ IF+entropy` row). The real gains: (a) **IF-alone recall 0.027 → 0.136** —
  the IF is a working detector now, not a `packet_count==4` flagger; (b) the design is
  defensible — zero dead features in the model, protocol violations on an explicit
  auditable rule; (c) the entropy-inclusive number is the *registered* headline.
  Capability envelope is otherwise identical to EXP-0001: reliable only on MFCI/Recon;
  MSCI/MPCI/CMRI/NMRI weak, DoS structurally invisible on egress.
- **Decision:** EXP-0002 is the current headline detector. Next lever would be Tier 2
  features (IAT histogram distance, per-source rolling profile) for the value-manip
  categories — but per EXP-0001 those are fundamentally payload-limited; expect small
  gains. No further IF tuning without a new signal. *(The Tier 2 IAT lever is
  **withdrawn** by EXP-0003 below — measured: no egress timing signal for DoS, and
  the same logic applies to CMRI/NMRI.)*

---

### EXP-0003 · DoS egress-timing measurement — 2026-09-04 (investigation only, no architecture change)
- **References:** EXP-0002; pre-registered CAN/CANNOT table above (DoS row);
  `DECISION_LOG.md` 2026-09-04. Code: `ml/exp0003_dos_timing.py`.
- **Question.** EXP-0001/0002 recorded DoS (Bad-CRC, specific 18) as **CANNOT
  (egress)** on threat-model *reasoning* (the flood is inbound; egress replies look
  normal). This experiment tests that verdict directly: is there any egress
  inter-arrival-time (IAT) signature separating DoS windows from Normal windows?
- **Pre-registration (fixed before the numbers were seen — script header):**
  - **SEPARATION** = ≥1 IAT statistic with |Cohen's d| > 0.5 **and** a one-sided
    threshold on it flags ≥30 % of DoS windows at ≤5 pp added Normal FPR.
  - **NO SEPARATION** = |d| < 0.2 on all four IAT stats **and** the raw inter-frame-gap
    distributions overlap (effect size decides, not p).
  - **AMBIGUOUS** = anything between → no verdict change without a fuller experiment.
  - Scope: measurement only, no detector code change, no new feature, **TEST split
    only** (3,610 pure-Normal windows; 138 windows containing ≥1 DoS frame — the
    "contains-a-DoS-frame" set, broader than EXP-0002's 91 dominant-DoS, chosen to be
    generous to the hypothesis).
- **Measurement (TEST split):**

  | IAT statistic (per 5 s window) | Normal mean ± std | DoS-window mean ± std | Cohen's d | Mann–Whitney p |
  |---|---|---|---|---|
  | `iat_mean` | 1.6654 ± 0.0312 | 1.6696 ± 0.0279 | **+0.135** | 0.11 |
  | `iat_std`  | 0.0868 ± 0.0313 | 0.0905 ± 0.0262 | **+0.120** | 0.24 |
  | `iat_min`  | 1.5786 ± 0.0360 | 1.5789 ± 0.0340 | **+0.009** | 0.70 |
  | `iat_max`  | 1.7529 ± 0.0508 | 1.7603 ± 0.0422 | **+0.146** | 0.16 |

  - **Raw consecutive inter-frame gaps** within those windows (Normal n = 7,195; DoS
    n = 277): mean 1.6659 vs 1.6695, std 0.0976 vs 0.0983. **Cohen's d = +0.036**,
    Mann–Whitney p = 0.45, **Kolmogorov–Smirnov p = 0.65** — the two gap
    distributions are the same distribution.
  - **Best single-threshold** on any IAT stat at ≤5 pp added Normal FPR:
    `iat_mean ≥ 1.7072` → **8.7 % DoS recall** (12 / 138 windows) for +5.0 % Normal
    FPR (~180 new false positives). Every other stat sits at the ~5 % FPR floor = noise.
  - **DoS frame content:** the 203 Bad-CRC frames (specific 18) in these windows are
    **1 distinct frame** — function code `0x10`, 8 bytes — byte-identical to a normal
    `0x10` echo response. DoS windows carry the same `{0x03, 0x10}` code mix, the same
    lengths, and the same ~3 frames/window as Normal windows.
- **Verdict: NO SEPARATION** (pre-registered criterion met on every axis: all four
  |d| < 0.2; raw-gap KS p = 0.65). **The DoS "CANNOT (egress)" verdict is now
  MEASURED, not assumed.** DoS is not weakly detectable on the egress side — it is
  *indistinguishable* from normal traffic across window-level timing, raw inter-frame
  gaps, and frame content. Consistent with the threat model: the diode blocks the
  inbound flood in hardware; the RTU keeps answering normally.
- **Decision.**
  1. Pre-registered CAN/CANNOT table (DoS row) updated to cite these effect sizes.
  2. `DECISION_LOG.md` 2026-09-04 entry extended with the measured result.
  3. **No new feature or rule.** The same "no egress timing signal" logic applies to
     CMRI/NMRI (their signal is payload value, not timing), so EXP-0003 also
     forecloses the Tier 2 IAT-feature rationale for those categories — see
     `06_AI_MODEL_EVALUATION_PLAN.md` Realistic-Expectations. Further recall on
     payload-content categories needs a **new signal type, not identified yet** — not
     incremental tuning of existing features.
