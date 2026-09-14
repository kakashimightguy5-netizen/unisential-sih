# Experiment Log

> ## ⚠️ RETRACTION NOTICE — 2026-09-08
>
> **EXP-0001, EXP-0002, EXP-0003 and DIAG-0001 are RETRACTED.** They were all run on
> `data/raw/gas_pipeline_raw.txt` (sha256 `45de4266…fbbd`), which has since been
> confirmed to be **AI-generated / fabricated content**, not a genuine capture (see
> `DECISION_LOG.md` 2026-09-08). Every metric, effect size, threshold and
> per-category number in those entries is **withdrawn**. The entries are kept below,
> unedited except for a per-entry banner, purely as an audit trail of the error.
>
> Replacement work: **EXP-0004** (below), run on the verified row-aligned file
> `data/raw/gas_pipeline_raw.txt` (sha256 `ce2d69e3…93e3`, 274,628 rows), which is
> confirmed row-for-row aligned to `IanArffDataset.arff`.

Every model run, split, audit, and benchmark gets an entry here. EXP-0017 is the
VALIDATED current baseline. EXP-0004 is superseded by EXP-0017, retained for historical
comparison. Retracted entries remain below only as an audit trail.

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
| **DoS (6)** — denial of service (specific 18) | **CANNOT (egress) — MEASURED (EXP-0004)** | Verified-file re-measurement found no egress IAT separation: Cohen's d = -0.086 / +0.098 / -0.123 / -0.029 on `iat_mean/std/min/max`; raw-gap d = -0.046 and Kolmogorov–Smirnov p = 0.461. The best thresholds at ≤5% Normal FPR reached only 2.6% / 3.1% / 4.7% / 2.6% DoS recall. |
| TS-5 — payload entropy anomaly | **EVALUABLE ON VERIFIED TXT PATH** | Exact 274,628-row TXT↔ARFF alignment resolves BLOCKER 3. EXP-0004 measured the paired entropy contribution; entropy remains unavailable on the ARFF-only path. |
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
   *2026-09-08:* the EXP-0001 measurement cited as the basis for admitting entropy
   to the headline was run on the retracted file. Whether entropy earns a headline
   slot is **re-opened** and must be decided by EXP-0004 on the verified file (§EXP-0004
   pre-registration below), not inherited.

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
| BLOCKER 3 — text↔ARFF join key | pairing payload entropy with ground truth | **RESOLVED** — exact 274,628-row alignment on timestamp, both labels, and direction | verified-file audit, 2026-09-08 |
| BLOCKER 4 / LICENSE | any *public* submission / repo push | **PARTIALLY RESOLVED** — mitigation active; team verification before public release | web check + mitigation, 2026-09-02 |

BLOCKER 1 and BLOCKER 2 are resolved, so label-based metrics and a fixed egress
filter value (`command response == 0`) are both permitted. Every metric must still be
entered in the same `### EXP-` entry as the split and artifact audit it depends on.
BLOCKER 3 is resolved by verified row alignment; entropy is in the EXP-0004 headline
IF. BLOCKER 4 affects public artifacts only.

---

## Diagnostics (NON-HEADLINE — not `### EXP-` experiments)

Supervised or exploratory probes run to size the problem. Their numbers are **not**
project results and must not appear on slides as detector performance. They inform
scope; they do not validate anything.

### DIAG-0001 · XGBoost supervised ceiling on frame-level TXT features (2026-09-04)
> **🚫 RETRACTED 2026-09-08.** Run on the fabricated file `gas_pipeline_raw.txt`
> (sha256 `45de4266…fbbd`). All numbers in this entry are withdrawn. Retained for
> audit only. See the RETRACTION NOTICE at the top of this file and `DECISION_LOG.md`
> 2026-09-08. Do not cite any figure below.

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

## PRE-REGISTRATION — EXP-0004 (recorded 2026-09-08, before any EXP-0004 run)

Supersedes the EXP-0001-era pre-registration for the TXT path (that work is retracted).
Fixed before the detector is run on the new file.

1. **Dataset.** `data/raw/gas_pipeline_raw.txt`, sha256 `ce2d69e3…93e3`, 274,628 rows,
   verified row-aligned to `IanArffDataset.arff` (provenance §"NEW AUTHORITATIVE RAW
   FILE"). Any deviation from this hash invalidates the run.

2. **Direction filter.** Egress = `destination == 1` (⇔ ARFF `command response == 0`,
   response/telemetry, thesis-confirmed + now ARFF-cross-verified). 137,013 egress
   frames. The `destination == 3` direction is a labelled sensitivity run only.

3. **Split.** Contiguous time-block, decided now, before any metric:
   - 60 / 20 / 20 by **egress-window index** (same rule as the retracted EXP-0001/2,
     which is a defensible default and keeps the design comparable).
   - 1-window (5 s) guard gap discarded at each of the two boundaries.
   - Boundaries recorded as absolute epoch `time` + ISO-8601 in the EXP-0004 entry
     and the report, per `03-data-split-protocol.md`.
   - TRAIN normal-only subset = windows with no attack-labelled frame
     (`categorized == 0` for every frame in the window).
   - TEST scored exactly once.

4. **Feature set — starting point = EXP-0002 headline, entropy status RE-OPENED.**
   - IF inputs (candidate, 14): `packet_count, packets_per_sec, bytes_per_sec,
     mean_frame_len, iat_{mean,std,min,max}, frac_func_{read,write},
     distinct_frame_ratio, repeat_frame_rate, payload_entropy_{mean,std}`.
   - Deterministic rule layer (not IF inputs): out-of-profile function code /
     novel slave address, profile frozen from TRAIN-normal.
   - `frac_func_valid`, `rare_func_rate` stay out of the IF (zero variance on normal).
   - **Entropy decision:** because BLOCKER 3 is now genuinely resolved (verified
     alignment, not "the TXT is self-labelled"), entropy IS legitimately evaluable
     against authoritative labels. It stays a **candidate headline input**, but its
     contribution must be reported as a paired with/without-entropy comparison in the
     EXP-0004 entry (recall, precision, PR-AUC each way), and the headline slot is
     only confirmed if entropy adds measured signal on the verified file — not
     inherited from the retracted EXP-0001.

5. **Model.** `sklearn.IsolationForest`, `n_estimators=300`, `max_samples="auto"`,
   `contamination="auto"` (not used for thresholding), `random_state=0`. Standardiser
   (mean/std) frozen from TRAIN-normal.

6. **Threshold.** 99th percentile of VALIDATION-normal anomaly scores (target FPR 1%).
   Chosen on validation only.

7. **Artifact / leakage audit** (`03-data-split-protocol.md` checklist, run on TRAIN
   only): boundary sanity; function-code tail per-class; the "exactly-40" scripted
   pattern; `source == 2` leak confirmation (see §5); field-presence not applicable
   (TXT has no sparse columns). Recorded PASS/FAIL/NEEDS-DOC in the entry before any
   metric is quoted.

8. **Metrics reported:** precision, recall, F1, FPR, FNR, PR-AUC, ROC-AUC, per-category
   (Normal/NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Recon) flag rate, inference latency, throughput.
   Naive baseline (Stage 0) reported alongside. Headline recall computed over the
   pre-registered CAN / PARTIAL-CAN categories only (that table is re-inherited from
   the top of this log — it derives from the thesis, not the retracted file, but the
   DoS "MEASURED (EXP-0003)" citation reverts to "reasoning; EXP-0003 retracted" until
   EXP-0004 re-measures it).

9. **DoS re-measurement.** Fold the EXP-0003 question (egress IAT separation for DoS)
   back in as a section of EXP-0004 or a same-day EXP-0005, on the verified file, with
   the same pre-registered NO-SEPARATION / SEPARATION / AMBIGUOUS decision rule.

**ABORTED INFRASTRUCTURE FAILURE:** First invocation computed TEST scores in memory but
aborted before displaying or persisting any results because the `data/experiments/`
directory did not exist. No TEST metrics or predictions were viewed. Directory created;
EXP-0004 re-run below under the unchanged pre-registration, with this deviation disclosed.

**ABORTED INFRASTRUCTURE FAILURE:** Second invocation computed TEST scores in memory but
aborted before displaying or persisting a usable report because the Windows default
CP-1252 encoding could not encode a Unicode arrow. No TEST metrics or predictions were
viewed. Report output fixed to UTF-8; EXP-0004 re-run below under the unchanged
pre-registration, with this deviation disclosed.

**OUTPUT-ONLY FAILURE AFTER SUCCESSFUL EXP-0004 SCORING:** The next invocation scored
TEST and persisted the complete UTF-8 report, then exited non-zero while printing that
same report to the CP-1252 console (`UnicodeEncodeError` on `→`). The persisted report
was subsequently read and is the recorded EXP-0004 result. No detector rerun was used
to conceal or replace it.

## Experiments

### EXP-0001 · Isolation Forest egress anomaly detector (windowed, TXT egress) — 2026-09-04
> **🚫 RETRACTED 2026-09-08.** Run on the fabricated file `gas_pipeline_raw.txt`
> (sha256 `45de4266…fbbd`). All numbers in this entry are withdrawn. Retained for
> audit only. See the RETRACTION NOTICE at the top of this file and `DECISION_LOG.md`
> 2026-09-08. Do not cite any figure below.

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
> **🚫 RETRACTED 2026-09-08.** Run on the fabricated file `gas_pipeline_raw.txt`
> (sha256 `45de4266…fbbd`). All numbers in this entry are withdrawn. Retained for
> audit only. See the RETRACTION NOTICE at the top of this file and `DECISION_LOG.md`
> 2026-09-08. Do not cite any figure below.

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
> **🚫 RETRACTED 2026-09-08.** Run on the fabricated file `gas_pipeline_raw.txt`
> (sha256 `45de4266…fbbd`). All numbers in this entry are withdrawn. Retained for
> audit only. See the RETRACTION NOTICE at the top of this file and `DECISION_LOG.md`
> 2026-09-08. Do not cite any figure below.

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

---

### EXP-0004 · Verified-file detector rebaseline + DoS timing re-measurement — 2026-09-08

- **Pre-registration:** the EXP-0004 block above was committed before the first detector
  invocation. Infrastructure/output deviations are disclosed there. The successful
  scoring result is the persisted `data/experiments/iforest_detector_report.md`.
- **Dataset:** `data/raw/gas_pipeline_raw.txt`, sha256
  `ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3`,
  18,627,186 bytes, 274,628 rows; verified row-aligned to
  `data/raw/IanArffDataset.arff`, sha256
  `970a7bcd3949d09ac7baff11603538b142f214ee47ed70baf9efb3344f4af459`.
- **Environment:** Python 3.12.10; NumPy 2.5.3; scikit-learn 1.9.0; SciPy 1.18.1.
- **Direction/windowing:** `destination == 1`, 137,013 egress frames; 5-second tumbling
  windows; 46,736 emitted windows.
- **Split:** contiguous 60/20/20 with one-window guard at each boundary: TRAIN 28,040,
  VALIDATION 9,345, TEST 9,347. TRAIN normal-only fit subset: 14,951 windows. TEST:
  4,807 Normal / 4,540 attack. Window start boundaries (epoch): TRAIN
  1418682165..1418846180; VALIDATION 1418846195..1418900830; TEST
  1418900845..1418957850. Guard between emitted blocks is 15 seconds (one omitted
  5-second bucket plus disjoint adjacent buckets). TEST scored once for the persisted
  result.
- **Model:** Isolation Forest, 300 trees, `max_samples="auto"`,
  `contamination="auto"`, seed 0; standardizer fit on TRAIN-normal. Threshold
  0.6745465823488428 = VALIDATION-normal 99th percentile.
- **Artifact/leakage audit:**
  - R1/R2: `source` is absent from model features. `categorized × source` confirms NMRI
    and CMRI occur exclusively at `source==2`; all 40,739 `source==2` rows are attack.
  - R4: among 214,580 Normal frames, 2 validate Modbus CRC-16 little-endian
    (0.000932%); 0 validate big-endian. This is effectively absent and is not a model
    feature.
  - R5: TRAIN-normal profile learned function codes `{0x03,0x10}` and address `{4}`.
    Rule fires on 0/4,807 Normal TEST windows; no novel-address Normal hits.
  - R6: every TRAIN tail function code outside `{0x03,0x10}` is attack-labelled
    (Recon or MFCI); the rule profile remains normal-only.
  - R7: exactly-40 function-code families occur across TRAIN/VALIDATION/TEST for the
    exception-code subset; request-code and address scripted tails are absent from the
    egress-window blocks because they occur in the opposite direction. This is a
    direction effect, not random split leakage. Boundary sanity PASS.
  - R8–R12: disjoint bucket split/guard PASS; timestamps ordered; local +1 row versus
    thesis remains documented; provisional CSV remains DISCARD and is unused;
    determinism test PASS. Field-presence check N/A for six-field TXT.
- **TEST metrics:**

  | detector | precision | recall | F1 | FPR | FNR | PR-AUC | ROC-AUC |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | Stage 0 naive baseline | 1.000 | 0.152 | 0.264 | 0.000 | 0.848 | — | — |
  | Deterministic rule only | 1.000 | 0.152 | 0.264 | 0.000 | 0.848 | — | — |
  | IF, **with entropy** | 0.932331 | 0.109251 | 0.195584 | 0.007489 | 0.890749 | 0.649319 | 0.619625 |
  | IF, **without entropy** | 0.558824 | 0.008370 | 0.016493 | 0.006241 | 0.991630 | 0.556460 | 0.563730 |
  | **Combined rule OR IF (with entropy)** | **0.954023** | **0.164537** | **0.280669** | **0.007489** | **0.835463** | — | — |

  Combined confusion: TN 4,771; FP 36; FN 3,793; TP 747. Measured IF TEST scoring
  throughput: 68,670 windows/s (0.136 s for 9,347 windows); IF fit 0.454 s. These are
  local component timings, not end-to-end pipeline latency.
- **Per-category combined flag rate:** Normal 36/4,807 = 0.749%; NMRI 109/1,131 =
  9.638%; CMRI 232/1,812 = 12.804%; MSCI 2/324 = 0.617%; MPCI 8/741 = 1.080%;
  MFCI 227/227 = 100%; DoS 0/136 = 0%; Recon 169/169 = 100%.
- **Entropy decision:** CONFIRMED as a headline candidate on the verified file. Against
  the paired no-entropy IF, entropy raises recall 0.008370→0.109251, precision
  0.558824→0.932331, PR-AUC 0.556460→0.649319, and ROC-AUC
  0.563730→0.619625. This is measured anew and does not inherit retracted results.
- **DoS re-measurement:** report `data/experiments/exp0004_dos_timing.txt`. TEST has
  4,807 pure-Normal and 193 DoS-containing windows. Cohen's d for
  `iat_mean/std/min/max` = -0.086/+0.098/-0.123/-0.029; best ≤5% Normal-FPR threshold
  reaches only 2.6%/3.1%/4.7%/2.6% DoS recall. Raw-gap d=-0.046, MWU p=0.308,
  KS p=0.461. **Verdict: NO SEPARATION** under the pre-registered rule (all |d|<0.2;
  overlapping raw-gap distributions). No new DoS feature or rule.
- **Tests:** first rebaseline run: 17 passed, 2 failed due to two stale expected values
  (`3_610` and an incorrectly transcribed full-precision F1). After correcting only
  those expectations, full pytest: **19 passed in 22.39 s**.
- **Decision:** EXP-0004 supersedes all detector/DoS numbers from retracted
  EXP-0001/0002/0003. Reliable detections remain MFCI and Recon via the explicit rule;
  other attack families are weak and DoS has no measured egress timing separation.

---

### EXP-0005 · Layer A pre-diode DoS detector proof of concept — 2026-09-08

> **PRE-REGISTRATION — PLANNED.** Recorded before `ml/layer_a_detector.py` exists and
> before any EXP-0005 model is fit, thresholded, or scored. No EXP-0005 result has been
> viewed at this point.

- **PLANNED — architectural scope:** Layer A is an OT-side sensor placed before the
  data diode, where legitimate bidirectional observation is available. It emits only a
  sanitized alert verdict outward; raw bidirectional traffic does not cross the diode.
  This is a separate proof of concept, not a change to EXP-0004's Layer B egress-only
  framing and not a weakening of the diode's one-way guarantee. EXP-0004's measured
  DoS limitation stands unchanged.
- **PLANNED — dataset:** use the current verified
  `data/raw/gas_pipeline_raw.txt`, sha256
  `ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3`, all
  274,628 rows and both directions (`destination ∈ {1,3}`). This is the unfiltered,
  original bidirectional Turnipseed stream, not EXP-0004's `destination == 1` egress
  slice. The TXT is verified row-aligned to the authoritative ARFF on timestamp, both
  labels, and direction; direction semantics are thesis-confirmed.
- **PLANNED — unit and label:** 5-second tumbling windows over the full time-ordered
  stream, with windows containing fewer than two frames omitted. A window is DoS-positive
  if it contains at least one `categorized_attack == 6` frame; a pure-Normal window has
  only `categorized_attack == 0` frames. Other-attack windows are excluded from the
  primary DoS-vs-Normal metric cohort rather than incorrectly counted as DoS false
  positives.
- **PLANNED — split/leakage control:** sort windows by absolute bucket index, then use
  the same contiguous 60/20/20 split rule and one-window guard at both boundaries as
  EXP-0004. Fit the standardizer and model on TRAIN pure-Normal windows only. Select
  the threshold as the 99th percentile of VALIDATION pure-Normal anomaly scores. Score
  TEST once after the implementation/tests are ready. Labels, `source`, `destination`,
  absolute timestamp, and raw bucket index are excluded from model inputs.
- **PLANNED — features:** per-window `packet_count`, `packets_per_sec`,
  `bytes_per_sec`, `mean_frame_len`, `iat_mean`, `iat_std`, `iat_min`, `iat_max`,
  `frac_func_read`, `frac_func_write`, `rare_func_rate`, `distinct_frame_ratio`,
  `repeat_frame_rate`, `payload_entropy_mean`, and `payload_entropy_std`. Inter-arrival
  times are computed only between consecutive frames inside each window, not across
  split boundaries.
- **PLANNED — model and rationale:** reuse the normal-only Isolation Forest approach
  from EXP-0004: 300 trees, `max_samples="auto"`, `contamination="auto"`, seed 0,
  with frozen TRAIN-normal standardization. This avoids training a supervised detector
  on known DoS labels and tests the intended operational question: whether bidirectional
  pre-diode traffic makes DoS statistically observable. A supervised classifier is not
  needed for this scoped proof of concept.
- **PLANNED — fixed decision/reporting rule:** this is a descriptive proof of concept
  with **no pass/fail performance gate**. Report the held-out TEST precision, recall,
  F1, FPR, and TN/FP/FN/TP exactly as observed, including a weak or null result. No
  threshold or feature may be changed after TEST metrics are viewed under EXP-0005;
  any such change requires a separately pre-registered experiment ID.
- **PLANNED — comparison:** report EXP-0005 Layer A DoS-specific metrics beside the
  validated EXP-0004 Layer B DoS result (0/136 dominant-DoS TEST windows flagged = 0%
  combined flag rate; the broader timing cohort contained 193 DoS-containing windows).
  The cohorts and units must be labelled, so this is an architectural contrast rather
  than a claim that Layer A universally solves DoS detection.
- **PLANNED — outputs/tests:** isolated implementation in `ml/layer_a_detector.py`,
  tests in a new Layer A test file, and machine-readable metrics under
  `data/experiments/`. No dashboard, REST API, SQLite, or Layer B code changes.

#### EXP-0005 outcome

- **IMPLEMENTED — code:** `ml/layer_a_detector.py` implements the pre-registered
  bidirectional window builder, frozen TRAIN-normal standardizer, Isolation Forest,
  validation-normal threshold, DoS-vs-pure-Normal TEST cohort, metrics, and JSON output.
  `tests/test_layer_a_detector.py` contains five isolated tests. No Layer B or dashboard
  file was modified.
- **TESTED — pre-TEST checks:** before the real EXP-0005 run, all five new synthetic
  tests passed in 2.17 s. They verify both directions are retained, IAT is computed
  inside a window, model features exclude labels/direction/identity/time, guard gaps
  are present, other-attack-only windows are excluded from the DoS cohort, and empty
  input is rejected.
- **VALIDATED — data/split:** the one permitted EXP-0005 run parsed 274,628 frames with
  observed destination values `{1,3}` and emitted 50,080 bidirectional 5-second
  windows. Contiguous blocks after guards: TRAIN 30,047 / VALIDATION 10,014 / TEST
  10,015. TRAIN pure-Normal fit set: 15,616; VALIDATION pure-Normal threshold set:
  5,013. TEST metric cohort: 4,931 pure-Normal + 193 DoS-containing windows. This
  confirms the run used the verified full bidirectional stream rather than Layer B's
  137,013-frame egress slice.
- **VALIDATED — model/threshold:** Isolation Forest with the pre-registered parameters;
  threshold `0.6950767586842237`, selected as the 99th percentile of VALIDATION
  pure-Normal scores before TEST classification.
- **VALIDATED — TEST metrics (DoS-containing vs pure-Normal windows):**

  | detector | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---|---:|---:|---:|---:|---:|---:|---:|---:|
  | Layer A EXP-0005 IF | 0.000000 | 0.000000 | 0.000000 | 0.015818 | 4,853 | 78 | 193 | 0 |

- **VALIDATED — architectural comparison:**

  | layer / observation point | DoS cohort used | DoS flagged | DoS flag rate |
  |---|---|---:|---:|
  | Layer A EXP-0005, pre-diode bidirectional | 193 DoS-containing TEST windows vs 4,931 pure-Normal | 0 / 193 | 0.000% recall |
  | Layer B EXP-0004, post-diode egress-only | 136 dominant-DoS TEST windows | 0 / 136 | 0.000% combined flag rate |

  The denominators differ and are shown explicitly; this is not a paired metric claim.
- **VALIDATED — interpretation:** the EXP-0005 Isolation Forest proof of concept did
  **not** detect DoS in this dataset despite bidirectional placement. Bidirectional
  visibility makes pre-diode DoS detection architecturally possible in principle, but
  does not guarantee that these pre-registered features contain a separable signal.
  The dataset's attack is labelled "Bad CRC," while standard Modbus CRC validity is
  effectively absent across this artifact and was therefore not used as a feature.
  Layer A does not "solve" DoS here. Layer B's structural limitation still stands,
  and Layer A remains separate because it has a different legitimate observation
  boundary—not because this experiment demonstrated improved performance.
- **VALIDATED — fixed-rule disposition:** the no-gate rule requires reporting this null
  result unchanged. No post-TEST feature, threshold, or model tuning was performed.
  Machine-readable output: `data/experiments/exp0005_layer_a_metrics.json` (under the
  repository's ignored `data/` tree; local experiment artifact, not raw-data input).

---

### EXP-0005b · Diagnostic supervised baseline + raw feature separation — 2026-09-08

> **PRE-REGISTRATION — PLANNED.** Recorded after EXP-0005's fixed result was viewed but
> before this additional model is fit or any TEST feature summaries are computed. This
> does not overwrite, rerun, or retune EXP-0005.

- **PLANNED — question:** determine whether EXP-0005's null result arose because its
  normal-only anomaly-score threshold missed a signal that a supervised classifier can
  use, or because the pre-registered feature values show little DoS-vs-Normal separation.
- **PLANNED — unchanged data/unit/split/features:** reuse EXP-0005's 50,080 unfiltered
  bidirectional 5-second windows, identical contiguous TRAIN/VALIDATION/TEST indices and
  guard gaps, and identical 15 features. A positive window means **any DoS frame is
  present** (`categorized_attack == 6`); it is not a majority or dominant-category
  rule. Pure-Normal means the category set is exactly `{0}`. Other-attack-only windows
  remain outside the binary cohort. This differs from EXP-0004's reported 136-window
  **dominant-DoS** category row; EXP-0004's separate timing diagnostic used the broader
  DoS-containing definition (193 windows).
- **PLANNED — supervised baseline:** `sklearn.RandomForestClassifier` with 300 trees,
  `class_weight="balanced"`, `random_state=0`, `n_jobs=-1`, trained on TRAIN
  DoS-containing plus pure-Normal windows only. Use only the same 15 numeric features;
  labels, `source`, `destination`, timestamp, and bucket ID remain excluded. Use the
  fixed probability threshold 0.5; do not tune it on VALIDATION or TEST. Report TEST
  precision, recall, F1, FPR, and TN/FP/FN/TP on the same DoS-vs-pure-Normal cohort.
- **PLANNED — feature diagnostic:** report mean and population standard deviation for
  every raw feature over all 193 TEST DoS-containing windows and over a deterministic
  simple random sample (seed 0, without replacement) of 193 TEST pure-Normal windows.
  These are descriptive raw values, not model scores or inferential guarantees.
- **PLANNED — decision rule:** no performance gate and no post-result tuning. If the
  supervised baseline finds material held-out signal or the raw summaries visibly
  separate, treat EXP-0005 as a fixable modeling/feature-threshold gap and do not claim
  a fundamental data limit. If both remain null/near-null, retain EXP-0005's null result
  with this additional evidence. Report whatever occurs exactly.

#### EXP-0005b outcome

- **IMPLEMENTED — diagnostic:** `ml/exp0005b_diagnostic.py` implements only the
  pre-registered supervised comparison and raw-value summaries. The first invocation
  stopped at Python parse time due to an unterminated output newline literal; no data
  was loaded and no model/result was produced. That syntax-only defect was corrected,
  after which the one scoring run below was performed. EXP-0005 was not rerun.
- **IMPLEMENTED — tests:** `tests/test_exp0005b_diagnostic.py` checks the fixed
  classifier configuration and any-DoS-frame label rule, exact validated TEST counts
  and metrics, and complete equal-size raw-feature summaries.
- **TESTED — full suite:** all 36 tests passed after EXP-0005b implementation,
  including the 28 pre-Layer-A tests, five EXP-0005 tests, and three EXP-0005b tests.
- **VALIDATED — supervised TEST metrics:** TRAIN cohort contained 15,616 pure-Normal
  and 359 DoS-containing windows. On the unchanged TEST cohort (4,931 pure-Normal +
  193 DoS-containing), the fixed 0.5 Random Forest threshold produced:

  | detector | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---|---:|---:|---:|---:|---:|---:|---:|---:|
  | EXP-0005b supervised Random Forest | 0.630252 | 0.388601 | 0.480769 | 0.008923 | 4,887 | 44 | 118 | 75 |

- **VALIDATED — raw TEST feature values:** DoS columns use all 193 DoS-containing
  windows; Normal columns use the pre-registered seed-0 sample of 193 pure-Normal
  windows. Standard deviations are population standard deviations.

  | feature | DoS mean | DoS std | Normal sample mean | Normal sample std |
  |---|---:|---:|---:|---:|
  | packet_count | 5.968912 | 0.247406 | 5.704663 | 0.987397 |
  | packets_per_sec | 1.193782 | 0.049481 | 1.140933 | 0.197479 |
  | bytes_per_sec | 25.099482 | 2.447384 | 23.915026 | 5.184216 |
  | mean_frame_len | 21.023637 | 1.852236 | 20.761411 | 2.412335 |
  | iat_mean | 0.699529 | 0.041197 | 0.682723 | 0.161629 |
  | iat_std | 0.704792 | 0.021963 | 0.665114 | 0.164904 |
  | iat_min | 0.085740 | 0.007866 | 0.086462 | 0.009096 |
  | iat_max | 1.612139 | 0.048005 | 1.526069 | 0.356453 |
  | frac_func_read | 0.495806 | 0.163794 | 0.512805 | 0.192736 |
  | frac_func_write | 0.503158 | 0.163818 | 0.487195 | 0.192736 |
  | rare_func_rate | 0.001036 | 0.014359 | 0.000000 | 0.000000 |
  | distinct_frame_ratio | 0.829164 | 0.044856 | 0.763928 | 0.106254 |
  | repeat_frame_rate | 0.000000 | 0.000000 | 0.000000 | 0.000000 |
  | payload_entropy_mean | 3.148738 | 0.071799 | 3.162245 | 0.076283 |
  | payload_entropy_std | 0.254053 | 0.072179 | 0.229369 | 0.079662 |

- **VALIDATED — three-way comparison:**

  | layer / model | observation point and cohort | precision | recall / DoS flag rate | F1 | FPR |
  |---|---|---:|---:|---:|---:|
  | Layer B EXP-0004 combined | post-diode egress-only; 136 dominant-DoS TEST windows | not defined for DoS-only row | 0.000000 | not defined for DoS-only row | 0.007489 overall Normal FPR |
  | Layer A EXP-0005 Isolation Forest | pre-diode bidirectional; 193 DoS-containing vs 4,931 pure-Normal | 0.000000 | 0.000000 | 0.000000 | 0.015818 |
  | Layer A EXP-0005b Random Forest | same pre-diode data, split, features, and TEST cohort as EXP-0005 | 0.630252 | 0.388601 | 0.480769 | 0.008923 |

  Layer B's precision/F1 are not derivable from its DoS category flag-rate row; its FPR
  shown is the validated detector-wide Normal TEST FPR. The different Layer B cohort is
  explicit. EXP-0005 and EXP-0005b are directly comparable on the same full-visibility
  cohort.
- **VALIDATED — interpretation:** the supervised baseline finds material held-out
  signal (75/193 DoS windows, 38.86% recall at 0.892% FPR), so EXP-0005's 0% result is
  a modeling/objective gap: normal-only Isolation Forest did not rank the comparatively
  tight DoS pattern as anomalous. The raw summaries support that diagnosis: several
  DoS feature distributions are narrower than Normal and modestly shifted, especially
  packet count/rate, IAT dispersion/maximum, and distinct-frame ratio. **These are
  subtle, tight-distribution shifts rather than extreme or volumetric behavior, so the
  dataset's "DoS" must not be described as a classic traffic flood in the final
  writeup.** This is **not** evidence of a fundamental bidirectional data limit and does
  not mean Layer A solves DoS: the supervised baseline still misses 118/193 DoS windows,
  and its generality beyond this labelled testbed is unvalidated. No post-result tuning
  was performed.
- **VALIDATED — artifact:** machine-readable output is local at
  `data/experiments/exp0005b_diagnostic.json` (ignored `data/` tree).

---

### EXP-0006 · Layer A DoS payload / imbalance / model ablation — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before any EXP-0006 payload audit, feature
> extraction, model fit, validation, or TEST scoring. EXP-0005/0005b and their files
> remain unchanged.

- **PLANNED — question:** measure independently whether Layer A DoS performance changes
  from (A) adding audited ARFF payload fields, (B-a) training-fold-only SMOTE with the
  original Random Forest, or (B-b) changing from Random Forest to gradient boosting on
  the original data; then measure the pre-specified combination of all three. Do not
  collapse these ablations into one headline number.
- **PLANNED — fixed success rule:** relative to EXP-0005b recall `0.388601`, an
  individual change is a **meaningful improvement** only if held-out TEST recall rises
  by at least 10 percentage points (to `>=0.488601`) while precision remains `>=0.55`.
  The combined run uses the same rule. Report all outcomes regardless of pass/fail; do
  not tune features, hyperparameters, sampling, or thresholds after TEST is viewed.
- **PLANNED — unchanged cohort/split:** use the verified 274,628-row ARFF aligned to the
  EXP-0005 bidirectional TXT, identical 50,080 five-second buckets and identical
  contiguous TRAIN/VALIDATION/TEST indices with one-window guards. Positive means any
  `categorized result == 6` frame is present; negative means a pure-Normal window.
  Other-attack-only windows remain outside the binary cohort. Fit/resample on TRAIN
  only; neither VALIDATION nor TEST is resampled. Fixed classification threshold `0.5`.
- **PLANNED — payload leakage audit before use:** audit separately the 11 candidate ARFF
  payload fields: `setpoint`, `gain`, `reset rate`, `deadband`, `cycle time`, `rate`,
  `system mode`, `control scheme`, `pump`, `solenoid`, `pressure measurement`. `crc
  rate` is not a candidate because the existing schema already marks it artifact-suspect
  and its standard Modbus meaning is invalid for this artifact. For each candidate,
  report Normal/DoS row presence, missingness, unique observed values, and observed
  value overlap. Exclude a field if presence alone perfectly separates DoS from Normal,
  if non-missing value sets are disjoint with both groups represented, or if it is
  constant on Normal but changes only during DoS. Missingness indicators are not model
  inputs, preventing frame-type presence from becoming a proxy. If semantics remain
  ambiguous after this audit, stop rather than score Change A.
- **PLANNED — Change A alone:** add surviving payload fields through new EXP-0006 code,
  preserving the original 15-feature matrix unchanged. Aggregate each surviving field
  per window as the mean of available values; impute missing window aggregates using
  TRAIN-cohort medians frozen before TEST. Train the exact EXP-0005b Random Forest
  (`300` trees, `class_weight="balanced"`, seed `0`) without SMOTE.
- **PLANNED — Change B(a) alone:** on only the original 15 EXP-0005b features, apply
  standard SMOTE (`sampling_strategy="auto"`, `k_neighbors=5`, seed `0`) to the TRAIN
  cohort only, then train the exact EXP-0005b Random Forest except that SMOTE supplies
  the balancing and `class_weight=None` isolates SMOTE's effect.
- **PLANNED — Change B(b) alone:** on the original 15 features and original unresampled
  TRAIN cohort, train `xgboost.XGBClassifier` with fixed defaults except
  `n_estimators=300`, `random_state=0`, `n_jobs=-1`, `eval_metric="logloss"`, and
  `scale_pos_weight = n_train_normal / n_train_dos`. XGBoost is already a declared
  project dependency. This isolates model choice from payload and SMOTE.
- **PLANNED — combined:** surviving payload-expanded matrix + TRAIN-only SMOTE + the
  same fixed XGBoost configuration, with `scale_pos_weight=1` because SMOTE balances
  the TRAIN classes. Run only after A, B(a), and B(b) have each been scored and recorded
  in memory. Report precision, recall, F1, FPR, and confusion counts for every row.
- **PLANNED — outputs/scope:** new isolated `ml/exp0006_detector.py`, new EXP-0006 tests,
  and local machine-readable audit/results under ignored `data/experiments/`. Do not
  modify Layer B, `app.py`, EXP-0005/0005b implementation files, or their existing tests.

---

### EXP-0007 · Query-type-aware egress cadence DoS experiment — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before the EXP-0007 response-type audit,
> feature extraction, CUSUM calibration, supervised fit, validation inspection, or TEST
> scoring. EXP-0004, Layer A, and EXP-0005/0005b files remain unchanged.

- **PLANNED — Step 0 background:** the completed source-3 egress Normal-to-Normal IAT
  diagnostic found unfiltered mean `2.005 s`, population CV `0.513`, and maximum
  `170.036 s`. The 170 s, 25.6 s, and leading approximately 12 s gaps bridge intervening
  attack-labelled traffic, especially repeated Normal→Reconnaissance→Normal sequences;
  they are not capture-boundary artifacts. Excluding gaps above 10 s lowers CV to
  `0.314`, but leaves two apparent cadences near 1.5–1.9 s and 3.3–3.7 s. This motivates
  type stratification; it is not yet evidence that the types are identifiable or useful.
- **PLANNED — hard observation boundary:** use only egress records with
  `destination == 1` in every audit, baseline, feature, fit, calibration, and evaluation.
  No command-side or bidirectional record may enter EXP-0007. This is the primary
  in-scope attempt at the problem statement's unidirectional DoS requirement; Layer A
  and EXP-0005b are context only and do not satisfy that requirement.
- **PLANNED — response-type audit and stop gate:** derive a type only from fields visible
  in each egress response. Prefer function code (`0x03` read response versus `0x10`
  write echo) if response shape confirms an unambiguous two-type interpretation; use
  `(function_code, is_request, frame_len_bytes, byte_count)` only to audit consistency.
  `source` partitions cadence streams but is not an input feature. Proceed only if
  source 3 has exactly two dominant, parser-certain types; each has at least 1,000
  TRAIN-normal frames, 200 eligible TRAIN-normal IATs, and 100 TRAIN-normal windows;
  both occur in TRAIN and VALIDATION and overlap pure-Normal and DoS-containing windows;
  each type's TRAIN-normal CV is below pooled CV; and their IAT-count-weighted CV is at
  least 20% below pooled CV. Type definitions cannot use labels or TEST. If any rule
  fails or the field is ambiguous, report `STOPPED — AUDIT GATE`; do not build either
  detector and mark TEST `NOT RUN`.
- **PLANNED — window, split, and labels:** use absolute five-second egress tumbling
  windows with at least two egress frames, ordered before splitting. Reuse the existing
  contiguous 60/20/20 convention with one-window guards; do not re-split after cohort
  filtering. Positive means **DoS-containing**: at least one
  `categorized_attack == 6` egress frame. Negative means pure-Normal, categories exactly
  `{0}`. Exclude other-attack-only windows. This matches EXP-0004's timing cohort and
  differs from its 136-window **dominant-DoS** per-category result.
- **PLANNED — cadence baseline/features:** for each supported `(source, type)`, form IATs
  only between consecutive same-stream events, never across a guard, split, or
  non-pure-Normal baseline interval. Fit expected IAT mean and population standard
  deviation from TRAIN-normal only and report mean/median/std/CV. In each existing
  five-second window aggregate per-stream IAT, signed/positive deviation from the
  correct baseline, normalized deviation, missed cycles
  `max(0, round(IAT / expected_IAT) - 1)`, and CUSUM state/max/alarm counts. Labels,
  raw source/destination, timestamps, and bucket IDs remain outside model inputs.
- **PLANNED — Detector A:** one-sided positive-delay CUSUM per supported `(source,type)`:
  `S_t = max(0, S_(t-1) + z_positive - 0.5)`, with scale floor
  `max(1e-6, 0.01 * expected_IAT)`. Reset at split/guard boundaries and immediately
  after recording a threshold crossing. Fit each threshold exclusively as the
  TRAIN-normal five-second CUSUM-max 99th percentile (`method="higher"`), bounded below
  by `0.5`. Alert a window if any stream crosses its frozen threshold.
- **PLANNED — Detector B:** train `RandomForestClassifier` on only the frozen cadence
  features from the TRAIN DoS-containing/pure-Normal cohort, with `n_estimators=300`,
  `class_weight="balanced"`, `random_state=0`, `n_jobs=-1`, and fixed probability
  threshold `0.5`. Validation is descriptive only; it may not change features,
  thresholds, type selection, or model settings.
- **PLANNED — fixed reporting rule:** there is **no pass/fail performance gate**. After
  pre-TEST tests pass, score the frozen TEST cohort once and report precision, recall,
  F1, FPR, and TN/FP/FN/TP for Detector A and Detector B exactly, including null or
  near-zero results. No post-TEST tuning is authorized under EXP-0007.
- **PLANNED — comparison/limitations:** compare with EXP-0004 egress-only 0/136
  dominant-DoS windows and EXP-0005b bidirectional 38.8601% recall, labelling their
  different cohorts and EXP-0005b as out of scope. A response type is only an
  egress-visible proxy for an unseen query, and `source` is dataset grouping metadata;
  one testbed cannot establish universal DoS detectability or impossibility.
- **PLANNED — isolated outputs/tests:** add only `ml/cadence_features.py`,
  `ml/exp0007_cadence.py`, dedicated tests, and local generated
  `data/experiments/exp0007_cadence.json`. Run the full suite before and after and report
  exact counts. Do not modify Layer A, `app.py`, `ml/features_windowed.py`,
  `ml/iforest_detector.py`, or EXP-0004 code/tests.

#### EXP-0007 response-type audit

- **TESTED — pre-change baseline:** before adding EXP-0007 code, the complete existing
  suite collected and passed **36 tests in 35.21 s** under Python 3.12.10 and pytest
  9.1.1. It exercised the real local verified dataset through existing integration
  fixtures; no failure, skip, or deselection occurred.
- **INVALIDATED — egress/type identity output:** the audit read 137,013 records after applying
  `destination == 1` and emitted the existing 46,736 eligible five-second egress
  windows (TRAIN 28,040 / VALIDATION 9,345 / TEST 9,347; TEST labels/features were not
  inspected for type selection). Source 3's Normal egress responses have exactly two
  parser-certain shapes: function `0x03` is always `(is_request=0, length=23,
  byte_count=18)` with 48,060 full-capture Normal frames; function `0x10` is always
  `(is_request=0, length=8, byte_count=-1)` with 48,856. Therefore function code is the
  fixed response-visible type field. It is a proxy for the unseen request type, not
  observation of command-side traffic.
- **INVALIDATED — TRAIN/VALIDATION support output:** source 3 function `0x03` has 27,889 TRAIN
  frames, appears in 14,951 TRAIN-normal and 232 TRAIN DoS-containing windows, then
  9,577 / 4,852 / 98 respectively in VALIDATION. Function `0x10` has 37,981 TRAIN
  frames, appears in 14,941 TRAIN-normal and 359 TRAIN DoS-containing windows, then
  13,248 / 4,848 / 203 in VALIDATION. Both exceed the fixed frame/IAT/window minima and
  overlap both classes before TEST. Source 2 has no pure-Normal window support and is
  excluded from cadence profiles rather than used as an attack-correlated feature.
- **INVALIDATED — TRAIN-normal cadence output:** eligible IATs reset across split, guard, and
  non-pure-Normal regions. Pooled source-3 IAT: `n=42,190`, mean `1.745896 s`, median
  `1.763541 s`, std `0.116227 s`, CV `0.066571`. Split `0x03`: `n=20,803`, mean
  `3.491012 s`, median `3.521090 s`, std `0.158879 s`, CV `0.045511`. Split `0x10`:
  `n=20,816`, mean `3.492007 s`, median `3.521104 s`, std `0.153074 s`, CV `0.043835`.
  The IAT-count-weighted split CV is `0.044673`, 32.895% below pooled CV (ratio
  `0.671052`), so both individual-CV rules and the fixed ≥20% tightening rule pass.
  This TRAIN-only gate is meaningfully tighter than the prior full-capture filtered
  pooled CV `0.314`, though those populations differ and are not a paired estimate.
- **INVALIDATED — audit disposition:** **PASS — proceed with the two frozen source-3
  response types `0x03` and `0x10`.** No other source has sufficient TRAIN-normal
  support. Type selection was frozen before Detector A/B execution.

#### EXP-0007 outcome — INVALIDATED BEFORE ACCEPTANCE

> **INVALIDATED.** Post-run review found that the implementation did not exactly enforce
> two pre-registered leakage controls. The numeric output below is retained as an invalid
> audit trail and must not be presented as validated performance or used to tune a rerun.
> EXP-0007 will not be rerun under the same experiment ID.

- **IMPLEMENTED — isolated code:** `ml/cadence_features.py` implements the hard egress
  filter, frozen function-code types, TRAIN-normal type baselines, per-stream cadence
  features, and one-sided CUSUM. `ml/exp0007_cadence.py` implements the fixed CUSUM and
  Random Forest evaluation and local JSON output. Existing Layer A, EXP-0004, Tier 1,
  and dashboard code was not modified.
- **TESTED — pre-TEST checks:** eight collected synthetic test cases passed in 3.39 s,
  then the full suite passed **44/44 in 32.13 s** before the one frozen TEST run. The final post-result
  full suite also passed **44/44 in 32.78 s** after invalidation was recorded. Tests cover the
  direction/type boundary, independent per-type pairing, attack-interval reset for
  baseline fitting, missed-cycle and CUSUM arithmetic/reset, TRAIN-normal threshold
  calibration, forbidden feature metadata, and fixed Random Forest configuration. The
  suite increased from 36/36 before changes to 44/44 before TEST.
- **INVALIDATED — execution scope/cohort output:** the single frozen run used 137,013 egress
  records with observed destination set exactly `{1}` and 46,736 windows. Binary cohorts
  were TRAIN 14,951 Normal + 359 DoS-containing, VALIDATION 4,852 + 203, and TEST 4,807
  + 193; other-attack-only windows were excluded. No bidirectional or command-side
  feature was used.
- **INVALIDATED — CUSUM calibration output:** TRAIN-normal 99th-percentile thresholds were
  `33.922365` for function `0x03` and `36.261586` for `0x10`, with frozen allowance
  `0.5`. These thresholds and all baselines were fit before held-out TEST scoring.
- **INVALIDATED — TEST metrics generated but not accepted:**

  | detector | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---|---:|---:|---:|---:|---:|---:|---:|---:|
  | INVALID — DO NOT CITE: Detector A per-type CUSUM | 0.028037 | 0.015544 | 0.020000 | 0.021635 | 4,703 | 104 | 190 | 3 |
  | INVALID — DO NOT CITE: Detector B cadence Random Forest | 0.716216 | 0.274611 | 0.397004 | 0.004369 | 4,786 | 21 | 140 | 53 |

- **INVALIDATED — contextual table (EXP-0007 rows are not findings):**

  | experiment / detector | observation and DoS cohort | precision | recall / flag rate | F1 | FPR |
  |---|---|---:|---:|---:|---:|
  | EXP-0004 combined IF+rule | egress-only; 136 **dominant-DoS** category windows | not derivable | 0.000000 | not derivable | 0.007489 detector-wide Normal FPR |
  | EXP-0005b RF — **out of scope** | bidirectional; 193 DoS-containing vs 4,931 Normal | 0.630252 | 0.388601 | 0.480769 | 0.008923 |
  | EXP-0007 Detector A — **INVALID, DO NOT CITE** | egress-only; 193 DoS-containing vs 4,807 Normal | 0.028037 | 0.015544 | 0.020000 | 0.021635 |
  | EXP-0007 Detector B — **INVALID, DO NOT CITE** | egress-only; 193 DoS-containing vs 4,807 Normal | 0.716216 | 0.274611 | 0.397004 | 0.004369 |

- **INVALIDATED — review finding:** the audit counted full-capture Normal response
  shapes while claiming TEST was unopened, and its TRAIN support count included attack
  frames rather than requiring TRAIN-normal frames exactly as pre-registered. In
  addition, CUSUM calibration reset on attack-labelled TRAIN windows while scoring
  replay did not, so the calibration and scoring state processes differed. These are
  method-integrity defects, not disappointing-performance tuning opportunities. The
  observed 3/193 and 53/193 values are therefore invalid and support no detector claim.
  Correcting and rescoring would require a new pre-registration/experiment ID because
  TEST has already been viewed.
- **VALIDATED — limitations/no tuning:** function code is an egress-response proxy for
  an unseen request type, and source is dataset grouping metadata rather than a model
  input. The attack is not established as a classic volumetric flood. No type, feature,
  baseline, CUSUM constant/threshold, RF setting, or probability threshold was changed
  after TEST. Machine-readable output is local at
  `data/experiments/exp0007_cadence.json` under the ignored `data/` tree.

---

### EXP-0008 · Corrected TRAIN-discovered egress cadence DoS experiment — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before any EXP-0008 real-data type
> discovery, support/overlap audit, baseline fit, CUSUM calibration, supervised fit,
> validation output, or TEST scoring. EXP-0007 is invalidated and retained unchanged as
> an audit trail; none of its outputs or metrics is an EXP-0008 input, tuning target, or
> performance reference.

- **PLANNED — background and four explicit corrections:** EXP-0007 was withdrawn because
  (1) its response-shape audit included TEST Normal rows, (2) its 1,000-frame gate
  counted all TRAIN frames rather than TRAIN-normal frames, (3) its baselines grouped
  raw function codes while scoring required exact parser-certain shapes, and (4) its
  calibration and inference replays used different CUSUM state processes. EXP-0008
  corrects these respectively by (1) discovering the immutable type map from TRAIN
  pure-Normal rows only, (2) counting canonically mapped TRAIN-normal frames exactly,
  (3) injecting one canonical mapping function into audit, baseline, calibration, and
  scoring, and (4) calling one label-independent CUSUM replay implementation for both
  calibration and inference.
- **PLANNED — hard observation boundary and dataset:** use only records with
  `destination == 1` from the verified `data/raw/gas_pipeline_raw.txt`, sha256
  `ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3`,
  274,628 source rows. No `destination == 3` row or bidirectional feature is permitted.
  Source identity is audit/grouping metadata only and is excluded from model inputs.
  This is the primary in-scope unidirectional DoS attempt.
- **PLANNED — windows, split, and cohort:** form absolute five-second egress windows,
  retaining windows with at least two egress frames; split ordered windows contiguously
  60/20/20 with one discarded window at each side of both boundaries. Never re-split
  after cohort filtering. Positive windows contain at least one
  `categorized_attack == 6` egress frame; negative windows are exactly pure-Normal
  (`categories == {0}`); other-attack-only windows are excluded from binary fitting and
  metrics. TEST is scored once only after explicit sign-off.
- **PLANNED — mandatory rule (a), TRAIN-only discovery:** derive candidate shapes only
  from source-3, egress, TRAIN pure-Normal frames using the egress-visible tuple
  `(function_code, is_request, frame_len_bytes, byte_count, length_anomaly)`. Freeze an
  immutable exact-shape-to-type map before examining VALIDATION. **Code enforcement:**
  the discovery API accepts a TRAIN-only partition object, not full-capture,
  VALIDATION, or TEST records.
- **PLANNED — mandatory rule (b), held-out blindness:** any pre-TEST check needing data
  beyond TRAIN is limited to the fixed VALIDATION partition; VALIDATION may establish
  the predeclared class-overlap gate but may not change discovered types, constants,
  features, or models. TEST values and labels are not materialized by preparation.
  **Code enforcement:** pre-TEST artifact builders accept only explicit TRAIN and
  VALIDATION records, while TEST scoring is a separate guarded API/CLI action.
- **PLANNED — mandatory rule (c), exact sufficiency population:** proceed only if exactly
  two parser-certain response types are discovered and each has at least 1,000
  **TRAIN-normal canonically mapped frames**, 200 eligible TRAIN-normal same-type IATs,
  and 100 TRAIN-normal windows. **Code enforcement:** the support audit first restricts
  to TRAIN windows whose complete category set is `{0}`, then counts only frames
  accepted by the canonical mapper; all-TRAIN frame counts are never the gate input.
- **PLANNED — mandatory rule (d), one canonical assignment:** one function maps a frame
  through the immutable TRAIN-discovered exact-shape map after enforcing source 3 and
  `destination == 1`. The same callable object is passed to the type-sufficiency audit,
  TRAIN-normal baseline builder, CUSUM calibration replay, and final feature/scoring
  replay. **Code enforcement:** all four stage APIs expose the mapper dependency and
  tests assert object identity plus observed calls; no stage groups raw function codes.
- **PLANNED — mandatory rule (e), one CUSUM state process:** use one one-sided per-type
  replay implementation for calibration and inference:
  `S_t = max(0, S_(t-1) + z_positive - 0.5)`, where
  `z_positive = max(0, IAT - expected_IAT) / max(std_IAT, 1e-6,
  0.01 * expected_IAT)`. State resets only at replay/block start, thereby separating
  splits/guards; labels never reset runtime state, and threshold crossings are reported
  without changing the trajectory. **Code enforcement:** calibration and scoring both
  call the same replay function; calibration only derives quantiles from its output.
- **PLANNED — audit/stop gate:** both frozen types must overlap pure-Normal and
  DoS-containing windows in TRAIN and VALIDATION. Each type's eligible TRAIN-normal IAT
  CV must be below the pooled eligible TRAIN-normal CV, and the IAT-count-weighted type
  CV must be at most `0.80 ×` pooled CV. The pooled population uses the same canonical
  mapped frames. If any discovery, support, overlap, or tightening condition fails,
  record `STOPPED — AUDIT GATE` and do not fit or TEST-score either detector.
- **PLANNED — cadence baseline and features:** fit per-type expected IAT mean, median,
  population standard deviation, CV, and scale from canonically mapped TRAIN-normal
  events only. IAT pairing never crosses a guard, split, or non-pure-Normal baseline
  interval. Freeze the EXP-0007 feature *definitions* as a design reference only:
  per-type event/IAT counts, IAT mean/std/max, signed and positive deviation summaries,
  positive-z mean/max, missed-cycle sum/count, CUSUM end/max/alarm count, plus aggregate
  event/missed-cycle/alarm/max/active-type values. EXP-0007 fitted values and outputs are
  forbidden. Labels, source/destination, timestamps, and bucket IDs are not features.
- **PLANNED — Detector A:** calibrate each type's threshold as the 99th percentile
  (`numpy.quantile(..., method="higher")`) of pure-Normal TRAIN window CUSUM maxima,
  bounded below by `0.5`. Replay the complete chronological TRAIN block with the same
  inference state process; labels select calibration maxima after replay but do not
  alter state. Alert a scored window if any type crosses its frozen threshold.
- **PLANNED — Detector B:** train `sklearn.ensemble.RandomForestClassifier` on only the
  TRAIN DoS-containing/pure-Normal cohort and frozen cadence matrix, with
  `n_estimators=300`, `class_weight="balanced"`, `random_state=0`, `n_jobs=-1`, and
  probability threshold `0.5`. Record a deterministic semantic fingerprint of
  hyperparameters and learned tree arrays before TEST. VALIDATION is descriptive and
  cannot tune this detector.
- **PLANNED — proof tests before any frozen TEST run:** synthetic tests must (1) mutate
  only TEST rows, including function/shape/label values, and prove that the discovered
  map, audit, baselines, thresholds, feature schema, RF hyperparameters, and learned
  forest fingerprint are unchanged; (2) prove the 1,000-frame population is exactly
  TRAIN-normal rather than all TRAIN; and (3) prove all four mapping stages use the same
  canonical function object. Additional tests cover egress rejection, shape certainty,
  guards, baseline pairing, CUSUM arithmetic/state identity, calibration quantile,
  forbidden metadata, RF configuration, and the explicit TEST guard.
- **PLANNED — fixed decision/reporting rule:** the pre-TEST audit either passes every
  fixed gate and EXP-0008 stops for sign-off, or stops without TEST. There is **no
  detector-performance pass/fail gate**. After explicit `proceed`, report one frozen
  TEST pass exactly as observed—precision, recall, F1, FPR, and TN/FP/FN/TP for both
  detectors, including weak or null results. No feature, type, state rule, threshold,
  hyperparameter, or probability cutoff may change after TEST; no second frozen pass is
  authorized under EXP-0008.
- **PLANNED — comparison and limitations:** the final table will include EXP-0004 only
  as an egress-only but different dominant-DoS cohort and EXP-0005b only as explicitly
  **out-of-scope bidirectional** context. EXP-0007 numbers will not be reproduced or
  cited. A response type remains an egress-visible proxy for an unseen query, `source`
  is dataset grouping metadata, this labelled attack is not established as a classic
  volumetric flood, and one testbed cannot validate universal DoS detection.
- **PLANNED — isolated files/output:** add only `ml/exp0008_cadence_features.py`,
  `ml/exp0008_cadence.py`, dedicated EXP-0008 tests, and ignored local pre-TEST/final
  JSON artifacts. Do not alter EXP-0007 files, Layer A, `app.py`, EXP-0004/0005/0005b
  files, or the existing EXP-0006 block above. Run and report exact full-suite counts;
  show the complete diff before any commit, and do not commit or push without explicit
  approval.

#### EXP-0008 outcome — one frozen TEST pass after explicit sign-off

- **IMPLEMENTED — isolated corrected path:** `ml/exp0008_cadence_features.py` keeps
  TEST records out of every pre-TEST artifact API, discovers an immutable response-shape
  map from TRAIN pure-Normal rows, and routes audit, baseline, calibration, and scoring
  through one canonical mapper. Calibration and inference both call the same
  label-independent CUSUM replay. `ml/exp0008_cadence.py` freezes and fingerprints the
  TRAIN-fitted Random Forest, defaults to pre-TEST preparation, and requires the exact
  confirmation token for TEST scoring. EXP-0007 code and artifacts were not reused.
- **TESTED — construction proofs before TEST:** the first dedicated synthetic run had
  one incorrect hand-calculated test expectation (`3.0` rather than the frozen
  recurrence's correct `2.5`); only that test expectation changed. The rerun passed
  **9/9 in 2.91 s**. Tests prove TEST-only value/shape/label mutations leave the type
  map, audit, baseline, CUSUM thresholds, feature schema, RF parameters, and learned
  forest fingerprint unchanged; prove support means TRAIN-normal canonical frames;
  and prove all four stages share/call the same mapper and both CUSUM stages share the
  same replay. The full pre-TEST suite passed **53/53 in 32.14 s** with no reported
  skips. The prior 44-test set was reconstructed after editing and passed **44/44 in
  31.59 s** because the literal before-edit command was blocked before execution; this
  is not represented as a contemporaneous baseline.
- **VALIDATED — TRAIN-only discovery and audit:** the immutable map contains exactly
  `0x03 -> (3,0,23,18,0)` and `0x10 -> (16,0,8,-1,0)`, discovered only from source-3
  egress TRAIN pure-Normal frames. Exact TRAIN-normal frame support was 21,384 and
  21,387; eligible TRAIN-normal IATs were 20,803 and 20,816; TRAIN-normal windows were
  14,951 and 14,941. Both types overlapped DoS-containing windows in TRAIN (232/359)
  and VALIDATION (98/203), with VALIDATION pure-Normal windows 4,852/4,848. Weighted
  per-type CV `0.044673` was 0.671052 of pooled CV `0.066571`, passing the fixed gate.
- **VALIDATED — frozen pre-TEST artifacts:** thresholds from the identical inference
  state process were `396318.476154` (`0x03`) and `202709.185269` (`0x10`). Their
  magnitude is reported without adjustment: unlike the invalidated method, state was
  not reset from labels or alarms. The RF semantic fingerprint before TEST was
  `43fa2ef7fd3112eaf572f6b38a3f64590df424d249140fea454b2534074d3833`.
  Descriptive VALIDATION results were CUSUM precision/recall/F1/FPR all `0`, and RF
  precision `0.514706`, recall `0.517241`, F1 `0.515971`, FPR `0.020404`; they did not
  change the frozen design.
- **VALIDATED — one authorized TEST execution:** after explicit user sign-off, the
  guarded scorer was invoked once. It scored 5,000 cohort windows: 4,807 pure-Normal
  and 193 DoS-containing; 4,347 other-attack-only TEST windows were excluded. The
  complete UTF-8 result was persisted to ignored local
  `data/experiments/exp0008_cadence.json`. No second TEST invocation or post-result
  tuning was performed.

  | detector | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---|---:|---:|---:|---:|---:|---:|---:|---:|
  | Detector A — canonical per-type CUSUM | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 4,807 | 0 | 193 | 0 |
  | Detector B — cadence Random Forest | 0.634146 | 0.269430 | 0.378182 | 0.006241 | 4,777 | 30 | 141 | 52 |

- **VALIDATED — required contextual comparison:** cohorts and observation boundaries
  differ, so the historical rows are context rather than like-for-like rankings.

  | experiment / detector | observation and DoS cohort | precision | recall / flag rate | F1 | FPR |
  |---|---|---:|---:|---:|---:|
  | EXP-0004 combined IF+rule — context | egress-only; 136 **dominant-DoS** category windows | not derivable | 0.000000 | not derivable | 0.007489 detector-wide Normal FPR |
  | EXP-0005b RF — **OUT OF SCOPE / BIDIRECTIONAL** | pre-diode bidirectional; 193 DoS-containing vs 4,931 pure-Normal | 0.630252 | 0.388601 | 0.480769 | 0.008923 |
  | EXP-0008 Detector A | egress-only; 193 DoS-containing vs 4,807 pure-Normal | 0.000000 | 0.000000 | 0.000000 | 0.000000 |
  | EXP-0008 Detector B | egress-only; 193 DoS-containing vs 4,807 pure-Normal | 0.634146 | 0.269430 | 0.378182 | 0.006241 |

- **VALIDATED — interpretation/limitations:** under this frozen method, Detector A made
  no TEST alerts and detected no DoS windows. Detector B detected 52/193 DoS-containing
  windows while producing 30/4,807 Normal false positives. This is held-out evidence
  only for this labelled testbed and split, not universal DoS capability. Response type
  remains an egress-visible proxy for an unseen query; source is non-feature dataset
  grouping metadata; and the labelled attack is not established as a classic
  volumetric flood. EXP-0007's withdrawn outputs are not evidence and were not used for
  tuning or comparison.

---

### EXP-0009 · Independent egress-only Detector B improvements — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before any EXP-0009 payload audit,
> transformation, resampling, model fit, VALIDATION metric, threshold sweep, or TEST
> access. All five sub-experiments and their selection rules are fixed below. Every
> result will be reported, including regressions and stopped variants.

- **PLANNED — common scope and held-out discipline:** retain EXP-0008's verified
  TXT/ARFF inputs and exact alignment, egress-only `destination == 1` / ARFF
  `command response == 0`, 46,736 eligible five-second windows, guarded chronological
  TRAIN 28,040 / VALIDATION 9,345 / TEST 9,347 split, DoS-containing versus pure-Normal
  cohort, and other-attack-only exclusion. Fit/derive on TRAIN and compare/select on
  VALIDATION only. No EXP-0009 TEST payload value, feature, label, prediction, or metric
  may be materialized until explicit sign-off; final TEST scoring is a separately
  guarded path and is permitted once only.
- **PLANNED — inherited EXP-0008 integrity controls:** reuse, without modification,
  EXP-0008's TRAIN-only immutable response-shape discovery, canonical frame-to-type
  mapper, per-type baselines, and original cadence features. Every EXP-0009 type-aware
  stage receives that same canonical mapper object. VALIDATION and TEST cannot define a
  type or baseline. Synthetic TEST-mutation and mapper-identity tests must pass before
  the real validation study. EXP-0007's invalidated method and outputs are forbidden as
  inputs or tuning references.
- **PLANNED — 0009a, response pressure only:** provenance records pressure attacks as
  pressure readings sent back to the master; schema field 14 `pressure measurement` is
  separate from command-payload fields 4–13; `command response == 0` is confirmed
  response/egress. The user explicitly authorized using this field through exact
  TXT↔ARFF row alignment, with the limitation that the current TXT parser does not
  independently decode its numeric register representation. Use no command-side row or
  setpoint/gain/reset-rate/deadband/cycle-time/rate/system-mode/control-scheme/pump/
  solenoid/CRC field. On TRAIN, audit Normal/DoS presence, missingness, finite/unique
  values, quantiles/ranges, value overlap, and whether presence or value perfectly
  separates labels. **Decision rule:** if provenance/alignment fails, there are no
  usable TRAIN-normal measurements, or presence/value is perfectly separable or
  otherwise an obvious lab-label proxy, report `STOPPED — PAYLOAD GATE`, substitute
  nothing, and exclude 0009a from selection. Otherwise freeze TRAIN-normal per-type
  baseline/imputation and add per-type window raw last/mean/min/max, deviation mean/
  maximum absolute deviation, and `(last-first)/elapsed-time` rate of change. Missing
  windows receive the TRAIN-normal baseline; no presence/missingness indicator is an
  input. Train the exact EXP-0008 RF on cadence plus pressure and report VALIDATION at
  threshold 0.5, independently of all other variants.
- **PLANNED — 0009b, TRAIN-only standard SMOTE:** apply
  `imblearn.over_sampling.SMOTE(sampling_strategy="auto", k_neighbors=5,
  random_state=0)` only to the original EXP-0008 cadence TRAIN cohort, then fit a
  300-tree RF with seed 0, `n_jobs=-1`, and `class_weight=None`; VALIDATION remains
  untouched and is scored at 0.5. Standard SMOTE is selected rather than Borderline-
  SMOTE as the simplest isolated resampling ablation without an extra border rule.
  **Decision rule:** report its fixed-threshold VALIDATION metrics exactly; it is
  eligible for 0009e even if worse than EXP-0008.
- **PLANNED — 0009c, XGBoost model swap:** use original cadence features and original
  unresampled TRAIN cohort with `XGBClassifier(objective="binary:logistic",
  n_estimators=300, random_state=0, n_jobs=-1, eval_metric="logloss",
  scale_pos_weight=n_train_normal/n_train_dos)`; record all installed-version defaults.
  XGBoost is selected because it is already a project dependency. Score unchanged
  VALIDATION at 0.5. **Decision rule:** report exactly and keep eligible for 0009e
  regardless of improvement or regression.
- **PLANNED — 0009d, per-response-type RFs:** train one RF per frozen type, each using
  only that type's 14 `func_XX_*` cadence features and only TRAIN cohort windows where
  the type is active. At evaluation an inactive type contributes probability zero;
  combine active type probabilities by maximum, equivalent to OR at threshold 0.5.
  Report each model on its active-type VALIDATION cohort and combined metrics on the
  unchanged overall EXP-0008 VALIDATION cohort. **Decision rule:** 0009e ranks the
  combined row, not either restricted per-type row, and all three rows are reported.
- **PLANNED — 0009e, VALIDATION-only threshold selection:** rank eligible 0009a–d by
  threshold-0.5 VALIDATION F1; ties use recall, then precision, then fixed a→d order.
  Sweep that one winner at thresholds 0.10 through 0.90 inclusive in 0.05 steps and
  report all 17 precision/recall/F1/FPR/confusion rows. **Decision rule:** recommend the
  threshold with maximum recall among points with precision at least 0.50; ties use
  higher F1, then precision, then the higher threshold. If no point reaches 0.50
  precision, recommend maximum F1 with ties by recall, precision, then higher threshold.
  This prioritizes missed-DoS reduction while predeclaring a minimum alert precision.
- **PLANNED — final configuration and stop rule:** the proposed final configuration is
  only 0009e's selected **single** variant plus its recommended threshold—no post-hoc
  fusion of improvements. A multi-variant combination requires a new pre-registration.
  After reporting 0009a–e on VALIDATION, mark TEST `NOT RUN` and stop. Following explicit
  `proceed`, score this frozen configuration on TEST once, report precision/recall/F1/
  FPR and confusion counts, and never tune or rerun after viewing it.
- **PLANNED — isolated outputs/tests:** add new `ml/exp0009_payload.py`,
  `ml/exp0009_variants.py`, and dedicated tests; add `imbalanced-learn` to dependencies
  only if absent. Write ignored local `exp0009_validation.json` and, only after sign-off,
  `exp0009_final.json`. Do not edit Layer A, `app.py`, dashboard components, or any
  EXP-0004/0005/0005b/0008 implementation/test file. Do not integrate a variant into the
  main pipeline in this experiment. Before changes, the complete suite passed **53/53
  in 33.59 s** with no reported skip.

#### EXP-0009 TRAIN/VALIDATION outcome — 2026-09-09

- **TESTED — integrity checks:** dedicated EXP-0009 tests passed **11/11 in 2.47 s**.
  The first dedicated run exposed three synthetic-fixture mistakes (3 failed, 8 passed),
  which were corrected without changing the real-data method. The complete pre-validation
  suite then passed **64/64 in 32.16 s** (up from 53/53; +11 tests), with no reported
  skip. Synthetic tests cover pre-TEST ARFF alignment, command-side exclusion,
  TRAIN-only baselines/imputation, hand-calculated pressure summaries, payload gate,
  SMOTE boundary/settings, XGBoost ratio/settings, per-type schemas and max combiner,
  all 17 threshold/tie rules, TEST-only mutation blindness, shared mapper injection, and
  the frozen TEST guard.
- **IMPLEMENTED — first validation attempt:** the first runner invocation stopped before
  any model fit or VALIDATION score because pressure passed the initial aggregate gate but
  had no TRAIN-normal pressure baseline for canonical type `0x10`. The gate omitted this
  prerequisite even though the pre-registration required per-type baseline/imputation.
  The audit was corrected to check each type explicitly; dedicated tests passed **11/11
  in 2.40 s**, and the same pre-registered study was resumed. No substitute payload,
  altered model rule, threshold change, or TEST access occurred.
- **VALIDATED — scope/environment:** egress only (`destination == 1`), 137,013 frames,
  46,736 emitted windows, guarded TRAIN 28,040 / VALIDATION 9,345 / unopened TEST 9,347.
  VALIDATION binary cohort: 4,852 pure-Normal and 203 DoS-containing windows. Python
  3.12.10; NumPy 2.5.3; scikit-learn 1.9.0; imbalanced-learn 0.14.2; XGBoost 3.4.1.
- **VALIDATED — 0009a STOPPED — PAYLOAD GATE:** TXT sha256 `ce2d69e3…93e3` and ARFF
  sha256 `970a7bcd…af459` passed; only aligned ARFF column 14 `pressure measurement` on
  `command response == 0` / TXT `destination == 1` rows was parsed. No forbidden
  command-payload field was used. TRAIN pressure-window presence was Normal 14,951/
  14,951 and DoS 232/359. Finite frame values: Normal 21,384 (2,387 unique, range
  0.482759–38.7471), DoS 326 (132 unique, range 0.551724–18.7701), with 129 exact
  values shared; neither presence nor value range perfectly separated the classes.
  However, canonical `0x10` had **no TRAIN-normal pressure measurement**, so its required
  per-type baseline/imputer could not be fitted. Per the frozen rule, 0009a was stopped,
  no feature substitution was made, and it was excluded from 0009e. The candidate
  pressure names remain the pre-registered seven summaries per type, but no 0009a model
  or VALIDATION prediction exists.
- **VALIDATED — a–d at threshold 0.5:**

  | variant | status | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---|---|---:|---:|---:|---:|---:|---:|---:|---:|
  | 0009a pressure + RF | STOPPED — PAYLOAD GATE | — | — | — | — | — | — | — | — |
  | 0009b TRAIN-only SMOTE + RF | VALIDATED — VALIDATION ONLY | 0.785185 | 0.522167 | 0.627219 | 0.005977 | 4,823 | 29 | 97 | 106 |
  | 0009c XGBoost | VALIDATED — VALIDATION ONLY | 0.368056 | 0.522167 | 0.431772 | 0.037510 | 4,670 | 182 | 97 | 106 |
  | 0009d per-type RF max/OR | VALIDATED — VALIDATION ONLY | 0 | 0 | 0 | 0.029678 | 4,708 | 144 | 203 | 0 |

  For context only, EXP-0008 Detector B on the same VALIDATION cohort at 0.5 was
  precision 0.514706, recall 0.517241, F1 0.515971, FPR 0.020404, TN/FP/FN/TP
  4,753/99/98/105. This context did not alter the pre-registered ranking.
- **VALIDATED — 0009d active-type rows:** `0x03` used only its 14 features on 15,183
  active TRAIN and 4,950 active VALIDATION rows: precision/recall/F1 0/0/0, FPR
  0.022465, TN/FP/FN/TP 4,743/109/98/0. `0x10` used only its 14 features on 15,300
  active TRAIN and 5,051 active VALIDATION rows: precision/recall/F1 0/0/0, FPR
  0.007219, TN/FP/FN/TP 4,813/35/203/0. Their frozen maximum-probability combination
  produced the overall 0009d row above. This variant regressed and is retained honestly.
- **VALIDATED — 0009e full VALIDATION sweep of selected 0009b:** 0009b won a–d by
  fixed-threshold F1. SMOTE was TRAIN-only (`auto`, k=5, seed 0), producing 14,951
  Normal and 14,951 synthetic-augmented DoS-class rows; the RF used 300 trees, seed 0,
  `n_jobs=-1`, `class_weight=None`. Semantic model fingerprint:
  `85bb15e11859a074871a99755c844094dae0621e249acb38a14a7cb4c9a8bcc6`.

  | threshold | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---:|---:|---:|---:|---:|---:|---:|---:|---:|
  | 0.10 | 0.075625 | 0.551724 | 0.133017 | 0.282152 | 3,483 | 1,369 | 91 | 112 |
  | 0.15 | 0.102927 | 0.536946 | 0.172742 | 0.195796 | 3,902 | 950 | 94 | 109 |
  | 0.20 | 0.145578 | 0.527094 | 0.228145 | 0.129431 | 4,224 | 628 | 96 | 107 |
  | 0.25 | 0.192029 | 0.522167 | 0.280795 | 0.091921 | 4,406 | 446 | 97 | 106 |
  | 0.30 | 0.263027 | 0.522167 | 0.349835 | 0.061212 | 4,555 | 297 | 97 | 106 |
  | 0.35 | 0.347541 | 0.522167 | 0.417323 | 0.041014 | 4,653 | 199 | 97 | 106 |
  | 0.40 | 0.493023 | 0.522167 | 0.507177 | 0.022465 | 4,743 | 109 | 97 | 106 |
  | 0.45 | 0.630952 | 0.522167 | 0.571429 | 0.012778 | 4,790 | 62 | 97 | 106 |
  | 0.50 | 0.785185 | 0.522167 | 0.627219 | 0.005977 | 4,823 | 29 | 97 | 106 |
  | 0.55 | 0.883333 | 0.522167 | 0.656347 | 0.002885 | 4,838 | 14 | 97 | 106 |
  | **0.60** | **0.929825** | **0.522167** | **0.668770** | **0.001649** | **4,844** | **8** | **97** | **106** |
  | 0.65 | 0.963303 | 0.517241 | 0.673077 | 0.000824 | 4,848 | 4 | 98 | 105 |
  | 0.70 | 0.981308 | 0.517241 | 0.677419 | 0.000412 | 4,850 | 2 | 98 | 105 |
  | 0.75 | 0.990566 | 0.517241 | 0.679612 | 0.000206 | 4,851 | 1 | 98 | 105 |
  | 0.80 | 0.990566 | 0.517241 | 0.679612 | 0.000206 | 4,851 | 1 | 98 | 105 |
  | 0.85 | 0.989247 | 0.453202 | 0.621622 | 0.000206 | 4,851 | 1 | 111 | 92 |
  | 0.90 | 1.000000 | 0.394089 | 0.565371 | 0 | 4,852 | 0 | 123 | 80 |

- **VALIDATED — frozen recommendation:** by the predeclared “maximum recall subject to
  precision ≥0.50” rule, threshold **0.60** is selected: it ties the best feasible recall
  0.522167 across 0.45–0.60, then has the highest F1. The proposed final configuration is
  **only 0009b TRAIN-only SMOTE + RF at threshold 0.60**. No variant fusion is allowed.
- **LIMITATIONS:** pressure provenance relies on exact ARFF alignment and is not decoded
  independently by the TXT parser; response type proxies an unseen query; the labelled
  attack is not established as a classic volumetric flood; variant and threshold
  selection reuse VALIDATION; and one labelled testbed cannot establish universal DoS
  detectability.
- **TEST NOT RUN:** no EXP-0009 TEST cohort, payload value, feature, prediction, or metric
  was materialized. Work stops here pending explicit `proceed` for exactly one frozen
  TEST score of 0009b at threshold 0.60. The final pre-TEST full suite passed **64/64
  in 32.24 s**, with no reported skip.

---

### EXP-0012b · Corrected manifest-backed causal block CV — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded after invalidating EXP-0012 and before fitting
> or viewing any corrected CV metric. Frozen TEST access and scoring remain forbidden.

- **PLANNED — correction:** replace full-capture-derived cut positions with exact ordered
  TRAIN 28,040 and VALIDATION 9,345 bucket memberships from tracked split manifest
  `verified-egress-5s-exp0008-pretest-v1`, membership SHA-256
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`.
  Pre-TEST parsing must stop after its final VALIDATION bucket and must not read TEST-tail
  records. Missing/ineligible manifest buckets fail closed.
- **PLANNED — provenance limit:** the manifest freezes the memberships previously recorded
  by EXP-0008 prospectively. Because EXP-0008 originally computed them from full-capture
  eligibility, this does not rehabilitate EXP-0008/0009/0011 or prove that the historical
  source boundary was selected independently of TEST. It eliminates future dependence on
  TEST-tail content while preserving the historical memberships for comparability.
- **PLANNED — regression gate:** mutate only synthetic TEST-tail destination/eligibility
  and labels, then require byte-identical ordered TRAIN and VALIDATION bucket-ID sets,
  identical pre-TEST records/artifacts, and proof that iteration stops before TEST.
- **PLANNED — frozen comparison:** otherwise retain EXP-0012 exactly: configurations X/Y,
  33 versus 49 features, five past-only expanding folds with guards, fold-local TRAIN-only
  preprocessing and Borderline-SMOTE, 300-tree RF, threshold 0.50, aggregation, precision
  floor, winner rule, and limitations. Write `exp0012b_block_cv.json`; never overwrite the
  invalid original result. **TEST NOT RUN.**
- **TESTED — boundary correction:** the manifest loader verifies its fixed ID and membership
  digest, ordered unique/disjoint blocks, and TRAIN/VALIDATION guard. The new regression
  mutates only synthetic TEST-tail destination/eligibility and labels, then proves ordered
  TRAIN and VALIDATION bucket tuples and their byte serializations are identical. A second
  generator test raises if the parser attempts to iterate beyond final VALIDATION. The
  pre-fit affected suite passed **17/17** and the full suite passed **92/92 in 32.64 s**.
- **VALIDATED — corrected fold populations:** after causal prefix exclusion, validation
  Normal/DoS counts were fold 1 `3336/88`, fold 2 `4735/86`, fold 3 `4326/87`, fold 4
  `2080/87`, and fold 5 `2516/87`. No fold was thin relative to the others; each retained
  86–88 positives. The corrected manifest preserves the prior pre-TEST memberships, so
  these counts match the invalid run by design, not because its integrity claim survived.
- **VALIDATED — corrected per-fold X:** precision/recall/F1/FPR and TN/FP/FN/TP were fold 1
  `0.058333/0.556818/0.105603/0.237110`, `2545/791/39/49`; fold 2
  `1.000000/0.232558/0.377358/0.000000`, `4735/0/66/20`; fold 3
  `0.928571/0.448276/0.604651/0.000693`, `4323/3/48/39`; fold 4
  `0.730769/0.218391/0.336283/0.003365`, `2073/7/68/19`; fold 5
  `0.666667/0.735632/0.699454/0.012719`, `2484/32/23/64`.
- **VALIDATED — corrected per-fold Y:** fold 1
  `0.109677/0.386364/0.170854/0.082734`, `3060/276/54/34`; fold 2
  `1.000000/0.232558/0.377358/0.000000`, `4735/0/66/20`; fold 3
  `1.000000/0.448276/0.619048/0.000000`, `4326/0/48/39`; fold 4
  `1.000000/0.218391/0.358491/0.000000`, `2080/0/68/19`; fold 5
  `1.000000/0.735632/0.847682/0.000000`, `2516/0/23/64`.
- **VALIDATED — corrected means ± population SD:** X precision/recall/F1/FPR was
  `0.676868±0.332675 / 0.438335±0.196592 / 0.424670±0.209644 /
  0.050778±0.093277`; Y was `0.821935±0.356129 / 0.404244±0.187667 /
  0.474687±0.234629 / 0.016547±0.033094`. Only Y meets mean precision `≥0.80`, so it
  mechanically wins again, but it lowers mean recall by `0.034091`; its gain is F1 and
  false-positive suppression, and the very large fold variance remains. X's mean recall
  is `0.083832` below the withdrawn EXP-0011b single-split `0.522167`, which remains
  evidence that one validation block was optimistic/unstable, not a valid benchmark.
- **STOP:** the corrected runner read only through the final manifest VALIDATION bucket;
  TEST count is deliberately `null`. No TEST row, label, feature, prediction, or metric
  was materialized or scored. Y remains a provisional, unstable pre-TEST winner and no
  TEST authorization is implied. Final verification after the manifest-integrity test was
  added passed **93/93 in 32.32 s**; `git diff --check` passed.

---

### EXP-0012 · INVALIDATED — Causal lag/trend features with block-respecting CV — 2026-09-09

> **INVALIDATED.** `partition_pretest_inputs()` enumerated full-capture eligible egress
> windows and derived its 60/20/20 indices from their total. Changing only nominal
> TEST-tail records' destination/eligibility changed both TRAIN and VALIDATION bucket IDs.
> TEST was not scored, but its tail was materialized during boundary construction and
> could alter every fold. All X/Y metrics and the Y recommendation below are withdrawn,
> retained only as an audit trail, and must not be cited or used to authorize TEST.
>
> **SHARED IMPACT.** EXP-0008, EXP-0009, and EXP-0011 used the same pre-TEST path;
> EXP-0009 payload alignment called it independently, and the already-run EXP-0008 and
> EXP-0011b TEST scorers refit through it. Their historical validation claims are not
> constructionally TEST-blind. Already-viewed TEST results remain audit evidence only and
> are not rerun. The corrected prospective manifest cannot retroactively cure those runs.

> **PRE-REGISTRATION — PLANNED.** Recorded before implementing EXP-0012 features/CV,
> fitting any EXP-0012 model, or viewing any EXP-0012 metric. Frozen TEST is excluded.

- **PLANNED — purpose and boundary:** repair the single-VALIDATION selection methodology
  whose `0.522167` EXP-0011b recall did not generalize to its one frozen TEST score
  (`0.269430`). Use only verified egress rows (`destination == 1`) and the existing
  five-second eligible TRAIN 28,040 + VALIDATION 9,345 windows. Preserve the
  DoS-containing versus pure-Normal cohort and exclude other-attack-only windows. No TEST
  row, label, feature, prediction, or metric may be materialized; no TEST CLI exists.
- **PLANNED — model scope:** LSTM/GRU is explicitly out of scope. The total available
  DoS-window pool is roughly 600–900 before splitting, at or below the user-supplied
  literature-informed floor of roughly 320–800 positives for rare-event deep learning,
  and the observed split variance makes additional sequence-model capacity unjustified.
  Add compact causal history summaries to the established tabular RF instead.
- **PLANNED — configurations:** X reproduces EXP-0011b's original 33 cadence columns. Y
  uses those 33 plus, separately for response types `0x03` and `0x10`, the exact prior
  five emitted windows' `deviation_mean` as lag 1–5, their least-squares slope, slope
  direction (`-1/0/+1`), and population variance: 16 new columns, 49 total. The current
  window and all future windows are forbidden. Source 3 remains grouping metadata, not a
  model input; no payload, pressure, availability, timestamp, bucket, or label is input.
- **PLANNED — sequence starts:** history resets for every independently constructed fold
  training or validation block. Exclude each block's first five windows rather than
  fabricating padding or exposing an availability flag. Record the exact exclusions and
  apply the same eligibility rows to X and Y so their comparison is paired.
- **PLANNED — five folds:** build six contiguous chronological segments from TRAIN+
  VALIDATION, selecting boundaries from sixths of the chronologically ordered eligible
  DoS positions to improve class balance without shuffling. Exclude one window on both
  sides of every boundary globally. Fold 1 trains on segment 1 and validates on segment
  2; folds 2–5 expand training through all earlier segments and validate on the next.
  All training precedes validation. Report every boundary/guard and actual total/cohort/
  Normal/DoS/other count; retain and disclose sparse folds rather than adjusting them.
- **PLANNED — fold-local leakage control:** in every fold, discover response types from
  fold-TRAIN pure-Normal egress only, and calculate cadence baselines/CUSUM thresholds
  from fold TRAIN only before constructing its train/validation windows. Do not reuse
  full-TRAIN learned preprocessing. Randomly shuffled stratified k-fold is forbidden
  because adjacent cadence windows and traffic regimes are temporally correlated.
- **PLANNED — fixed learner/evaluation:** inside each configuration/fold only, apply
  `BorderlineSMOTE(sampling_strategy="auto", k_neighbors=5, random_state=0)` to training
  rows only, retaining installed defaults `kind="borderline-1"` and `m_neighbors=10`.
  Fit RF `n_estimators=300`, `class_weight=None`, `random_state=0`, `n_jobs=-1`,
  `max_depth=None`, `min_samples_leaf=1`; score untouched validation at fixed threshold
  `0.50`. There is no threshold sweep. Report per-fold confusion counts and precision,
  recall, F1, FPR plus arithmetic mean, population variance, and standard deviation.
- **PLANNED — winner rule:** feasible means mean CV precision ≥`0.80`. Among feasible
  configurations maximize mean recall, then mean F1, mean precision, minimize mean FPR,
  then minimize recall variance; an exact tie retains X. If neither is feasible, maximize
  mean F1 with the same subsequent tie-breakers and explicitly disclose the failed floor.
  Recommend Y for a later one-shot TEST only if it strictly beats X. If X wins/ties,
  retain already-tested EXP-0011b and do not rerun it. Compare X's CV distribution with
  the old single-split VALIDATION result, and report instability or a negative lag result
  plainly.
- **PLANNED — implementation and stop:** create only `ml/exp0012_features.py`,
  `ml/exp0012_block_cv.py`, and their two dedicated test files; atomically write ignored
  `data/experiments/exp0012_block_cv.json`. Existing EXP-0008/0009/0011 files/results,
  Layer A, `app.py`, dashboard, requirements, and TEST artifacts stay untouched. Baseline
  suite: **81 passed in 39.98 s**. Run dedicated/full tests before CV, show real
  results and full diff, then stop before commit or push.

- **IMPLEMENTED — isolated causal/CV path:** added only the two EXP-0012 modules and two
  dedicated test files. Configuration Y adds 16 columns (five prior deviations, slope,
  direction, and variance for each of `0x03`/`0x10`) to X's 33. History is block-local;
  the first five windows of every independently built segment are excluded for both X/Y.
  Six positive-stratified contiguous segments produce five past-only expanding folds,
  with ten boundary windows globally excluded. Every fold independently discovers types,
  fits TRAIN-normal cadence baselines/CUSUM thresholds, resamples fold TRAIN only, and
  scores untouched validation at `0.50`. The runner imports no TEST materializer and has
  no TEST option, token, scorer, or result field beyond `test_materialized: false`.
- **VALIDATED — fold layout and counts:** segment window/Normal/DoS/other counts were
  `5205/2809/93/2303`, `6419/3337/92/2990`, `8963/4735/91/4137`,
  `7805/4326/92/3387`, `4380/2080/92/2208`, and `4603/2516/92/1995`.
  After each validation block's five-window causal prefix exclusion, fold binary cohorts
  were respectively Normal/DoS `3336/88`, `4735/86`, `4326/87`, `2080/87`, and
  `2516/87`. Thus every validation fold retained 86–88 DoS windows; no sparse-positive
  fold occurred. Expanding TRAIN cohort Normal/DoS counts were `2804/93`, `6140/181`,
  `10875/267`, `15201/354`, and `17281/441`, and Borderline-SMOTE balanced each fold to
  the corresponding Normal count.
- **VALIDATED — per-fold X metrics at threshold 0.50:** precision/recall/F1/FPR and
  TN/FP/FN/TP were: fold 1 `0.058333/0.556818/0.105603/0.237110`,
  `2545/791/39/49`; fold 2 `1.000000/0.232558/0.377358/0.000000`,
  `4735/0/66/20`; fold 3 `0.928571/0.448276/0.604651/0.000693`,
  `4323/3/48/39`; fold 4 `0.730769/0.218391/0.336283/0.003365`,
  `2073/7/68/19`; fold 5 `0.666667/0.735632/0.699454/0.012719`,
  `2484/32/23/64`.
- **VALIDATED — per-fold Y metrics at threshold 0.50:** fold 1
  `0.109677/0.386364/0.170854/0.082734`, `3060/276/54/34`; fold 2
  `1.000000/0.232558/0.377358/0.000000`, `4735/0/66/20`; fold 3
  `1.000000/0.448276/0.619048/0.000000`, `4326/0/48/39`; fold 4
  `1.000000/0.218391/0.358491/0.000000`, `2080/0/68/19`; fold 5
  `1.000000/0.735632/0.847682/0.000000`, `2516/0/23/64`.
- **VALIDATED — mean/variance/stability:** X mean precision/recall/F1/FPR was
  `0.676868/0.438335/0.424670/0.050778`; population variance was
  `0.110673/0.038648/0.043951/0.008701` and population standard deviation
  `0.332675/0.196592/0.209644/0.093277`. Y mean was
  `0.821935/0.404244/0.474687/0.016547`; variance
  `0.126828/0.035219/0.055051/0.001095` and standard deviation
  `0.356129/0.187667/0.234629/0.033094`. Both configurations are highly regime-sensitive,
  especially fold 1. Y reduces mean recall by `0.034091` versus X, but improves mean F1
  by `0.050017`, mean precision by `0.145067`, and mean FPR by `0.034231`.
- **VALIDATED — selection and interpretation:** only Y satisfies the preregistered mean
  precision floor (`0.821935 ≥ 0.80`); X does not (`0.676868`). Therefore Y is the formal
  winner and may proceed to one later explicitly authorized frozen TEST score. This is
  not a uniform lag-feature win: Y has lower mean recall, folds 2–5 have unchanged recall,
  and fold 1 loses 15 TP while removing 515 FP. Its advantage is primarily false-positive
  suppression and F1, not additional DoS detection. X's CV mean recall `0.438335` is below
  EXP-0011b's single-split `0.522167`, while its very large fold spread (`0.218391` to
  `0.735632`) supplies further evidence that one validation block was not a stable
  estimator. Neither CV mean predicts frozen TEST performance.
- **TESTED — verification/stop:** the pre-change baseline was **81 passed in 39.98 s**.
  One initial dedicated run had **1 failed, 8 passed** because a synthetic test stub lacked
  `CadenceBaseline` fields; the stub—not production logic—was corrected. Dedicated tests
  then passed **9/9**, and the pre-CV full suite passed **90/90 in 32.67 s**. EXP-0012 ran
  once and wrote strict JSON. **TEST NOT RUN.** No prior experiment, Layer A, `app.py`,
  requirements, or frozen result was changed; no commit or push performed.

---

### EXP-0011 · Validation-only follow-up to EXP-0009 — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before the EXP-0011 baseline test run,
> protocol/payload diagnostic, resampling, model fitting, hyperparameter comparison,
> ensemble construction, or VALIDATION scoring. Frozen TEST remains unopened and no
> EXP-0011 TEST path is authorized or implemented.

- **PLANNED — inherited boundary:** use only verified aligned response/egress rows
  (`destination == 1`, ARFF `command response == 0`) and preserve EXP-0008's exact
  five-second eligible windows, guarded TRAIN 28,040 / VALIDATION 9,345 / TEST 9,347
  split, DoS-containing versus pure-Normal cohort, exclusion of other-attack-only
  windows, 33 cadence features, TRAIN-only immutable type discovery/baselines, and
  canonical mapper. EXP-0007 outputs remain invalid; EXP-0008/0009 code, tests, and
  results remain read-only. No TEST row/value/label/feature/prediction/metric may be
  materialized during EXP-0011.
- **PLANNED — common sweep and recommendation rule:** for every successful candidate,
  sweep thresholds 0.10 through 0.90 inclusive by 0.05. Select maximum recall subject
  to precision ≥0.50; ties use higher F1, then precision, then higher threshold. If no
  point is feasible, use maximum F1, then recall, precision, and higher threshold. Rank
  candidates and frozen EXP-0009b by their selected points using recall, then F1, then
  precision; exact configuration ties prefer the existing EXP-0009b, followed by 0011a,
  0011b Borderline-SMOTE, 0011b ADASYN, the written 0011c grid order, then 0011d. A
  candidate meaningfully beats the baseline only if this ranking is strictly improved.
- **PLANNED — 0011a protocol diagnosis and conditional model:** verify Modbus semantics
  and actual canonical shapes: function `0x03` Read Holding Registers responses contain
  byte count plus returned register values, whereas function `0x10` Write Multiple
  Registers responses normally echo starting address and quantity and contain no
  returned measurement value. Audit non-missing pressure by TRAIN/VALIDATION type and
  class. If `0x10` has no pressure throughout pre-TEST data and the protocol/shape check
  agrees, classify the gate as a schema/protocol limitation. Add only the seven frozen
  numeric `0x03` pressure summaries plus `func_03_pressure_available`; when unavailable,
  numeric summaries use a declared zero placeholder interpreted only with that flag.
  Define no `0x10` pressure feature. Train standard-SMOTE + RF exactly as 0009b and sweep
  VALIDATION. If any `0x10` pressure exists outside TRAIN, classify this as split
  sparsity and stop 0011a—do not widen TRAIN, alter the split, or invent/impute values.
  Any contradictory protocol/shape evidence also stops the sub-experiment.
- **PLANNED — 0011b sampler comparison:** on the original 33 cadence features, replace
  standard SMOTE independently with
  `BorderlineSMOTE(sampling_strategy="auto", k_neighbors=5, random_state=0)` and
  `ADASYN(sampling_strategy="auto", n_neighbors=5, random_state=0)`. Resample TRAIN
  only; retain RF `n_estimators=300`, `class_weight=None`, `random_state=0`,
  `n_jobs=-1`; report threshold 0.60 plus the full sweep/selected point. If a library
  sampler fails, report that candidate stopped without changing settings.
- **PLANNED — 0011c small RF grid:** use EXP-0009b's original 33 cadence features and
  exact standard SMOTE, then evaluate all nine combinations of
  `max_depth ∈ {None, 10, 20}` × `min_samples_leaf ∈ {1, 2, 5}`. Every RF retains 300
  trees, `class_weight=None`, seed 0, and `n_jobs=-1`. Sweep each on unchanged
  VALIDATION, select by the common rule, and break exact ties by written Cartesian order
  (depth None/10/20, then leaf 1/2/5). Report all nine selected rows and the winning
  curve.
- **PLANNED — 0011d RF/XGBoost ensemble:** reproduce EXP-0009b RF and EXP-0009c
  XGBoost probabilities from their frozen recipes on the original cadence features;
  combine only by equal-weight probability average `(p_rf + p_xgb) / 2`; sweep unchanged
  VALIDATION. Report threshold 0.60 and the selected point. Across the 17 RF and 17
  ensemble thresholds, report whether either model Pareto-dominates the other (precision
  and recall no worse with at least one strict improvement), including whether the
  ensemble beats RF on both metrics, only one, or neither.
- **PLANNED — outputs and stop:** create only `ml/exp0011_payload_diagnostic.py`,
  `ml/exp0011_validation.py`, and dedicated tests; write ignored local
  `data/experiments/exp0011_validation.json` atomically. Report all candidates,
  regressions, diagnostic evidence, full comparison, and the honest final recommendation
  even if it remains EXP-0009b. Run the complete suite before and after and report exact
  counts. Stop with **TEST NOT RUN**, show the full diff/results, and wait before any
  commit. Do not touch Layer A, `app.py`, dashboard, prior experiment files, or push.

- **IMPLEMENTED — isolated construction:** added only the two preregistered EXP-0011
  modules and two synthetic test modules. The runner has no TEST scorer or confirmation
  token, prepares only TRAIN/VALIDATION matrices, applies every sampler to TRAIN only,
  uses one standard-SMOTE resample across the nine RF-grid fits, forms the ensemble by
  the frozen arithmetic mean, and writes machine-readable JSON atomically. Eight new
  0011a columns are seven numeric `0x03` summaries plus the explicit availability flag;
  there is no `0x10` pressure column.
- **VALIDATED — protocol and measured diagnosis:** the official *MODBUS Application
  Protocol Specification V1.1b3* §6.3 and §6.12 defines `0x03` responses as byte count
  plus returned registers and `0x10` responses as starting address plus quantity written.
  The discovered canonical shapes exactly matched `(3,0,23,18,0)` and
  `(16,0,8,-1,0)`. Every canonical `0x03` pre-TEST frame had pressure: TRAIN Normal/DoS/
  other `21,384/326/6,179`, VALIDATION `7,262/146/2,169`. Every canonical `0x10` frame
  had no pressure: TRAIN frame counts `21,387/518/16,076`, VALIDATION
  `7,263/305/5,680`, all with zero non-missing values. This is therefore
  **SCHEMA_LIMITATION — 0x03-ONLY PAYLOAD AUTHORIZED**, not split sparsity. The
  TRAIN-normal `0x03` baseline was `8.27919195936214`.
- **VALIDATED — common cohort and incumbent:** the unchanged VALIDATION cohort contained
  5,055 windows (`4,852` Normal, `203` DoS). Reproduced EXP-0009b at threshold `0.60`
  exactly: precision `0.929825`, recall `0.522167`, F1 `0.668770`, FPR `0.001649`,
  TN/FP/FN/TP `4,844/8/97/106`.
- **VALIDATED — selected points for 0011a/b/d:** under the preregistered sweep rule,
  0011a selected `0.20`: precision `0.568528`, recall `0.551724`, F1 `0.560000`, FPR
  `0.017519`, counts `4,767/85/91/112`. At `0.60`, it was `0.963303/0.517241/0.673077`
  precision/recall/F1 with FPR `0.000824` and counts `4,848/4/98/105`.
  Borderline-SMOTE selected `0.50`: `0.963636/0.522167/0.677316`, FPR `0.000824`,
  `4,848/4/97/106`; at `0.60` it was `0.990566/0.517241/0.679612`, FPR `0.000206`,
  `4,851/1/98/105`. ADASYN selected `0.55` and exactly tied the incumbent point; at
  `0.60` it was also `0.990566/0.517241/0.679612`, FPR `0.000206`,
  `4,851/1/98/105`. The ensemble selected `0.80`: `0.963636/0.522167/0.677316`, FPR
  `0.000824`, `4,848/4/97/106`; at `0.60` it was `0.576087/0.522167/0.547804`, FPR
  `0.016076`, `4,774/78/97/106`. The ensemble selected point improves precision but
  not recall versus RF—it does **not** beat RF on both. Each curve has all 17 frozen
  thresholds; each model family also dominates some points of the other curve, so there
  is no global Pareto dominance.
- **VALIDATED — 0011c grid:** selected threshold and precision/recall/F1 for the written
  grid order were: None/1 `0.60, 0.929825/0.522167/0.668770`; None/2 `0.55,
  0.913793/0.522167/0.664577`; None/5 `0.55, 0.946429/0.522167/0.673016`; 10/1 `0.50,
  0.946429/0.522167/0.673016`; 10/2 `0.45, 0.929825/0.522167/0.668770`; 10/5 `0.45,
  0.921739/0.522167/0.666667`; 20/1 `0.60, 0.938053/0.522167/0.670886`; 20/2 `0.50,
  0.791045/0.522167/0.629080`; and 20/5 `0.55, 0.938053/0.522167/0.670886`. None/5
  wins because it ties 10/1 exactly and precedes it in the frozen Cartesian order.
- **VALIDATED — recommendation:** 0011a at threshold `0.20` strictly wins the declared
  recall-first rule, detecting six additional DoS windows (`112` versus `106` TP), but
  its precision falls by `0.361297`, F1 falls by `0.108770`, and false positives rise
  from `8` to `85`. Thus it is the formal candidate to send to one eventual frozen TEST
  score, not an across-metric improvement. Borderline-SMOTE and the ensemble improve
  precision/F1 but not recall; ADASYN ties; no 0011c setting improves recall. Repeated
  comparisons on one VALIDATION block and ARFF-only pressure decoding remain material
  limitations.
- **TESTED — execution record:** pre-implementation suite baseline was **64 passed**.
  Final dedicated coverage is **14 passed** and the complete suite is **78 passed**
  (net **+14**), subject to the final verification command recorded with the diff. The
  first modeling invocation completed fits but failed before accepted output because
  nested read-only mappings were not JSON serializable; recursive strict-JSON
  normalization was added, tests were extended, and VALIDATION was rerun. This was an
  implementation-output correction, not a rule or model change. **TEST NOT RUN. No
  commit or push performed.**
- **AUTHORIZED SELECTION OVERRIDE — recorded before TEST:** 0011a was investigated and
  remains the mechanical recall-first winner, but it is **not selected**: its six extra
  true positives cost 77 extra false positives and regress precision, F1, and FPR, while
  `func_03_pressure_available` retains an unresolved schedule/presence leakage question.
  The final frozen-TEST configuration is instead **0011b Borderline-SMOTE + RF at 0.50**,
  using only EXP-0009b's 33 cadence features, TRAIN-only resampling, and fingerprint
  `bb89557b34a1ff3850ae06a3e8151d70dad9f215837f5c0d5216e1a5b0f9cc40`; this is a
  human deployment-suitability override after VALIDATION, not a retroactive change to
  the preregistered selection rule. **TEST NOT YET RUN at the time of this record.**
- **VALIDATED — one frozen TEST pass:** after that selection override, the exact guarded
  EXP-0011b configuration was refitted from TRAIN, its fingerprint matched
  `bb89557b34a1ff3850ae06a3e8151d70dad9f215837f5c0d5216e1a5b0f9cc40`, and TEST
  was materialized and scored exactly once at threshold `0.50`. The cohort contained
  `4,807` pure-Normal and `193` DoS-containing windows; `4,347` other-attack windows
  remained excluded. Result: precision `0.912281`, recall `0.269430`, F1 `0.416000`,
  FPR `0.001040`, TN/FP/FN/TP `4,802/5/141/52`. No payload or availability feature was
  used. Compared with EXP-0008 Detector B on the identical TEST cohort, recall and TP/FN
  are unchanged, while false positives fall `30→5`, precision rises `0.634146→0.912281`,
  and F1 rises `0.378182→0.416000`. The VALIDATION recall `0.522167` did not hold on
  frozen TEST; 141/193 DoS windows remain missed. **NO TEST RERUN.**

---

### EXP-0013 · First TEST-blind frozen Type 1 DoS evaluation (corrected manifest) — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before fitting the EXP-0013 model or
> materializing any TEST row, value, label, feature, prediction, or metric. This is the
> **first genuinely TEST-blind frozen evaluation for Type 1 DoS detection in this
> project.** It is built on the corrected split manifest and follows the invalidation of
> EXP-0008, EXP-0009, and EXP-0011's TEST-adjacent results by the boundary-construction
> flaw (`partition_pretest_inputs()` derived the 60/20/20 cut positions from full-capture
> eligibility, so nominal TEST-tail records could alter the pre-TEST TRAIN/VALIDATION
> populations). EXP-0011b's previously-reported `26.9% / 91%` frozen TEST result is
> withdrawn and must not be cited, reused, or treated as final.

- **PLANNED — corrected manifest:** pre-TEST construction selects only the exact ordered
  bucket IDs in `ml/splits/verified_egress_5s_exp0008_pretest_v1.json`, split ID
  `verified-egress-5s-exp0008-pretest-v1`, membership SHA-256
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`. Parsing stops after
  the final frozen VALIDATION bucket; no TEST-tail record is read during TRAIN/VALIDATION
  construction, and the manifest's TEST count is deliberately `null`/unreadable. The
  loader fails closed on any ID or checksum mismatch.
- **PLANNED — TEST construction (guarded, one shot):** TEST is every emitted egress
  (`destination == 1`) five-second window that begins **after** the frozen final
  VALIDATION bucket, with the **first 2 emitted windows discarded as guards**, derived
  from the manifest's fixed boundary — **not** from any full-capture recomputation. This
  is the "future guarded TEST construction" described in the prior review. TEST is
  materialized only inside the explicitly confirmed score path
  (`--score-frozen-test --confirm SCORE-EXP-0013-FROZEN-TEST-ONCE`) and scored exactly
  once.
- **PLANNED — exact frozen configuration (fixed before running):**
  `BorderlineSMOTE(sampling_strategy="auto", k_neighbors=5, m_neighbors=10,
  kind="borderline-1", random_state=0)` applied to TRAIN only, then
  `RandomForestClassifier(n_estimators=300, class_weight=None, random_state=0,
  max_depth=None, min_samples_leaf=1, n_jobs=-1)`, decision threshold `0.50`, on
  EXP-0009b's original **33 cadence features** with no payload, availability, or
  lag/trend features. This is EXP-0011b's model configuration, retrained fresh on the
  corrected manifest's TRAIN population. EXP-0013 asserts the exact sampler and RF knobs;
  it does **not** gate on EXP-0011b's pre-correction semantic fingerprint
  `bb89557b34a1ff3850ae06a3e8151d70dad9f215837f5c0d5216e1a5b0f9cc40`, because the
  corrected manifest and the rewritten cadence-feature pipeline legitimately produce a
  fresh forest. A knob mismatch stops before any TEST row is read.
- **PLANNED — cohort and rule:** DoS-containing versus pure-Normal windows;
  other-attack-only windows excluded. No threshold sweep, no TEST tuning, no rerun, no
  fusion. Configuration X is selected over EXP-0012's Configuration Y (see DECISION_LOG
  2026-09-09) because Y did not improve CV recall despite winning the mechanical
  precision-floor rule, and X is simpler with no unproven feature additions.
- **PLANNED — outputs and stop:** create only `ml/exp0013_frozen_test.py` and
  `tests/test_exp0013_frozen_test.py`; write ignored local
  `data/experiments/exp0013_frozen_test.json` atomically. Report exact
  precision/recall/F1/FPR/confusion counts and the full honest comparison table. Run the
  complete suite before and after with exact counts. Show the full diff and the real
  result, and wait for explicit go-ahead before any commit. Do not touch Layer A,
  `app.py`, the dashboard, or unrelated files; no push.

- **IMPLEMENTED — isolated construction:** added only `ml/exp0013_frozen_test.py` and its
  synthetic test module. The runner imports EXP-0011b's `fit_final_0011b` directly so the
  model recipe cannot drift, reuses `exp0008_cadence._test_block` for the manifest-derived
  guarded TEST construction, gates on the manifest ID + checksum and on the exact sampler
  and RF knobs, prepares only TRAIN/VALIDATION matrices before the confirmed score path,
  and writes machine-readable JSON atomically. No payload, availability, or lag/trend
  feature is present.
- **TESTED — execution record:** pre-implementation full suite baseline **93 passed**.
  New dedicated coverage `tests/test_exp0013_frozen_test.py` is **13 passed** and the
  complete suite is **106 passed** (net **+13**). Tests prove: confirmation token
  required before any work; manifest guard rejects a wrong split ID or checksum; TEST
  construction starts after the final VALIDATION bucket and discards the first 2 guard
  windows; the guarded score uses 33 features at threshold `0.50` with complete
  confusion counts and no payload/lag features; a wrong RF knob stops before TEST
  materialization; TEST-only record mutations leave the pre-TEST matrices byte-identical;
  pre-TEST construction never enumerates TEST windows.
- **VALIDATED — one TEST-blind frozen pass (threshold 0.50):** manifest verified
  (`verified-egress-5s-exp0008-pretest-v1`, checksum
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`); pre-TEST
  parsing stopped after the final VALIDATION bucket (TEST count `null` during
  construction). TRAIN/VALIDATION window counts were `28,040 / 9,345` (identical to
  EXP-0011b by manifest design); resampled TRAIN was `29,902` rows (`14,951 / 14,951`).
  The fresh forest fingerprint is
  `d55a802eeb0b5effb356dc7fee700b5a882d18cfbe165be3ef897d8cb06c2023` (EXP-0011b
  pre-correction was `bb89557b…`; differs by design). TEST was then materialized once:
  `9,347` emitted windows, cohort `5,000` (`4,807` pure-Normal, `193` DoS-containing),
  `4,347` other-attack windows excluded. Result: **precision `0.981132`, recall
  `0.269430`, F1 `0.422764`, FPR `0.000208`, TN/FP/FN/TP `4,806/1/141/52`.** `52/193`
  DoS windows detected; `141` missed. **NO TEST RERUN.**

- **VALIDATED — full honest comparison table.** EXP-0013 is the **only** row that is a
  validated, trustworthy, constructionally TEST-blind Type 1 DoS number. Every
  EXP-0008/0009/0011 row is retained for the audit trail only and must not be treated as
  comparable.

  | experiment | scope / status | precision | recall | F1 | FPR | TN / FP / FN / TP |
  |---|---|---|---|---|---|---|
  | **EXP-0013** (this) | **VALIDATED — first TEST-blind frozen Type 1 DoS number** | **0.981132** | **0.269430** | **0.422764** | **0.000208** | **4,806 / 1 / 141 / 52** |
  | EXP-0004 | CONTEXT — egress-only Isolation Forest; different (136 dominant-DoS) cohort | — | 0.000 (flag rate) | — | 0.007489 | — |
  | EXP-0005b | OUT OF SCOPE — bidirectional traffic; 193 DoS vs 4,931 Normal | 0.630252 | 0.388601 | 0.480769 | 0.008923 | 4,887 / 44 / 118 / 75 |
  | EXP-0008 Detector A | INVALIDATED — boundary-construction flaw, not constructionally TEST-blind, retained for audit trail only | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 4,807 / 0 / 193 / 0 |
  | EXP-0008 Detector B | INVALIDATED — boundary-construction flaw, not constructionally TEST-blind, retained for audit trail only | 0.634146 | 0.269430 | 0.378182 | 0.006241 | 4,777 / 30 / 141 / 52 |
  | EXP-0009b | INVALIDATED — boundary-construction flaw; VALIDATION-only, never frozen-TEST scored; retained for audit trail only | 0.929825 | 0.522167 | 0.668770 | 0.001649 | (VALIDATION) 4,844 / 8 / 97 / 106 |
  | EXP-0011b | INVALIDATED — boundary-construction flaw, not constructionally TEST-blind, retained for audit trail only; the `26.9% / 91%` result must NOT be cited, reused, or treated as final | 0.912281 | 0.269430 | 0.416000 | 0.001040 | 4,802 / 5 / 141 / 52 |

- **VALIDATED — reading of the result:** the corrected boundary did **not** change the
  substantive Type 1 DoS finding. On the identical cohort, EXP-0013 detects the same
  `52/193` DoS windows as the invalidated EXP-0011b and EXP-0008 Detector B and misses
  the same `141`; recall is `0.269430` (`≈27%`). The fresh fit tightened precision
  (`0.912281 → 0.981132`) and FPR (`0.001040 → 0.000208`), with false positives
  `5 → 1`. The `≈52%` VALIDATION recall seen across EXP-0009b/0011/0012 did not
  generalize — consistent with EXP-0012b's finding of large fold-to-fold instability.
- **LIMITATIONS:** one labelled testbed cannot establish universal DoS detectability; the
  labelled attack is not established as a classic volumetric flood; response type is an
  egress-visible proxy for an unseen query; the manifest freezes memberships EXP-0008
  originally derived from full-capture eligibility, so the prospective freeze removes
  future TEST-tail dependence but does not prove the historical source boundary was
  chosen independently of TEST.
- **STOP — phase closed for Type 1 DoS.** This is the final closing number for Type 1 DoS
  in the current phase. No further Type 1 DoS variants or optimizations are proposed or
  authorized. Full suite **106 passed**. Diff and result shown; **no commit or push
  performed** pending explicit go-ahead.

---

### EXP-0010 · Synthetic egress-flood (Type 2 DoS) capability test of the existing EXP-0004 detector — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before writing the injection/evaluation code,
> before synthesizing any flood, and before scoring anything. Parameters below are fixed
> now. This experiment **trains no model** and **modifies no detector code**: it measures
> whether the already-validated EXP-0004 detector (deterministic rule layer OR Isolation
> Forest) flags a clearly-labelled *synthetic* egress-channel flood injected into real
> Normal egress windows.

- **PLANNED — Type 1 vs Type 2 (see DECISION_LOG 2026-09-09):** the Turnipseed dataset's
  `DoS` label is **Type 1** — an external Bad-CRC flood on the *inbound command* path.
  It never crosses the diode, the slave's egress replies during it are byte-identical to
  normal, and EXP-0013 closed it at recall `0.269430` / precision `0.981132`
  (constructionally TEST-blind). **Type 2** is architecturally different: an insider or
  compromised device flooding the *outbound* channel itself (excessive telemetry,
  high-frequency sensor spam, log flooding) — traffic that by definition **does** cross
  the diode because it *is* the egress stream. **No dataset in this project contains a
  labelled Type 2 example.** The only available test method is synthetic injection into
  real Normal egress traffic; every result table is labelled `SYNTHETIC INJECTION TEST`
  and is never presented as captured attack data. This is not the fabricated-dataset
  failure mode: the underlying frames are real verified capture, only the volume/rate
  anomaly is synthetic, and it is labelled synthetic throughout.
- **PLANNED — detector under test (unmodified):** the EXP-0004 combined operational
  detector = `DeterministicRuleLayer` (out-of-profile function code / novel slave
  address; frozen from TRAIN-normal) **OR** Isolation Forest (300 trees, `max_samples=
  "auto"`, `contamination="auto"`, seed 0) over the 14 `IF_FEATURES`, standardiser frozen
  from TRAIN-normal, threshold = VALIDATION-normal 99th-percentile score
  `0.6745465823488428`. `ml/iforest_detector.py`, `ml/rules.py`, `ml/features_windowed.py`
  are **not modified**. EXP-0010 reproduces the identical fit in-process (same seed,
  config, TRAIN-normal population) and **asserts** its TEST-block `if_pred` is
  element-wise equal to `run_detector()` before scoring any synthetic window; a mismatch
  stops the experiment.
- **PLANNED — corrected manifest for all boundary construction:** TRAIN / VALIDATION come
  from `ml/splits/verified_egress_5s_exp0008_pretest_v1.json`, split ID
  `verified-egress-5s-exp0008-pretest-v1`, membership SHA-256
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`. TEST is the egress
  five-second windows (`destination == 1`, ≥2 frames) whose bucket begins **after** the
  final frozen VALIDATION bucket, with the first **2** emitted windows discarded as
  guards — the manifest-derived construction, **not** a full-capture recomputation.
  EXP-0010 **asserts** that the existing detector's own `contiguous_blocks(46,736)`
  TRAIN / VALIDATION / TEST bucket sets are byte-identical to this manifest construction
  (pre-checked: they are — TRAIN 28,040 / VALIDATION 9,345 / TEST 9,347); a mismatch
  stops the experiment and is itself reported as a finding.
- **PLANNED — why using TEST data here is appropriate:** this is a capability probe of an
  **already-trained, already-frozen** detector, not model selection or training. No
  EXP-0010 decision (threshold, feature, hyperparameter, architecture) is or can be
  informed by what is seen on these windows — the detector is immutable. That is
  categorically different from training-time TEST access, which biases a model toward the
  held-out set. The real Normal TEST windows are used as a realistic substrate for
  injection and as an untouched false-positive control.
- **PLANNED — injection substrate:** every real **Normal** TEST window (`is_attack == 0`,
  `categorized_attack` all `0`) — pre-checked count 4,807. Each is flooded independently;
  the real frames of that window are the seed material.
- **PLANNED — injection method (frame-level synthesis, uniform re-spacing):** for
  severity multiplier `K`, build `target_n = round(K · n)` frames spanning the window's
  5-second bucket, uniformly spaced (`t_i = bucket·5 + i·5/target_n`, `i = 0..target_n-1`;
  constant gap `5/target_n`). Feature values are then computed by a helper that mirrors
  `features_windowed.build_windows` exactly and is **asserted identical** to
  `build_windows()` for every real Normal TEST window at `K = 1`. Two profiles, reported
  as separate dose-response curves:
  - **Profile A — distinct-frame flood:** the `target_n` frames cycle the window's real
    frames (`real[i mod n]`) for address / function code / length / entropy, each given a
    fresh unique `frame_id`. Only volumetric and timing features move
    (`packet_count`, `packets_per_sec`, `bytes_per_sec` scale by `K`; `iat_mean/min/max
    → 5/(target_n-1)`; `iat_std → 0`; `distinct_frame_ratio → 1.0`;
    `repeat_frame_rate → 0`). This is the hardest, purest volumetric test: can the IF
    catch a flood from **rate alone**? Models high-rate distinct telemetry / sensor spam.
  - **Profile B — duplicate-frame flood:** the `target_n` frames are the `n` real
    distinct frames plus `target_n - n` exact duplicates (same `frame_id`), ordered so
    identical frames are adjacent. Additionally collapses `distinct_frame_ratio` (`→
    n_distinct/target_n`) and raises `repeat_frame_rate`. Models a stuck sensor / cached
    telemetry / log line re-emitted at high frequency.
  Function codes stay `{0x03, 0x10}` and address stays the profiled value, so the rule
  layer is expected to stay silent — flood detection therefore rests on the IF. Uniform
  re-spacing is the standard constant-rate-flood model; real floods carry jitter, which
  would not materially change the volumetric signal.
- **PLANNED — severity levels (dose-response):** `K ∈ {1, 2, 5, 10, 20}`. `K = 1` is a
  sanity anchor: no injection, both profiles must reproduce the EXP-0004 Normal-TEST
  false-positive rate exactly. `2× / 5× / 10×` are the requested operating points; `20×`
  shows the curve's high end. These multipliers are reasonable egress-flood proxies:
  Normal egress here is regular ~2 s polling telemetry, so 2× is a mild but plausible
  misconfiguration and 10–20× is an unambiguous flood well inside real DoS rate ranges.
- **PLANNED — evaluation and reporting:** for each `(profile, K)` report, over the 4,807
  injected windows: **detection rate** of the combined detector, plus rule-only and
  IF-only rates, and the mean IF anomaly score vs. threshold. Separately report the
  combined / IF-only **false-positive rate on the 4,807 untouched real Normal TEST
  windows** (expected unchanged from EXP-0004's `36/4,807 = 0.749%`; confirmed, not
  assumed). Every table is headed `SYNTHETIC INJECTION TEST`. If the existing detector
  already catches Type 2 floods well, that is the finding — Type 2 would then be covered
  by the existing pipeline. If it does not, that is the finding, and the entry will
  **note but not build** what a minimal fix looks like (most likely a fixed
  rate-threshold rule in the existing deterministic rule layer, a fast low-risk addition
  since the rule layer already exists and a volumetric flood is not a subtle signal).
- **PLANNED — outputs / scope:** new files only — `ml/exp0010_egress_flood.py`,
  `tests/test_exp0010_egress_flood.py`, and gitignored `data/experiments/
  exp0010_egress_flood.json`. Do **not** touch Layer A, `app.py`, `ml/iforest_detector.py`,
  `ml/rules.py`, `ml/features_windowed.py`, or the Type 1 DoS files (EXP-0007…EXP-0013).
  Run the full suite before and after with exact counts. Show the full diff and all
  per-severity results, then wait for explicit go-ahead before any commit. No push.

- **IMPLEMENTED — isolated code:** added only `ml/exp0010_egress_flood.py` and
  `tests/test_exp0010_egress_flood.py`; JSON is gitignored at
  `data/experiments/exp0010_egress_flood.json`. `FrozenExp0004Detector` reproduces the
  EXP-0004 combined detector in-process (Isolation Forest 300 trees, seed 0, frozen
  TRAIN-normal standardiser, threshold `0.6745465823488428`; rule layer from the frozen
  TRAIN-normal profile). `synthesize_flood` is deterministic (no RNG). `_window_features`
  mirrors `features_windowed.build_windows` and is asserted equal to `build_windows()` for
  every real Normal TEST window at `K = 1`. `ml/iforest_detector.py`, `ml/rules.py`,
  `ml/features_windowed.py` are unchanged.
- **VALIDATED — gates (all passed before any synthetic window was scored):**
  - *Boundary gate:* EXP-0004's `contiguous_blocks(46,736)` TRAIN / VALIDATION / TEST
    bucket sets are byte-identical to `verified-egress-5s-exp0008-pretest-v1` (TRAIN
    28,040 / VALIDATION 9,345) and to the manifest-derived guarded TEST construction
    (9,347).
  - *Identity gate:* the reproduced IF's `if_pred` on the real TEST block equals
    `run_detector().if_pred` element-wise; the combined-detector TEST confusion is exactly
    EXP-0004's `TN 4,771 / FP 36 / FN 3,793 / TP 747`; threshold equals the EXP-0004
    frozen value.
  - *Feature-helper gate:* `_window_features` reproduces `build_windows()` exactly on all
    4,807 real Normal TEST windows.
  - *K = 1 sanity:* both profiles at `K = 1` reproduce the untouched Normal-TEST
    detection rate exactly.
- **VALIDATED — false-positive control (untouched real Normal TEST, n = 4,807):** combined
  FPR `0.007489`, identical to EXP-0004's `36/4,807`. Injecting floods into *other*
  windows does not change the detector's behaviour on real Normal traffic (confirmed, not
  assumed).

- **VALIDATED — evaluation cohort (explicit, reproducible):** each `(profile, severity)`
  row is scored against a two-class cohort of **9,614** windows —
  - **negative class:** the **4,807** real untouched Normal TEST windows (`is_attack == 0`,
    `categories == {0}`), scored once;
  - **positive class:** the **same 4,807** windows, synthetic-flood-injected at that
    `(profile, severity)`.
  `FP` and `TN` are therefore constant across every row (the negative class is
  unmodified, and injecting floods into other windows does not change the detector's
  verdict on real Normal traffic — verified): `FP = 36`, `TN = 4,771`, exactly EXP-0004's
  real-Normal-TEST split. `precision = TP/(TP+36)`, `recall = TP/(TP+FN) =` the flood
  detection rate, `FPR = 36/4,807 = 0.007489`. The `1×` rows have no injection, so the
  positive class *is* the negative class — they are the sanity anchor only, not a
  meaningful precision/recall point.

- **VALIDATED — SYNTHETIC INJECTION TEST — dose-response, combined detector (rule OR IF):**

  | profile | severity | precision | recall | F1 | FPR | TN | FP | FN | TP |
  |---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
  | A — distinct-frame flood | 1× (sanity anchor) | 0.5000 | 0.0075 | 0.0148 | 0.007489 | 4,771 | 36 | 4,771 | 36 |
  | A — distinct-frame flood | 2× | 0.9694 | **0.2376** | 0.3816 | 0.007489 | 4,771 | 36 | 3,665 | 1,142 |
  | A — distinct-frame flood | 5× | 0.9694 | **0.2376** | 0.3816 | 0.007489 | 4,771 | 36 | 3,665 | 1,142 |
  | A — distinct-frame flood | 10× | 0.9694 | **0.2376** | 0.3816 | 0.007489 | 4,771 | 36 | 3,665 | 1,142 |
  | A — distinct-frame flood | 20× | 0.9694 | **0.2376** | 0.3816 | 0.007489 | 4,771 | 36 | 3,665 | 1,142 |
  | B — duplicate-frame flood | 1× (sanity anchor) | 0.5000 | 0.0075 | 0.0148 | 0.007489 | 4,771 | 36 | 4,771 | 36 |
  | B — duplicate-frame flood | 2× | 0.9926 | **1.0000** | 0.9963 | 0.007489 | 4,771 | 36 | 0 | 4,807 |
  | B — duplicate-frame flood | 5× | 0.9926 | **1.0000** | 0.9963 | 0.007489 | 4,771 | 36 | 0 | 4,807 |
  | B — duplicate-frame flood | 10× | 0.9926 | **1.0000** | 0.9963 | 0.007489 | 4,771 | 36 | 0 | 4,807 |
  | B — duplicate-frame flood | 20× | 0.9926 | **1.0000** | 0.9963 | 0.007489 | 4,771 | 36 | 0 | 4,807 |

  IF-only detection rate equals the combined rate here (the rule layer fires on 0 of all
  20 rows); IF-only / rule-only rates and the mean IF score per row are in the JSON.
  *These rows are a synthetic injection test, not results on captured attack data.*

- **VALIDATED — reading of the result (mixed; one clear gap):**
  - The **rule layer contributes nothing** to flood detection at any severity — it is a
    function-code / address membership test and is blind to volume, exactly as designed.
    All Type 2 detection here is the Isolation Forest.
  - **Duplicate-frame floods (Profile B) are caught completely** — recall `1.0000`,
    precision `0.9926`, F1 `0.9963` at every severity ≥ 2×. The collapsing
    `distinct_frame_ratio` (1.0 → 0.05) is a direction the IF was trained to treat as
    tightly constant, and it pushes the score decisively past threshold. A stuck sensor,
    cached-telemetry loop, or repeated log line at ≥ 2× rate is already effectively
    covered by the existing pipeline.
  - **Pure-volumetric floods with distinct frames (Profile A) are mostly missed** —
    recall only **`0.2376`** (precision `0.9694`, F1 `0.3816`), and **severity does not
    help**: the mean IF anomaly score is
    identical for 2× through 20× (`0.6617`) and sits just *below* the operating threshold
    `0.6745`. This is the well-known Isolation Forest saturation property — once a point
    is far outside the training support, extra distance does not lengthen its isolation
    path. The ~24% that are caught are windows whose non-rate features (entropy, frame
    length, read/write mix) were already near the boundary.
  - Every injected window at ≥ 2× has `packets_per_sec ≥ 1.2`, versus a **TRAIN-normal
    maximum of 0.8** and a **real Normal-TEST maximum of 0.8**. The volumetric signal is
    unambiguous and cleanly separated; the IF simply does not convert it into a
    threshold crossing for the distinct-frame case.
- **NOTED, NOT BUILT — minimal fix:** a single fixed rate-threshold rule in the existing
  `DeterministicRuleLayer` — flag a window when `packets_per_sec` exceeds the TRAIN-normal
  maximum (`0.8`) — would flag **100%** of both profiles at all severities ≥ 2× with
  **zero** new false positives on the 4,807 real Normal TEST windows (whose maximum is
  `0.8`). It is low-risk: the rule layer already exists, the threshold is frozen from
  TRAIN-normal exactly like the existing function-code profile, and a volumetric flood is
  not a subtle signal. This is **not implemented in EXP-0010**; it is recorded as the
  obvious next step if Type 2 coverage is wanted.
- **TESTED — execution record:** pre-EXP-0010 full suite **106 passed**. Added
  `tests/test_exp0010_egress_flood.py` = **8 passed** (7 fast synthetic unit tests + 1
  `@pytest.mark.slow` end-to-end gate/dose-response test). Full suite after: **114 passed
  in ~70 s** (net **+8**; the slow integration test re-runs the real detector +
  `build_windows`, roughly doubling suite wall time — deselect with `-m 'not slow'` for
  ~33 s).
- **LIMITATIONS:** the flood is synthetically injected, not captured; uniform re-spacing
  omits real timing jitter; Profiles A and B bracket two flood shapes and a real flood
  may sit between them; this is one testbed's Normal egress profile and detectability may
  differ elsewhere.
- **STATUS — Type 2 DoS:** the existing detector **already covers** duplicate/near-
  identical egress floods and **does not reliably cover** distinct-frame volumetric
  floods (~24%, severity-independent). A one-line rate rule would close the gap. No
  detector change is made here; **no commit or push performed** pending explicit
  go-ahead.

---

### EXP-0014 · Diagnostic — why does the EXP-0004 detector miss MSCI / MPCI? — 2026-09-09

> **PRE-REGISTRATION — PLANNED.** Recorded before writing the diagnostic code and before
> reading any per-window Isolation Forest score. **This is diagnostic / investigative
> only — no model is trained, retrained, re-thresholded, or changed, and no feature is
> added.** It characterises *why* EXP-0004's combined detector flags almost no MSCI
> (`2/324`) or MPCI (`8/741`) egress windows, and classifies the likely root cause for
> each. MSCI and MPCI first; NMRI and CMRI are a separate later diagnostic. **No fix is
> built or proposed as an implementation task here** — only the *category* of fix each
> diagnosis would indicate.

- **PLANNED — what MSCI / MPCI are (thesis-cited, `docs/00-dataset-provenance.md`
  BLOCKER 1):**
  - **MSCI** = *Malicious State Command Injection* (`categorized result == 3`). A
    command-injection attack that modifies the **state** of the physical process.
    Specific attacks (Table 3.6): `13` Pump ("randomly changes the state of the pump"),
    `14` Solenoid, `15` System Mode, `16–17` Critical Condition ("places the system in a
    Critical Condition … not included in normal activity").
  - **MPCI** = *Malicious Parameter Command Injection* (`categorized result == 4`). A
    command-injection attack that modifies **control parameters**. Specific attacks:
    `1–2` Setpoint, `3–4` PID Gain, `5–6` Reset Rate, `7–8` Rate, `9–10` Deadband,
    `11–12` Cycle Time — each "outside and inside the range of normal operation."
  - **Direction:** both are **command-side** (`command response == 1`, inbound). The
    malicious value (new setpoint / gain / pump state) travels in the injected command.
    An egress-only observer (`destination == 1`, `command response == 0`) never sees the
    command — only the slave's response.
  - **Pre-checked egress reality (frame-level):** every egress frame that carries an
    MSCI or MPCI label is a `function 0x10`, 8-byte **write-echo response**, and those
    echoes are structurally identical to normal write echoes — `start_register 3049`,
    `quantity 18`, `byte_count −1`, `length_anomaly 0`, `crc_ok 0`, `address 4`, message
    entropy exactly `3.0000` — for Normal, MSCI and MPCI alike. The echo does not encode
    which value was written. Read responses (`function 0x03`, 23-byte) in the same
    windows are label `0` (Normal). This will be stated as measured fact, not assumed.
- **PLANNED — corrected manifest for all boundary needs:** window blocks are assigned
  from `ml/splits/verified_egress_5s_exp0008_pretest_v1.json` (split ID
  `verified-egress-5s-exp0008-pretest-v1`, membership SHA-256
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`) for TRAIN /
  VALIDATION, and the manifest-derived guarded TEST construction (windows after the
  final VALIDATION bucket, first 2 discarded as guards). EXP-0014 asserts EXP-0004's own
  `contiguous_blocks(46,736)` split is byte-identical to this before using any score,
  exactly as EXP-0010 did.
- **PLANNED — detector reproduced, not modified:** EXP-0014 reconstructs the EXP-0004
  combined detector in-process (Isolation Forest 300 trees, seed 0, standardiser frozen
  from TRAIN-normal, threshold `0.6745465823488428`; rule layer from the frozen
  TRAIN-normal profile) and **asserts** its real-TEST `if_pred` equals `run_detector()`
  element-wise and its combined-TEST confusion equals EXP-0004's exact
  `TN 4,771 / FP 36 / FN 3,793 / TP 747` before any diagnostic score is read.
  `ml/iforest_detector.py`, `ml/rules.py`, `ml/features_windowed.py` are not touched.
- **PLANNED — feature-level diagnostic:** for **pure** MSCI windows (`categories ⊆ {0, 3}`,
  MSCI present) versus Normal, and separately pure MPCI versus Normal, report per-feature
  **mean ± population SD and Cohen's d** across all 16 `WINDOW_FEATURES` (the EXP-0004
  Isolation-Forest inputs plus the two rule-layer fields). Normal reference is reported
  two ways: (i) the full pure-Normal window population, and (ii) a **temporally matched**
  sample — for each attack window the nearest pure-Normal window by window index — to
  control for slow drift in the physical process. Effect sizes are graded by the
  pre-existing EXP-0003/0004 convention (`|d| < 0.2` negligible, `0.2–0.5` small,
  `0.5–0.8` medium, `> 0.8` large).
- **PLANNED — Isolation Forest score diagnostic (no retraining):** score every MSCI and
  every MPCI window with EXP-0004's already-fitted model. Report the score distribution
  (min / p10 / p25 / median / p75 / p90 / max, mean), the fraction at or above the
  operating threshold, and where the mass sits relative to two anchors: the
  **Normal-window mean score** (`≈ 0.47` — the "deep normal" region) and the
  **threshold** (`0.6745`). Clustering near the threshold indicates a
  calibration/threshold problem; sitting down at the Normal mean indicates
  feature-blindness. Report all-blocks and TEST-block-only.
- **PLANNED — class-size context:** report exact MSCI and MPCI window counts for TRAIN /
  VALIDATION / TEST (containing ≥ 1 such frame, and pure), alongside DoS's
  `359 / 203 / 193` and the pure-Normal `14,951 / 4,852 / 4,807`. Note that the current
  detector is **unsupervised** (fitted on Normal only), so class size does not limit it
  directly; the counts bound what a future *supervised* fix could use.
- **PLANNED — honest diagnosis, per category separately (MSCI and MPCI may differ):**
  classify the likely root cause as (a) feature blindness — existing features do not
  capture what the attack changes; (b) threshold / calibration — signal present but
  under the decision threshold; (c) extreme class imbalance — too few examples for any
  method; (d) something else. State which **category of fix** each diagnosis indicates
  (e.g. new payload/pressure-dynamics features; a targeted deterministic rule; a
  threshold change; more labelled data / a supervised model) **without building it**.
- **PLANNED — outputs / scope:** new files only — `ml/exp0014_cmd_injection_diag.py`,
  `tests/test_exp0014_cmd_injection_diag.py`, and gitignored
  `data/experiments/exp0014_cmd_injection_diag.json`. Tests reproduce EXP-0004's model /
  predictions exactly (EXP-0010 identity-check discipline) and cover the stats helpers.
  Do **not** touch EXP-0004's trained model, `ml/iforest_detector.py`, `ml/rules.py`,
  `ml/features_windowed.py`, the DoS files (EXP-0007…EXP-0013), Layer A, or `app.py`.
  Run the full suite before and after with exact counts. Show the full diff and every
  finding, then wait for explicit go-ahead before any commit. No push.

- **IMPLEMENTED — isolated diagnostic code:** added only `ml/exp0014_cmd_injection_diag.py`
  and `tests/test_exp0014_cmd_injection_diag.py`; JSON is gitignored at
  `data/experiments/exp0014_cmd_injection_diag.json`. `FrozenExp0004Detector` reproduces
  the EXP-0004 combined detector in-process from the same `ml/features_windowed` +
  `ml/iforest_detector` primitives — one `build_windows()` call, TRAIN-normal standardiser
  and Isolation Forest (300 trees, seed 0, `contamination`/`max_samples` `"auto"`),
  threshold as the VALIDATION-normal 99th-percentile score, rule layer fitted on the
  TRAIN-normal profile. *(Deviation from the pre-registration, which said "assert `if_pred`
  equals `run_detector()` element-wise": calling `run_detector()` re-runs `build_windows()`
  and roughly triples the test's wall time. The reproduction is instead gated on
  EXP-0004's exact frozen regression constants — the identical threshold and TEST
  confusion that `tests/test_detector.py` already asserts — which is an equally strong
  identity check.)* No model is trained beyond that reproduction; nothing is scored until
  the gates pass. `ml/iforest_detector.py`, `ml/rules.py`, `ml/features_windowed.py` unchanged.
- **VALIDATED — gates (all passed before any diagnostic score was read):** EXP-0004's
  `contiguous_blocks(46,736)` TRAIN / VALIDATION / TEST buckets are byte-identical to
  `verified-egress-5s-exp0008-pretest-v1` and its manifest-derived guarded TEST
  construction; the reproduced threshold equals EXP-0004's frozen
  `0.6745465823488428` **exactly** (`|Δ| < 1e-12`); the reproduced combined-detector
  TEST confusion is exactly `TN 4,771 / FP 36 / FN 3,793 / TP 747`.
- **VALIDATED — what is actually visible on egress (measured fact):** every egress frame
  carrying an MSCI (`3,950` frames) or MPCI (`10,206` frames) label is a `function 0x10`,
  8-byte **write-echo response** with `start_register 3049`, `quantity 18`,
  `byte_count −1`, `length_anomaly 0`, `crc_ok 0`, `address 4`, message entropy exactly
  `3.0000` — **identical to a normal write echo** on every field. Read responses
  (`function 0x03`, 23-byte) in these windows are label `0`. The injected command
  (`command response == 1`, inbound) — which carries the malicious setpoint / gain / pump
  state — is never on the egress side.

- **VALIDATED — EXP-0004 combined detector on MSCI / MPCI, TEST block (positive = TEST
  windows containing ≥ 1 such frame; negative = pure-Normal TEST windows; detector
  unchanged; FP / TN are EXP-0004's frozen Normal split):**

  | category | recall | precision | F1 | FP rate (of Normal) | TP / FN / FP / TN |
  |---|---:|---:|---:|---:|---:|
  | **MSCI** | **0.43 %** | 5.26 % | 0.80 % | 0.7489 % | `2 / 460 / 36 / 4,771` |
  | **MPCI** | **1.56 %** | 35.71 % | 2.99 % | 0.7489 % | `20 / 1,260 / 36 / 4,771` |

  The `36` false positives / `0.7489 %` FP rate is exactly EXP-0004's frozen Normal-FP
  (`36/4,807`) — the detector is not modified. MSCI recall against the narrower
  *dominant*-MSCI cohort EXP-0004's per-category table used (`324` windows) is
  `2/324 = 0.62 %`, matching that table; this diagnostic uses the broader *containing*
  cohort (`462`) throughout.
- **VALIDATED — class-size context:** MSCI/MPCI egress window counts (containing ≥ 1 such
  frame) are TRAIN / VALIDATION / TEST `1,791 / 521 / 462` (MSCI) and
  `4,356 / 1,510 / 1,280` (MPCI), versus DoS's `359 / 203 / 193` and pure-Normal
  `14,951 / 4,852 / 4,807`. MSCI and MPCI have **5× and 12× more** training windows than
  DoS. Pure windows (this category + Normal only): MSCI `1,080 / 296 / 322`, MPCI
  `2,402 / 864 / 739`. The current detector is unsupervised (Normal-only fit), so class
  size does not limit it directly; these counts show a future supervised fix would not
  be data-starved.

- **VALIDATED — feature-level diagnostic (pure windows vs nearest-index-matched pure-Normal;
  Cohen's d, EXP-0003/0004 grading):**

  | | max \|d\| across all 16 features | features with \|d\| ≥ 0.2 |
  |---|---:|---|
  | **MSCI** | `0.513` — `payload_entropy_std` (**medium**) | `payload_entropy_std` `+0.51`, `payload_entropy_mean` `+0.38`, `distinct_frame_ratio` `−0.25`, `frac_func_read` `−0.25`, `frac_func_write` `+0.25`, `mean_frame_len` `−0.25` (all small) |
  | **MPCI** | `0.268` — `frac_func_write` (**small**) | `frac_func_write` `+0.27`, `frac_func_read` `−0.27`, `mean_frame_len` `−0.27`, `distinct_frame_ratio` `−0.25` (all small) |

  Volumetric / timing features (`packet_count`, `packets_per_sec`, `bytes_per_sec`,
  `iat_mean/std/min/max`, `repeat_frame_rate`) are `|d| ≤ 0.16` for both. The small
  read/write-ratio and `mean_frame_len` shifts come from the injected write frames
  slightly changing the per-window frame mix. MSCI's `payload_entropy_*` signal is a
  **second-order** effect: state changes disturb the physical pressure, so the
  normal-labelled read-response payloads within an MSCI window vary more. MPCI (gradual
  parameter drift) produces no entropy signal.

- **VALIDATED — Isolation Forest score diagnostic (EXP-0004's already-fitted model, no retraining):**

  | | n windows | score min / median / p90 / max | mean | Normal-window mean | threshold | IF flag rate (all / TEST) | median position (0 = Normal mean, 1 = threshold) |
  |---|---:|---|---:|---:|---:|---:|---:|
  | **MSCI** | 2,774 | `0.398 / 0.484 / 0.566 / 0.697` | `0.492` | `0.473` | `0.6745` | `0.0083 / 0.0043` | **`0.055`** |
  | **MPCI** | 7,146 | `0.397 / 0.470 / 0.573 / 0.726` | `0.485` | `0.473` | `0.6745` | `0.0091 / 0.0141` | **`−0.015`** |

  The rule layer fires on `4` MSCI and `11` MPCI windows across all blocks (novel-address
  / bad-func-code coincidence in mixed windows, not the command injection). Both score
  distributions sit essentially **on top of** the Normal-window distribution: the median
  is within `±0.02` of the Normal-window mean and `< 6%` of the way to the threshold;
  even the p90 (`≈ 0.57`) is far below the threshold (`0.6745`), and only the extreme
  max just grazes it. A threshold low enough to catch half of MSCI (`≈ 0.484`) would sit
  barely above the Normal mean and flag a large fraction of Normal traffic.

- **VALIDATED — DIAGNOSIS (per category; a fix is described only by *category*, not built):**
  - **MPCI → (a) feature blindness. Unambiguous.** Every EXP-0004 feature is `|d| ≤ 0.27`
    (small at most) against matched Normal; the IF scores MPCI windows at or *below* the
    Normal-window mean (median position `−0.015`) — the model sees them as ordinary
    Normal traffic. **Not (b):** scores are deep-normal, not near threshold; no feasible
    threshold separates them. **Not (c):** `4,356` TRAIN windows, 12× DoS. Root cause:
    the parameters MPCI changes travel in the unseen inbound command; the egress echo is
    identical to normal; and a parameter nudge "inside the range of normal operation" is
    too subtle to perturb 5-second window aggregates.
    *Indicated category of fix (not built):* **new response-side content features** —
    decode the `pressure measurement` value from the `0x03` read response and model its
    dynamics (setpoint-tracking error, oscillation, drift), the only egress-visible
    consequence of the injected command, then a supervised model to weight them. A
    threshold change or more raw frames would not help.
  - **MSCI → primarily (a) feature blindness, with a partial signal the current model
    cannot exploit.** 14 of 16 features are `|d| ≤ 0.25`; two IF-input features carry a
    real but modest signal (`payload_entropy_std` `d = +0.51` medium, `payload_entropy_mean`
    `+0.38` small) from the pressure disturbance that discrete state changes cause. Yet
    the IF still scores MSCI at median position `0.055` and flags `0.4–0.8%` — a medium
    effect on 2 of 14 features, diluted by 12 near-identical features, does not lengthen
    an isolation path enough. **Not (b)**, **not (c)** (`1,791` TRAIN windows, 5× DoS).
    *Indicated category of fix (not built):* feature engineering that **isolates and
    amplifies the pressure-disturbance signal** the entropy features only hint at
    (explicit pressure-value variance / dynamics features), and/or a **supervised model**
    that can weight the two informative features the unsupervised IF averages away; a
    narrow deterministic rule on `payload_entropy_std` is a cheaper partial option worth
    measuring first. Not calibration, not data volume.

- **VALIDATED — honest limitation on "under-investment":** part of this gap is
  **structural**, like DoS — the command-injection payload genuinely never crosses the
  diode. What is *not* structural, and is under-investment: the response-side
  `pressure measurement` value **does** cross the diode and is currently used by **no**
  feature. There is real headroom there, but it is bounded by how detectable a
  mis-tuned controller is from its output pressure alone — which for the subtlest MPCI
  parameter tweaks may be close to a hard ceiling. The correct expectation is
  "meaningfully better than `1%`", not "`100%` like MFCI/Recon".
- **TESTED — execution record:** pre-EXP-0014 full suite **114 passed**. Added
  `tests/test_exp0014_cmd_injection_diag.py` = **8 passed** (7 fast stats-helper /
  confusion-arithmetic tests + 1 `@pytest.mark.slow` gate/structure test). Full suite
  after: **122 passed** (net **+8**). The `@pytest.mark.slow` EXP-0014 test builds the
  46,736-window feature matrix once and reproduces the EXP-0004 model
  (`build_windows()` dominates its ~35 s); it does **not** call `run_detector()`.
  `-m 'not slow'` runs **109 passed, 13 deselected**.
- **LIMITATIONS:** Cohen's d compares aggregate window features and the matched-Normal
  sample controls for slow drift by window index, not every confounder; the MSCI entropy
  signal is a second-order pressure effect, not the injected command; one testbed;
  egress-only.
- **STATUS — MSCI / MPCI:** diagnosed, **not fixed**. On the frozen TEST block the
  EXP-0004 combined detector gets MSCI recall `0.43 %` / precision `5.26 %` / F1
  `0.80 %` and MPCI recall `1.56 %` / precision `35.71 %` / F1 `2.99 %`, at the
  unchanged `0.7489 %` Normal FP rate. Both gaps are primarily feature blindness (the
  injected command is inbound; the egress echo is uninformative); MSCI leaks a weak
  pressure-disturbance signal into entropy that the unsupervised IF cannot use, MPCI
  leaks none. Fix category identified (response-side pressure-value features ± a
  supervised model); no fix built or scheduled here. NMRI / CMRI diagnostic is a
  separate follow-up. **No commit or push performed** pending explicit go-ahead.

---

### EXP-0015 · Diagnostic — why does the EXP-0004 detector miss NMRI / CMRI? — 2026-09-10

> **PRE-REGISTRATION — PLANNED.** Recorded before writing the diagnostic code and before
> reading any per-window Isolation Forest score. **Diagnostic / investigative only — no
> model is trained, retrained, re-thresholded, or changed, and no feature is added.** It
> characterises *why* EXP-0004's combined detector flags only `109/1,131` NMRI (`9.6 %`)
> and `232/1,812` CMRI (`12.8 %`) egress windows, and classifies the likely root cause
> for each. This completes the per-category gap review begun for MSCI/MPCI in EXP-0014.
> **No fix is built or scheduled here** — only the *category* of fix each diagnosis
> indicates.

- **PLANNED — what NMRI / CMRI are (thesis-cited, `docs/00-dataset-provenance.md` BLOCKER 1,
  same source as EXP-0014):**
  - **NMRI** = *Naïve Malicious Response Injection* (`categorized result == 1`). A
    **response-injection** attack: the forged reply has "sporadic and out of bounds
    behavior that would not be present in normal operation" — the attacker lacks
    physical-process knowledge. Specific attacks: `29–31` Random Value ("random pressure
    measurements are sent to the master"), `32` Negative Pressure ("sends back a negative
    pressure reading from the slave").
  - **CMRI** = *Complex Malicious Response Injection* (`categorized result == 2`). A
    **response-injection** attack that "mimic[s] certain behaviors which occur within
    normal bounds" to evade detection. Specific attacks: `25–26` Rise/Fall ("sends back
    pressure readings which create trends"), `27–28` Slope ("randomly increases/decreases
    pressure reading by a random slope"), `33–34` Fast, `35` Slow ("high then low
    setpoint changing fast/slow").
  - **Direction — the decisive question, pre-checked as measured fact:** both are
    **response-side / egress**. Every NMRI-labelled frame (`7,753`) and every
    CMRI-labelled frame (`13,035`) is `destination == 1`, `function 0x03`, 23-byte
    **read response** — the pressure telemetry the slave sends back. **Zero** NMRI/CMRI
    frames occur on the inbound command path. The forged pressure value **is** the egress
    traffic.
  - **Therefore the "malicious value never crosses the diode" caveat that bounds
    DoS / MSCI / MPCI does NOT apply to NMRI / CMRI.** The tampered content is directly
    present in egress. Any low recall here is a plain feature/model gap, not a structural
    observation limit. EXP-0015 will state this explicitly in the diagnosis either way.
- **PLANNED — corrected manifest for all boundary needs:** window blocks are assigned from
  `ml/splits/verified_egress_5s_exp0008_pretest_v1.json` (split ID
  `verified-egress-5s-exp0008-pretest-v1`, membership SHA-256
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`) for TRAIN /
  VALIDATION, and the manifest-derived guarded TEST construction. EXP-0015 asserts
  EXP-0004's `contiguous_blocks(46,736)` split is byte-identical to this.
- **PLANNED — detector reproduced, not modified (EXP-0010/0014 identity discipline):**
  EXP-0015 reconstructs the EXP-0004 combined detector in-process (Isolation Forest 300
  trees, seed 0, standardiser frozen from TRAIN-normal, threshold as the VALIDATION-normal
  99th-percentile score; rule layer from the TRAIN-normal profile) and **asserts**, before
  any diagnostic score is read: (i) its real-TEST `if_pred` equals `run_detector().if_pred`
  element-wise; (ii) its reproduced threshold equals EXP-0004's frozen
  `0.6745465823488428` (`|Δ| < 1e-12`); (iii) its combined-TEST confusion equals
  EXP-0004's exact `TN 4,771 / FP 36 / FN 3,793 / TP 747`. `ml/iforest_detector.py`,
  `ml/rules.py`, `ml/features_windowed.py` are not touched.
- **PLANNED — full metrics (same format as EXP-0014):** for NMRI and CMRI separately, on
  the unchanged EXP-0004 combined detector, report precision / recall / F1 / FPR and
  `TP / FN / FP / TN` for:
  - the **containing** cohort — positive = TEST windows with ≥ 1 that-category frame;
  - the **dominant** cohort — positive = TEST windows whose lowest non-zero
    `categorized_attack` is that category (the definition EXP-0004's per-category table
    used: NMRI `1,131`, CMRI `1,812`), to reconcile with the known `109/1,131` and
    `232/1,812`.
  Negative class for both = the `4,807` pure-Normal TEST windows; `FP` / `TN` are
  EXP-0004's frozen Normal split (`36 / 4,771`).
- **PLANNED — feature-level diagnostic:** for **pure** NMRI windows (`categories ⊆ {0, 1}`,
  NMRI present) versus Normal, and pure CMRI versus Normal, report per-feature mean ±
  population SD and **Cohen's d** across all 16 `WINDOW_FEATURES`, against both the full
  pure-Normal population and a **nearest-window-index matched** Normal sample. Grade by
  the EXP-0003/0004 convention (`|d| < 0.2` negligible, `0.2–0.5` small, `0.5–0.8` medium,
  `> 0.8` large).
- **PLANNED — Isolation Forest score diagnostic (no retraining):** score every NMRI and
  CMRI window with EXP-0004's fitted model; report min / p10 / p25 / median / p75 / p90 /
  max and mean, the IF flag fraction, and the median score's position between the
  Normal-window mean score and the frozen threshold — the same table as EXP-0014.
- **PLANNED — class-size context:** exact NMRI and CMRI TRAIN / VALIDATION / TEST window
  counts (containing and pure), alongside DoS `359 / 203 / 193`, MSCI `1,791`, MPCI
  `4,356`, and pure-Normal `14,951 / 4,852 / 4,807`.
- **PLANNED — honest diagnosis, per category separately:** classify as (a) feature
  blindness, (b) threshold / calibration, (c) class imbalance, (d) something else. State
  explicitly that the diode caveat does **not** apply (these are response-side), so a
  low-recall finding here is a feature/model gap. Name the **category of fix** each
  diagnosis indicates (e.g. features that decode the response `pressure measurement`
  value and its dynamics; a supervised model; a targeted rule) **without building it**.
- **PLANNED — outputs / scope:** new files only — `ml/exp0015_response_injection_diag.py`,
  `tests/test_exp0015_response_injection_diag.py`, and gitignored
  `data/experiments/exp0015_response_injection_diag.json`. Tests reproduce EXP-0004's
  model / predictions exactly (EXP-0010/0014 identity-check discipline) and cover the
  stats helpers. Do **not** touch EXP-0004's trained model, `ml/iforest_detector.py`,
  `ml/rules.py`, `ml/features_windowed.py`, the DoS files (EXP-0007…EXP-0013), the
  MSCI/MPCI diagnostic (EXP-0014), Layer A, or `app.py`. Run the full suite before and
  after with exact counts. Show the full diff and every finding, then wait for explicit
  go-ahead before any commit. No push.

- **IMPLEMENTED — isolated diagnostic code:** added only
  `ml/exp0015_response_injection_diag.py` and
  `tests/test_exp0015_response_injection_diag.py`; JSON is gitignored at
  `data/experiments/exp0015_response_injection_diag.json`. `FrozenExp0004Detector`
  reproduces the EXP-0004 combined detector in-process and is gated three ways before any
  diagnostic score is read (see below). No model is trained beyond that reproduction;
  `ml/iforest_detector.py`, `ml/rules.py`, `ml/features_windowed.py` unchanged.
- **VALIDATED — gates (all passed):** the reproduced Isolation Forest's `if_pred` on the
  real TEST block equals `run_detector().if_pred` **element-wise**; the reproduced
  threshold equals EXP-0004's frozen `0.6745465823488428` (`|Δ| < 1e-12`); the reproduced
  combined-detector TEST confusion is exactly `TN 4,771 / FP 36 / FN 3,793 / TP 747`;
  EXP-0004's `contiguous_blocks(46,736)` split is byte-identical to
  `verified-egress-5s-exp0008-pretest-v1`.
- **VALIDATED — direction (measured fact — the decisive question):** every NMRI-labelled
  frame (`7,753`) and every CMRI-labelled frame (`13,035`) is `destination == 1`,
  `function 0x03`, 23-byte **read response** — the pressure telemetry the slave sends
  back. **Zero** NMRI/CMRI frames on the inbound command path. NMRI/CMRI forge the
  response payload, and that payload **is** the egress traffic. **The "malicious value
  never crosses the diode" caveat that bounds DoS / MSCI / MPCI does NOT apply here.** Any
  low-recall finding is a plain feature/model gap.
- **VALIDATED — class-size context:** NMRI window counts (containing ≥ 1 frame) TRAIN /
  VALIDATION / TEST `3,093 / 1,098 / 1,131`, pure `1,839 / 678 / 715`. CMRI containing
  `5,337 / 1,795 / 1,826`, pure `3,238 / 1,086 / 1,198`. Both dwarf DoS's `359`; CMRI is
  comparable to MPCI's `4,356`. Not data-starved.

- **VALIDATED — EXP-0004 combined detector on NMRI / CMRI, TEST block (negative = the
  `4,807` pure-Normal TEST windows; `FP / TN = 36 / 4,771`, EXP-0004's frozen split;
  detector unchanged):**

  | category | cohort | n⁺ | recall | precision | F1 | combined TP | of which IF-only | of which rule-only |
  |---|---|---:|---:|---:|---:|---:|---:|---:|
  | **NMRI** | containing / dominant | 1,131 | **9.64 %** | 75.17 % | 17.08 % | 109 | 85 | 93 |
  | **NMRI** | **pure** (real RI detection) | 715 | **1.12 %** | 18.18 % | 2.11 % | 8 | 8 | **0** |
  | **CMRI** | containing | 1,826 | 12.71 % | 86.57 % | 22.16 % | 232 | 137 | 201 |
  | **CMRI** | dominant | 1,812 | **12.80 %** | 86.57 % | 22.31 % | 232 | 137 | 201 |
  | **CMRI** | **pure** (real RI detection) | 1,198 | **2.34 %** | 43.75 % | 4.44 % | 28 | 28 | **0** |

  FP rate is `0.7489 %` (`36 / 4,807`) on every row — EXP-0004's frozen Normal FP,
  unchanged. The **containing / dominant** rows (`9.64 % / 12.80 %`) reconcile with the
  known per-category table `109/1,131` and `232/1,812` **exactly** — but they are
  **misleading**: on those cohorts the deterministic **rule layer fires on `93` / `201`**
  of the flagged windows, because those windows also contain a co-occurring MFCI or Recon
  frame (a foreign function code), which is what the rule catches — *not* the response
  injection. On **pure** NMRI/CMRI windows (no co-attack, so the rule cannot fire on a
  foreign code) the combined detector flags **`8/715 = 1.12 %` (NMRI)** and
  **`28/1,198 = 2.34 %` (CMRI)**, entirely from the Isolation Forest. **The detector's
  actual detection of the forgery itself is ~1–2 %, right down with MSCI/MPCI.**

- **VALIDATED — feature-level diagnostic (pure windows vs nearest-index-matched Normal):**

  | | max \|d\| over 16 features | features with \|d\| ≥ 0.2 |
  |---|---:|---|
  | **NMRI** | `0.354` — `distinct_frame_ratio` (**small**) | `distinct_frame_ratio` `+0.35`, `frac_func_read` `+0.31`, `frac_func_write` `−0.31`, `mean_frame_len` `+0.31`, `payload_entropy_mean` `−0.26`, `bytes_per_sec` `+0.23` (all small) |
  | **CMRI** | `0.592` — `payload_entropy_mean` (**medium**) | `payload_entropy_mean` `−0.59`, `payload_entropy_std` `+0.45`, `distinct_frame_ratio` `+0.25`, `frac_func_read` `+0.21`, `frac_func_write` `−0.21`, `mean_frame_len` `+0.21` (rest small) |

  The small `distinct_frame_ratio` / `frac_func_read` / `mean_frame_len` / `bytes_per_sec`
  cluster (both categories) is a mild volumetric effect: the injection tools add extra
  read responses, so these windows carry a few more `0x03` frames. CMRI additionally has
  a **medium** byte-entropy signal — its "smooth trend / slope" forged readings are more
  repetitive (`payload_entropy_mean` down `0.055`) and more variable within a window
  (`payload_entropy_std` up). NMRI's "random / out-of-bounds" readings barely shift byte
  entropy (`d = −0.26`).

- **VALIDATED — Isolation Forest score diagnostic (EXP-0004's fitted model, no retraining):**

  | | n windows | score median / p90 / max | Normal-window mean | threshold | IF flag rate (all blocks) | median position (0 = Normal mean, 1 = threshold) |
  |---|---:|---|---:|---:|---:|---:|
  | **NMRI** | 5,322 | `0.475 / 0.624 / 0.708` | `0.473` | `0.6745` | `0.0445` | **`0.010`** |
  | **CMRI** | 8,962 | `0.491 / 0.630 / 0.739` | `0.473` | `0.6745` | `0.0436` | **`0.088`** |

  Both distributions sit on top of the Normal-window distribution: the median is at
  (NMRI) or `9 %` toward (CMRI) the threshold from the Normal mean, and even p90 (`≈ 0.63`)
  is below the threshold (`0.6745`). CMRI is marginally closer than MSCI/MPCI/NMRI (whose
  positions were `~0.05` or below).

- **VALIDATED — DIAGNOSIS (per category; fix described only by *category*, not built):**
  - **NMRI → (a) feature blindness. The diode caveat does NOT apply.** The forged pressure
    readings are egress traffic, but no feature decodes the value — and the byte entropy
    of "random / out-of-bounds" values barely differs from normal (`d = −0.26`). Real
    detection is `1.1 %`; the IF scores NMRI windows at the Normal-window mean (position
    `0.010`). **Not (b)** (deep normal, not near threshold). **Not (c)** (`3,093` TRAIN
    windows, 9× DoS). This is a pure feature/model gap on a fully-observable attack.
    *Indicated category of fix (not built):* decode the response `pressure measurement`
    value and add **physical-plausibility / out-of-bounds checks** (range, sign,
    rate-of-change) — NMRI is *defined* as naive out-of-bounds behaviour, so a simple
    decoded-value bound is likely to be highly effective and is the **cheapest, highest-
    yield fix in the whole per-category review**. A supervised model on decoded-value
    features is the fuller option.
  - **CMRI → (a) feature blindness, with the strongest salvageable signal of any missed
    category so far. The diode caveat does NOT apply.** Real detection is `2.3 %`, but
    `payload_entropy_mean` carries a **medium** effect (`d = −0.59`) and `payload_entropy_std`
    a near-medium one — the artificial trends/slopes measurably flatten and destabilise
    the frame byte entropy. The IF uses these features yet still cannot convert the signal
    (median position `0.088`): two informative features against twelve flat ones do not
    lengthen an isolation path. **Not (b)**, **not (c)** (`5,337` TRAIN windows).
    *Indicated category of fix (not built):* decode the pressure value and add **temporal-
    dynamics features** (trend vs. expected, autocorrelation, slope) — CMRI is designed to
    stay within static bounds but creates unnatural *motion* — plus a **supervised model**
    that can weight the entropy signal the unsupervised IF averages away. CMRI is harder
    than NMRI (it mimics normal bounds by design) but has real, measured headroom.
- **VALIDATED — contrast with EXP-0014 (MSCI/MPCI):** MSCI/MPCI are *partly structural* —
  the malicious command payload never crosses the diode, only its physical effect does.
  NMRI/CMRI are **not structural at all**: the malicious content is the egress read
  response. The current ~1–2 % detection is entirely because the pipeline has no feature
  that decodes the response payload value. Combined with healthy class sizes and (for
  NMRI) an obvious cheap bound check, NMRI/CMRI are the clearest "under-investment,
  directly fixable" rows in the per-category review.
- **TESTED — execution record:** pre-EXP-0015 full suite **122 passed**. Added
  `tests/test_exp0015_response_injection_diag.py` = **8 passed** (7 fast stats /
  confusion-arithmetic / cohort-selection tests + 1 `@pytest.mark.slow` gate/direction
  test that calls `run_detector()` as pre-registered). Full suite after: **130 passed
  in ~101 s** (net **+8**). Three slow integration tests now (EXP-0010, EXP-0014,
  EXP-0015); `-m 'not slow'` runs **116 passed, 14 deselected**.
- **LIMITATIONS:** Cohen's d compares aggregate window features and the matched-Normal
  sample controls for slow drift by window index, not every confounder; the forged
  pressure value itself is not a feature so any signal here is its second-order effect on
  frame byte entropy and window frame mix; one testbed; egress-only.
- **STATUS — NMRI / CMRI:** diagnosed, **not fixed**. Both are response-side (no diode
  caveat) and both are feature blindness: the EXP-0004 detector's real detection of the
  forgery is `1.12 %` (NMRI) / `2.34 %` (CMRI); the per-category-table `9.6 % / 12.8 %`
  is the rule layer catching co-occurring MFCI/Recon frames, not response injection.
  NMRI has an obvious cheap fix (decoded-value bound check); CMRI needs decoded-value
  dynamics features + a supervised model. This completes the per-category gap review
  (DoS, MSCI, MPCI, NMRI, CMRI). No fix built or scheduled. **No commit or push
  performed** pending explicit go-ahead.

---

### EXP-0016 · Decoded-pressure out-of-bounds rule for NMRI (first built fix) — 2026-09-10

> **PRE-REGISTRATION — PLANNED.** Recorded before writing any rule or scoring any cohort.
> The decision rule, bounds method, and cohorts are fixed now. **This is the first
> experiment in the per-category review that BUILDS a fix and that MODIFIES the rule
> layer** (`ml/rules.py`) — every prior experiment (EXP-0010, EXP-0014, EXP-0015) was
> additive-only outside the core detector. It follows EXP-0015's diagnosis that NMRI is a
> fully egress-observable response-injection attack whose real detection is only `1.12 %`
> purely because no feature decodes the response pressure value.

- **PLANNED — what NMRI injects (thesis-cited, `docs/00-dataset-provenance.md`):** NMRI
  (`categorized result == 1`) = *Naïve Malicious Response Injection* — "sporadic and out
  of bounds behavior that would not be present in normal operation". Specific attacks:
  `29–31` Random Value ("random pressure measurements are sent to the master"), `32`
  Negative Pressure ("sends back a negative pressure reading from the slave"). Direction:
  response-side / egress only (EXP-0015 measured: every NMRI frame is a `destination == 1`
  `function 0x03` read response). The forged value **is** egress traffic; the diode caveat
  does not apply.
- **PLANNED — pressure decoding (reuse EXP-0009 / EXP-0011a, not reimplemented):** the
  response pressure is the ARFF `pressure measurement` field (data column 13), row-index
  aligned to the TXT and verified by matching `command response == 0` /
  `destination == 1`, timestamp, `categorized result`, and `specific result` — the exact
  alignment `exp0009_payload.align_pretest_pressure` performs. EXP-0016 reuses that
  module's `_arff_data_rows` / `_parse_optional_float` primitives and the same
  row-by-row alignment assertions; it adds only a variant that also retains pressure for
  TEST-block records (the frozen rule is derived from TRAIN-normal and *scored* against
  TEST — no leakage). Pressure is taken only from canonical `0x03` Read Holding Registers
  responses (per EXP-0011a §6.3/§6.12, `0x10` echoes carry no returned value).
- **PLANNED — bounds (NOT documented — derived empirically, TRAIN-normal only):** the
  dataset documentation and thesis give no numeric normal pressure range. The bound is
  therefore **the observed min and max of every `0x03` pressure value in a
  pure-Normal TRAIN window** (`categories == {0}`, TRAIN block per the corrected
  manifest). Pre-checked: `[0.4828, 38.7471]` over `21,384` values; zero negative values
  occur anywhere in the dataset. This is stated as an empirical TRAIN-normal bound, not a
  physical spec. No percentile trimming — the absolute observed range gives the lowest
  new false-positive rate; a percentile variant (`0.1st / 99.9th`) will be reported
  alongside for context but the **min/max bound is the frozen rule**.
- **PLANNED — the rule (`ml/rules.py`, additive):** a new class `PressureBoundsRule`,
  independent of and alongside `DeterministicRuleLayer`, in the same "fit on TRAIN-normal
  → `evaluate` → `RuleHit`" style. `fit(train_normal_pressure_values)` freezes
  `low = min`, `high = max`. `evaluate(window_pressure_min, window_pressure_max)` fires
  (`RuleHit(True, [...])`) iff a window's minimum `0x03` pressure `< low` or its maximum
  `> high`; a window with no `0x03` pressure yields `RuleHit(False, [])`.
  **`DeterministicRuleLayer` — the existing function-code / novel-address checks used for
  MFCI / Recon — is not touched at all.** No existing rule, threshold, or the Isolation
  Forest is modified. A regression test asserts `DeterministicRuleLayer.evaluate` is
  behaviourally unchanged (bad func code, novel address, clean window).
- **PLANNED — identity gates (EXP-0010/0014/0015 discipline):** EXP-0016 reproduces the
  EXP-0004 combined detector in-process and asserts, before scoring: real-TEST `if_pred`
  equals `run_detector().if_pred` element-wise; reproduced threshold equals the frozen
  `0.6745465823488428`; reproduced combined-TEST confusion equals EXP-0004's exact
  `TN 4,771 / FP 36 / FN 3,793 / TP 747`; the split is byte-identical to
  `verified-egress-5s-exp0008-pretest-v1`. `ml/iforest_detector.py` is **not** modified;
  the operational `run_detector` is left frozen and the effect of adding the rule to it is
  *measured and reported*, not applied here.
- **PLANNED — validation cohorts (TEST block; negative class = the `4,807` pure-Normal
  TEST windows throughout):**
  1. **Rule alone** (not combined) vs: (a) pure-NMRI TEST windows — recall; (b)
     pure-Normal TEST windows — new false-positive rate; (c) pure windows of every other
     category (Normal, CMRI, MSCI, MPCI, MFCI, DoS, Recon) — to account for incidental
     help or harm per category, separately.
  2. **Full combined** (EXP-0004 rule OR IF OR `PressureBoundsRule`) vs the same cohorts,
     plus the **whole 9,347-window TEST block** binary attack/Normal confusion, compared
     directly to EXP-0004's frozen `4,771 / 36 / 3,793 / 747` — to state exactly how much
     the operational baseline *would* move if the rule were wired in.
  All rows report precision / recall / F1 / FPR and `TP / FN / FP / TN`.
- **PLANNED — FIXED DECISION RULE (stated before scoring):**
  - **Strong result** = pressure-rule-alone **pure-NMRI TEST recall ≥ 50 %** AND
    pressure-rule-alone **pure-Normal TEST false-positive rate ≤ 0.30 %** (so the combined
    operational FPR stays well under 1 % and rises by at most ~0.3 pp over EXP-0004's
    `0.7489 %` — "not meaningfully worse").
  - **Acceptable** = NMRI recall ≥ 30 % with Normal FP ≤ 0.30 %.
  - **Weak / reconsider** = NMRI recall < 30 %, or Normal FP > 0.30 %.
  - MFCI/Recon-style ~100 % recall is **not** expected here and is not the bar: NMRI's
    "random value" attacks land inside the normal pressure range a meaningful fraction of
    the time, so a value-bound rule has a real ceiling below 100 %.
  - Any incidental change to another category's detection (CMRI, MSCI, …) is reported
    per category and **not** counted toward or against the NMRI bar.
- **PLANNED — explicit baseline-change flag:** if the full combined detector's TEST
  confusion differs from EXP-0004's frozen matrix, EXP-0016 states the exact new matrix
  and the delta, and flags that wiring the rule into `run_detector` would **update
  EXP-0004's frozen baseline** — a larger step than any prior additive-only experiment —
  to be decided separately, not done in EXP-0016.
- **PLANNED — outputs / scope:** new files `ml/exp0016_pressure_bounds_rule.py`,
  `tests/test_exp0016_pressure_bounds_rule.py`, gitignored
  `data/experiments/exp0016_pressure_bounds_rule.json`; plus the additive
  `PressureBoundsRule` in `ml/rules.py`. Do **not** touch `ml/iforest_detector.py`,
  `ml/features_windowed.py`, the existing `DeterministicRuleLayer`, the DoS files
  (EXP-0007…EXP-0013), the MSCI/MPCI diagnostic (EXP-0014), the NMRI/CMRI diagnostic
  (EXP-0015), Layer A, or `app.py`. Run the full suite before and after with exact
  counts. Show the full diff and every result, then wait for explicit go-ahead before any
  commit. No push.
- **PLANNED — known limitation to disclose:** the rule reads the ARFF `pressure
  measurement` value via row alignment, exactly as EXP-0009/0011a did. A real
  PCAP-replay deployment would decode this value from the Modbus `0x03` response payload
  bytes; the register index and scaling factor for that are not documented, so this fix —
  like the EXP-0009/0011 payload work — is validated against the aligned ARFF value and
  its deployment path is a separate open item.

- **IMPLEMENTED — additive rule + isolated experiment:** added
  `rules.PressureBoundsRule` (a new class in `ml/rules.py`, alongside the **unchanged**
  `DeterministicRuleLayer`), `ml/exp0016_pressure_bounds_rule.py`, and
  `tests/test_exp0016_pressure_bounds_rule.py`; JSON gitignored at
  `data/experiments/exp0016_pressure_bounds_rule.json`. `PressureBoundsRule.fit` freezes
  `low = min`, `high = max` of the values it is given; `evaluate(window_min, window_max)`
  fires iff `window_min < low` or `window_max > high`, and returns `RuleHit(False, [])`
  for a window with no `0x03` pressure. `ml/iforest_detector.py`, `ml/features_windowed.py`,
  and the existing `DeterministicRuleLayer` body are untouched; a regression test asserts
  the func-code / novel-address behaviour and the `DeterministicRuleLayer` source are
  unchanged.
- **VALIDATED — gates (all passed before scoring):** reproduced IF `if_pred` equals
  `run_detector().if_pred` element-wise on the real TEST block; reproduced threshold
  equals the frozen `0.6745465823488428`; reproduced combined-detector TEST confusion is
  exactly `TN 4,771 / FP 36 / FN 3,793 / TP 747`; the split is byte-identical to
  `verified-egress-5s-exp0008-pretest-v1`.
- **VALIDATED — bound (derived, TRAIN-normal only):** `[0.4828, 38.7471]` — the observed
  minimum and maximum of every `0x03` read-response pressure value in a pure-Normal
  TRAIN window (`21,384` values). No negative pressure value occurs anywhere in the
  dataset. A percentile variant (`0.1st / 99.9th` = `[0.5172, 34.3820]`) is recorded for
  context; the frozen rule uses min/max because it gives the lowest new false-positive
  rate.

- **VALIDATED — FIXED DECISION RULE: verdict `STRONG`.**
  - pressure-rule-alone **pure-NMRI TEST recall `79.02 %`** (`565/715`) — bar was `≥ 50 %`.
  - pressure-rule-alone **new pure-Normal TEST false positives `4/4,807 = 0.083 %`** — bar
    was `≤ 0.30 %`. (EXP-0004's current Normal FP is `0.749 %`; this rule adds `0.083 pp`.)
  - MFCI/Recon-style `~100 %` was explicitly **not** the bar: `27 %` of NMRI "random
    value" forgeries land inside `[0.4828, 38.7471]` by chance, so a value-bound rule's
    ceiling is `~79 %` here, not `100 %`.

- **VALIDATED — SYNTHETIC-FREE cohort scoring, TEST block (negative class throughout =
  the `4,807` pure-Normal TEST windows):**

  | category | cohort | n⁺ | rule-alone recall | rule-alone precision | EXP-0004 recall | combined+rule recall |
  |---|---|---:|---:|---:|---:|---:|
  | **NMRI** | pure | 715 | **79.02 %** | 99.30 % | 1.12 % | **79.02 %** |
  | **NMRI** | containing / dominant | 1,131 | 75.42 % | 99.53 % | 9.64 % | 76.57 % |
  | **CMRI** | pure | 1,198 | **53.67 %** | 99.38 % | 2.34 % | **54.59 %** |
  | **CMRI** | containing | 1,826 | 53.56 % | 99.59 % | 12.71 % | 60.19 % |
  | **CMRI** | dominant | 1,812 | 53.42 % | 99.59 % | 12.80 % | 60.10 % |
  | MSCI | pure | 322 | 4.04 % | 76.47 % | 0.62 % | 4.66 % |
  | MPCI | pure | 739 | 0.00 % | — | 0.95 % | 0.95 % |
  | MFCI | pure | 227 | 0.00 % | — | 100.00 % | 100.00 % |
  | DoS | pure | 136 | 0.00 % | — | 0.00 % | 0.00 % |
  | Recon | pure | 169 | 0.00 % | — | 100.00 % | 100.00 % |

  - **NMRI (target):** combined-detector real detection goes `1.12 % → 79.02 %` on pure
    windows.
  - **CMRI (incidental, helpful):** `2.34 % → 54.59 %` pure — CMRI forgeries also leave
    the normal range about half the time. Reported, not tuned for.
  - **MSCI (incidental, helpful):** `+13` windows (`0.62 % → 4.66 %` pure) — state changes
    briefly push a real read outside the range. Minor.
  - **MPCI / MFCI / DoS / Recon: unchanged.** The rule fires on `0` of their pure windows;
    MFCI/Recon stay at `100 %` (their func-code rule is untouched). No category is harmed.
  - New pure-Normal TEST false positives: EXP-0004 `36` → combined+rule `40` (`+4`).

- **VALIDATED — EXPLICIT BASELINE-CHANGE FLAG.** `ml/iforest_detector.run_detector` is
  **not** modified in EXP-0016. If `PressureBoundsRule` were wired into the operational
  detector, EXP-0004's frozen whole-TEST-block binary confusion would change:

  | | TN | FP | FN | TP | attack recall | precision | Normal FPR |
  |---|---:|---:|---:|---:|---:|---:|---:|
  | EXP-0004 frozen | 4,771 | 36 | 3,793 | 747 | 16.45 % | 95.40 % | 0.7489 % |
  | + PressureBoundsRule | 4,767 | 40 | 2,166 | **2,374** | **52.29 %** | 98.34 % | 0.8321 % |
  | **delta** | **−4** | **+4** | **−1,627** | **+1,627** | **+35.8 pp** | +2.9 pp | +0.083 pp |

  This is a **much larger step than any prior additive-only experiment** — it would
  supersede EXP-0004's headline TEST numbers (`+1,627` true positives caught, `+4` false
  positives). EXP-0016 stops at *measuring and reporting* this. Wiring it into
  `run_detector` and updating the frozen baseline (and `tests/test_detector.py`'s
  regression constants) is a **separate, explicit decision** — flagged, not taken here.

- **TESTED — execution record:** pre-EXP-0016 full suite **130 passed**. Added
  `tests/test_exp0016_pressure_bounds_rule.py` = **8 passed** (7 fast: `PressureBoundsRule`
  fit/evaluate/guards/batch, `window_pressure_min_max`, confusion arithmetic, **and the
  `DeterministicRuleLayer` behaviour + source regression**; 1 `@pytest.mark.slow`
  end-to-end). Full suite after: **138 passed** (net **+8**). Existing `test_detector.py`
  rule-layer regression tests still pass unchanged — the addition is strictly additive.
- **LIMITATIONS:** the pressure value is the ARFF-aligned `pressure measurement`, exactly
  as EXP-0009/0011a use it; a PCAP-replay deployment would decode it from the `0x03`
  response bytes and that register index / scaling is undocumented — a separate open
  item. The bound is an empirical TRAIN-normal range, not a physical spec. NMRI "random
  value" forgeries inside the normal range are missed (`~21 %`). CMRI / MSCI incidental
  detections are not tuned for. One testbed; egress-only.
- **STATUS — NMRI fix:** **built, validated `STRONG`, not yet operational.**
  `PressureBoundsRule` in `ml/rules.py` catches `79 %` of pure-NMRI TEST windows
  (`1.12 % → 79.02 %`) at `+0.083 pp` Normal FP, plus `~54 %` of CMRI as a bonus.
  Wiring it into `run_detector` would improve EXP-0004's whole-block attack recall
  `16.5 % → 52.3 %` for `+4` false positives — a baseline update flagged for a separate
  decision. **No commit or push performed** pending explicit go-ahead.
# EXP-0017 — PLANNED baseline supersession (2026-09-10)

Pre-registration written before EXP-0017 execution. Human authorization: wire the
pressure rule permanently; one guarded TEST evaluation; reuse saved historical
outputs in the test harness; no commit or push. EXP-0004 is superseded by EXP-0017
as the operational baseline; its original results remain historical comparison,
unaltered. The new benchmark remains PLANNED until the evaluation succeeds.

Exact method: preserve the EXP-0004 IF features, seed 0, 300 trees, TRAIN-normal
standardization and VALIDATION-normal 99th-percentile threshold. Add
PressureBoundsRule permanently to the deterministic-rule OR IF verdict, fitting
finite canonical 0x03 ARFF-row-aligned pressure on TRAIN-normal only using min/max.
Pressure is NOT decoded from live packet bytes; the register map/scale remains
undocumented. This is an offline simulated data-diode view of one testbed.

All memberships use the checksummed manifest
`ml/splits/verified_egress_5s_exp0008_pretest_v1.json`, split ID
`verified-egress-5s-exp0008-pretest-v1`. TRAIN and VALIDATION use exact manifest
bucket IDs; TEST uses eligible buckets after the final manifest VALIDATION bucket,
excluding the first two eligible guard buckets, as in the existing guarded path.
Never derive split fractions from total capture length. Verify raw TXT and ARFF
identity and row alignment. No feature, threshold, bound, or model selection on TEST.

Decision rule fixed in advance: success requires threshold exactly
0.6745465823488428; TRAIN-normal pressure bounds [0.482759, 38.7471] (the
user's 0.4828 lower bound is rounded; exact value read from the saved EXP-0016
artifact before EXP-0017 execution); old-rule OR IF
confusion exactly (4771,36,3793,747) and new operational confusion exactly
(4767,40,2166,2374), in TN/FP/FN/TP order; element-wise new verdict equals old-rule
OR IF OR pressure; all pressure hits have bound explanations. Report dominant
category totals/flags for Normal, MFCI, Recon, NMRI, CMRI, MSCI, MPCI and DoS,
plus pure and containing cohorts for comparison with EXP-0016. These are expected
identity criteria from the user's frozen specification, NOT new observed results.
Failure of any gate is reported without tuning or rescoring TEST.

Execution discipline: first install a saved-output-only historical test adapter and
run the pre-change suite; historical detector-array tests without saved arrays must
be explicitly skipped rather than scored or claimed passed. Preserve exact observed
passed/skipped/failed counts. Run synthetic/pretest checks before TEST. Extend the
existing exact-confirmation gated TEST pattern for EXP-0017 with an exclusive
attempt ledger; even a failed attempt consumes authorization. Persist the single
evaluation's arrays, windows, reasons, identities and category results as JSON with
checksum (no pickle, weights, or raw capture). Subsequent regression tests and
dashboard loads only read that saved result. Historical result replay is artifact
regression, not rerun validation. Run the entire adapted suite after integration,
reporting the exact counts and replay/skip limitations. Do not modify protected
EXP-0005 through EXP-0013 or Layer A files. Show the exact proposed app.py diff
before editing it; show full final diff and actual output before any commit.

## EXP-0017 execution outcome - VALIDATED (2026-09-10)

- **IMPLEMENTED:** PressureBoundsRule is permanently OR-ed into `run_detector()`;
  combined rule hits preserve both protocol and pressure explanations. The default
  entry point rejects unconfirmed scoring. An exclusive attempt ledger protects
  the one authorized TEST evaluation; pytest and Streamlit load its saved JSON.
- **VALIDATED:** one guarded evaluation started at `2026-09-10T15:21:05.683317+00:00`.
  Actual TEST TN=4767, FP=40, FN=2166, TP=2374. Precision
  `0.9834299917149959`; recall `0.5229074889867842`; F1 `0.6827725050330745`;
  Normal FPR `0.008321198252548368`. Threshold `0.6745465823488428`;
  TRAIN-normal pressure extrema `[0.482759, 38.7471]`.
- **VALIDATED:** all seven fixed identity checks passed, including saved EXP-0016
  cohort comparison. Historical protocol OR IF component predictions from this same
  evaluation reproduce TN=4771, FP=36, FN=3793, TP=747; no second scoring run.
  No historical saved IF vector exists for an independent element-wise old/new
  comparison. The new three-way OR composition is checked element-wise.

| Dominant category | Windows | Operational flags | Rate |
|---|---:|---:|---:|
| Normal | 4807 | 40 | 0.832120% FPR |
| MFCI | 227 | 227 | 100% |
| Recon | 169 | 169 | 100% |
| NMRI | 1131 | 866 | 76.569408% |
| CMRI | 1812 | 1089 | 60.099338% |
| MSCI | 324 | 15 | 4.629630% |
| MPCI | 741 | 8 | 1.079622% |
| DoS | 136 | 0 | 0% |

- **TESTED execution record:** first adapted pre-change attempt: **124 passed,
  12 skipped, 2 setup errors**, due to pytest temporary-directory permissions;
  authorized environment retry: **126 passed, 12 skipped**. No historical TEST
  scoring occurred. Twelve tests lacked saved detector arrays; four passing tests
  replayed historical JSON. These counts do not claim a fresh 138-test baseline.
- **TESTED before real scoring:** first synthetic guard/storage/split check run:
  **5 passed, 3 skipped**; after adding the synthetic pipeline leakage check:
  **6 passed, 3 skipped**. Synthetic TEST-tail changes did not alter the fitted
  standardizer, pressure bounds, or threshold. All skipped cases awaited the saved
  real evaluation.
- **TESTED after integration:** full adapted suite **147 passed, 0 skipped,
  0 failed**, in 20.32 seconds. The 12 previously skipped tests now use saved
  arrays; 9 EXP-0017 tests were added. Four historical tests remain saved-summary
  regression, not experimental reruns. Streamlit and all 2,414 alert explanations
  passed with raw capture access blocked by the test harness. See the XML execution
  records and [EXP0017_RESULTS.md](EXP0017_RESULTS.md).
- **VALIDATED supersession:** EXP-0017 is now the headline benchmark. EXP-0004 is
  superseded by EXP-0017, retained for historical comparison. Original historical
  results and protected EXP-0005 through EXP-0013 / Layer A files are unchanged.
- **IMPLEMENTED limitation:** pressure is ARFF-row-aligned, NOT live packet-byte
  decoding. Register map/scale is undocumented; bounds are empirical; one testbed
  and a simulated data-diode view. Pure/dominant DoS still has zero flags; mixed
  containing cohorts are not evidence of detecting their named attack.
- Full measured cohorts, raw/source identities, and local saved-artifact links:
  [EXP0017_RESULTS.md](EXP0017_RESULTS.md), [exp0017_results.json](exp0017_results.json).
  No commit, staging, or push performed.

# EXP-0018 — PLANNED — residual-smoothness test for the CMRI forgeries EXP-0017 misses (2026-09-10)

Pre-registration written before any EXP-0018 scoring. Diagnostic-then-build, same
discipline as EXP-0014/0015/0016: build a new detector, measure it standalone and
OR-ed into a reproduced EXP-0017 combined detector, and DO NOT modify
`ml/iforest_detector.run_detector`. New files only
(`ml/exp0018_pressure_residual_smoothness.py`, its test). No change to `app.py`,
DoS files, MSCI/MPCI files, Layer A, or protected EXP-0005..EXP-0013.

## Hypothesis (external research — to be tested here, NOT assumed)

A signal forged to mimic a real sensor is often *less* noisy than the genuine
process, because real physical fluctuation is hard to fake. If so, a segment of
smooth CMRI response-value injection that stays inside the EXP-0016 pressure bounds
should still show **suppressed one-step prediction residuals** relative to
TRAIN-normal. Two-sided: abnormally LOW residual energy (over-smooth forgery) and
abnormally HIGH residual energy (noisy forgery / instability) are tested as
SEPARATE hypotheses, each calibrated against TRAIN-normal's own residual-energy
distribution — not one symmetric threshold assumed without checking the shape.

## Structural constraint found at pre-registration (measurement, not outcome)

Egress `0x03` read-response pressure cadence is ~1–2 samples per 5 s window
(TRAIN-normal: 14,951 windows, 21,384 finite pressure samples; median 1, max 2 per
window). A within-window variance / autocorrelation test is therefore impossible.
CMRI attack episodes are long contiguous runs (median ~16 windows; 425 of the 544
previously-missed pure-CMRI windows lie in runs of ≥6). The predictor and the
residual-energy statistic are therefore defined over the **global chronological
sequence of individual `0x03` responses**, with a causal rolling window that spans
multiple 5 s windows. User approved this adaptation on 2026-09-10.

## Exact method (fixed before running)

1. **Pressure sequence.** `exp0016_pressure_bounds_rule.align_egress_pressure`
   (row-index-aligned ARFF `pressure measurement`, verified TXT/ARFF sha256,
   canonical 0x03 read responses only). Global sample order = ascending 5 s bucket,
   then within-bucket append (file) order. Each sample keeps its bucket id.
2. **Blocks.** From the checksummed manifest
   `ml/splits/verified_egress_5s_exp0008_pretest_v1.json` exactly as EXP-0017:
   TRAIN / VALIDATION = manifest bucket ids; TEST = buckets after
   `final_pretest_bucket_id`, dropping the first `2 * GUARD_WINDOWS` eligible
   buckets. TRAIN-normal = TRAIN buckets whose `build_windows` window has
   `is_attack == 0`.
3. **Predictor — AR(1), fit on TRAIN-normal samples only.**
   `mu` = mean of TRAIN-normal values; `phi` = lag-1 Yule-Walker coefficient
   `Σ(x[t-1]-mu)(x[t]-mu) / Σ(x[t-1]-mu)²` over globally-consecutive sample pairs
   whose BOTH members are TRAIN-normal. Prediction `x̂[t] = mu + phi·(x[t-1]-mu)`;
   residual `r[t] = x[t] - x̂[t]` for every global sample with a predecessor.
   `sigma` = population std of TRAIN-normal `r[t]`. Standardised `z[t] = r[t]/sigma`.
   The naive persistence residual (`phi := 1`) is computed and reported for context
   only; the frozen detector uses fitted `phi`.
4. **Rolling residual energy per 5 s window.** `K = 15` samples (≈ the median
   11-window / ~55 s span; smallest causal window giving n ≥ 10 for a stable
   variance estimate while staying inside the median CMRI episode). For window with
   bucket `b`, let `j` = global index of the last sample in `b`;
   `E_b = mean(z[j-K+1 .. j]²)` (mean squared standardised residual). Windows with
   fewer than `K` preceding samples get `E_b = None` and cannot be flagged (same
   fail-safe as `PressureBoundsRule` with no 0x03 pressure). The rolling window is
   strictly causal (backward-looking); a TEST window's context may include
   VALIDATION/guard samples — that is context, not a label, and is disclosed.
5. **Two-sided calibration.** Calibration set = TRAIN-normal windows whose entire
   `K`-sample causal window lies within TRAIN-normal buckets. On that set:
   `low_thr = quantile(E, 0.005)`, `high_thr = quantile(E, 0.995)` (nominal 1%
   two-sided, matching the IF's 1% VALIDATION-normal FPR target). Report the
   calibration median, both quantiles and the skew so the asymmetry is visible
   rather than assumed. Detector fires iff `E_b < low_thr` (reason
   `residual_energy_low`) OR `E_b > high_thr` (reason `residual_energy_high`).
   low-only and high-only variants are also reported.
6. **Identity gate before any scoring.** Load the checksummed EXP-0017 artifact via
   `exp0017_operational.load_result` (re-verifies every tracked source sha256, the
   envelope checksum, manifest identity and the VALIDATED status). Confirm
   `comb_pred == protocol_pred | pressure_pred | if_pred` element-wise and whole-TEST
   confusion `(4767, 40, 2166, 2374)`. `run_detector` is NOT called (its attempt is
   consumed by design). Abort if any gate fails.

## Evaluation cohort (explicit)

The experiment's success is judged ONLY on **CMRI-labelled TEST windows the
EXP-0017 combined detector does NOT already flag** (`comb_pred == 0`). Windows
EXP-0017 already catches earn this experiment no credit. "New detection" =
flagged by the residual-smoothness detector AND `comb_pred == 0`. Primary cohort:
`pure` (`categories ⊆ {0, CMRI}`); `dominant` and `containing` also reported.

## Fixed decision rule

Let `new_recall` = new-detections / previously-missed pure-CMRI windows (that have a
defined `E_b`); `new_normal_fp_rate` = residual detector's flags on pure-Normal TEST
windows / pure-Normal TEST windows; `combined_precision` = precision of
(EXP-0017 comb_pred OR residual detector) over all 9,347 TEST windows.

- **STRONG** — `new_recall ≥ 0.25` AND `new_normal_fp_rate ≤ 0.0030` AND
  `combined_precision ≥ 0.970`.
- **ACCEPTABLE** — `new_recall ≥ 0.10` AND `new_normal_fp_rate ≤ 0.0030` AND
  `combined_precision ≥ 0.970`.
- **WEAK / HYPOTHESIS NOT SUPPORTED** — otherwise.

Independent of any threshold, also report the **Mann–Whitney U** test of
`E_b` for previously-missed pure-CMRI vs pure-Normal TEST windows (two-sided, with
U and p), and the median/IQR of `E_b` for missed-pure-CMRI, pure-Normal TEST and
the TRAIN-normal calibration set. Signal is called "present" only if
p < 0.01 AND missed-CMRI energy is lower (one-sided direction of the hypothesis).
A significant result in the WRONG direction, or a non-significant one, is reported
as the hypothesis failing on this dataset.

## No-regression checks (reported)

NMRI / MFCI / Recon `pure` recall for EXP-0017 combined vs (combined OR residual):
an OR can only add flags, so the honest checks are (a) `new_normal_fp_rate` bar
above and (b) whole-TEST-block confusion delta with `combined_precision ≥ 0.970`.
Both are gated. Also report the residual detector's standalone
recall/precision/F1/FPR on NMRI/MFCI/Recon `pure` and on the whole attack class,
for context.

## Outputs

`data/experiments/exp0018_pressure_residual_smoothness.json` (atomic write, JSON
only, no pickle/weights/raw bytes): method constants, `phi`, `sigma`,
`low_thr`/`high_thr` and calibration shape, the identity-gate results, per-cohort
confusions (residual-alone / EXP-0017-combined / combined+residual), the
distributional test, the whole-block confusion delta, the decision-rule verdict,
and limitations. A Markdown summary is printed. `run_detector` unchanged; wiring is
a separate decision if the verdict warrants it (EXP-0016 → EXP-0017 pattern).

## Tests

New `tests/test_exp0018_pressure_residual_smoothness.py`: fast synthetic units for
the AR(1) fit, the rolling-energy statistic, the two-sided calibration and the
decision-rule arithmetic (no raw data); one `@pytest.mark.slow` test that loads the
saved `exp0018_*.json` and asserts structure + recorded identity gates + the
decision rule (skips if the artifact is absent; never reads raw data, so it runs
under the EXP-0017 `open()` guard without a conftest change). Full suite before:
**147 passed**. After: report exact counts.

## EXP-0018 execution outcome — TESTED — HYPOTHESIS NOT SUPPORTED (2026-09-10)

The pre-registered method ran once against the frozen EXP-0017 saved output. The
smoothness hypothesis does **not** hold for this dataset's CMRI, and the
pre-registered decision rule returns **WEAK / HYPOTHESIS NOT SUPPORTED**.

- **IDENTITY GATES (passed).** `exp0017_operational.load_result` verified every
  tracked source sha256, the envelope checksum, the manifest identity and the
  VALIDATED status. `comb_pred == protocol_pred | pressure_pred | if_pred`
  element-wise; whole-TEST confusion `(4767, 40, 2166, 2374)`. `run_detector` was
  not called. No drift.
- **MODEL.** AR(1) on TRAIN-normal 0x03 pressure: `mu = 8.2792`, `phi = 0.99031`,
  residual `sigma = 0.8546` (14,951 TRAIN-normal windows; 21,384 TRAIN-normal
  pressure samples; 68,848 global 0x03 samples). `K = 15`. TRAIN-normal rolling
  energy is extremely right-skewed: median `0.0077`, 0.5% quantile `0.0002`,
  99.5% quantile `24.8143` (n = 9,995 calibration windows).
- **SIGNAL TEST — NOT SUPPORTED, and significant in the WRONG direction.**
  Mann–Whitney U on rolling energy, previously-missed pure-CMRI vs pure-Normal
  TEST: `U = 1,905,977`, `p = 9.35e-69`. Median energy: missed pure-CMRI
  **9.749**, pure-Normal TEST 0.0081, TRAIN-normal 0.0077. The missed CMRI
  windows that carry a pressure signal are **noisier** than normal, not smoother.
  `missed_cmri_energy_lower_than_normal = False`.
- **NEW DETECTIONS on the 544 previously-missed pure-CMRI windows** (defined
  energy): two-sided rule 257 (47.24%); **low-energy / over-smooth variant only
  14 (2.57%)** — the hypothesised mechanism is essentially absent; high-energy
  variant 243 (44.67%). dominant / containing cohorts: 43.98% / 44.02% two-sided,
  ~1.9% low-only.
- **UNUSABLE OPERATING POINT.** Two-sided rule flags **570 / 4,807 = 11.86%** of
  pure-Normal TEST windows (bar ≤ 0.30%; ~40× over). Combined precision
  (comb OR residual) falls to **82.99%** (bar ≥ 97.0%). Whole-block delta
  (TN, FP, FN, TP) = `(-563, +563, -568, +568)`.
- **WHY IT FAILS (diagnostic, no method change).** Not a sampling-gap artifact:
  high-energy Normal windows have median max bucket-gap 1. Genuine normal egress
  pressure has legitimate large step changes; with `sigma = 0.85` any real move is
  a large standardised residual, so ~11% of Normal windows carry a high-energy
  rolling segment. The AR(1)-residual-energy statistic does not separate normal
  from attack on this data and does not transfer TRAIN→TEST at a usable quantile.
- **NO REGRESSION (measurement only).** `run_detector` unchanged; NMRI / MFCI /
  Recon `pure` cohorts unaffected in the EXP-0017 detector. An OR with this rule
  would only add flags, but at the cost above — it is not wired in and, on this
  verdict, should not be.
- **TESTED.** Full suite **156 passed, 0 skipped, 0 failed** (was 147; +9 EXP-0018
  tests — 8 fast synthetic units + 1 slow saved-result replay). No raw data read
  in pytest. Saved result:
  [exp0018_pressure_residual_smoothness.json](../data/experiments/exp0018_pressure_residual_smoothness.json),
  summary [EXP0018_RESULTS.md](EXP0018_RESULTS.md).
- **CONCLUSION.** The external-research idea ("forgeries are unnaturally smooth")
  is a reasonable prior but is **not supported** for CMRI in this testbed: the
  detectable pressure deviation in the missed cases is excess residual energy, not
  suppressed residual energy, and no calibration of this statistic clears the
  false-positive bar. EXP-0018 is closed as a negative result. `run_detector`,
  `app.py` and all protected files are unchanged.

# EXP-0019 — PLANNED — physical rate-of-change plausibility test for missed CMRI (2026-09-10)

Pre-registration written before any EXP-0019 scoring. Diagnostic-then-build,
measurement only, same discipline as EXP-0016 / EXP-0018. `run_detector`, `app.py`,
DoS / MSCI / MPCI files, Layer A, protected EXP-0005..EXP-0018 and every EXP-0018
file are NOT touched. New files only
(`ml/exp0019_pressure_rate_plausibility.py`, its test,
`data/experiments/exp0019_pressure_rate_plausibility.json`, `docs/EXP0019_RESULTS.md`).

## Hypothesis (tested here — not assumed)

A real physical process has a maximum plausible RATE of pressure change: a valve or
pump moves pressure only so fast. A forged CMRI injection that jumps the reported
value may exceed what is physically achievable in the elapsed real time since the
last reading — even when the value itself is inside the EXP-0016 bounds and even
when the raw jump *size* resembles a legitimate large swing. This differs from
EXP-0018: EXP-0018 tested residual energy against a fixed-variance AR(1) model and
ignored elapsed time; EXP-0019 tests `|Δpressure| / Δt` against the empirical
TRAIN-normal rate distribution, using the real inter-sample time.

## Timing structure (reused from EXP-0007/0008, re-confirmed, not re-derived)

Raw TXT timestamps are **strictly monotonic non-decreasing** over all 274,628
records (0 inversions, 0 non-positive steps). Egress `0x03` read responses
(`function_code=0x03, frame_len=23, is_request=0`) number 68,848; consecutive
`Δt` median **3.39 s**, ~93% within ±15 % of one cadence, with a characterised
minority of gaps: ~4.8 % at ≈3× cadence (~10 s) and ~2 % at ≈4× (~13.6 s), almost
none at 2×. EXP-0007's per-stream `0x03` IAT audit found mean 3.49 s, CV 0.046.
So elapsed time is cleanly available and near-regular; dividing by the true `Δt`
naturally makes a jump across a gap more plausible than the same jump in one step.

## Exact method (fixed before running)

1. **Time series.** A new `align_egress_pressure_timeseries()` reuses the
   `exp0009_payload` primitives and the EXP-0016 verification loop (both raw
   sha256, per-row direction/timestamp/category/specific check) but keeps
   `(timestamp, pressure)` for every egress canonical `0x03` response. Global order
   = ascending timestamp (already monotonic). Non-finite pressures dropped.
2. **Blocks.** Identical construction to EXP-0018 (`Blocks`): manifest
   `verified_egress_5s_exp0008_pretest_v1.json` TRAIN/VALIDATION bucket ids; TEST =
   buckets after `final_pretest_bucket_id` minus the first `2*GUARD_WINDOWS`.
   TRAIN-normal = TRAIN buckets whose `build_windows()` window is not attack.
3. **Rate feature.** For consecutive samples `(i-1, i)` in the global sequence with
   `Δt = t_i - t_{i-1} > 0`: `rate_i = |p_i - p_{i-1}| / Δt`. Pairs with `Δt <= 0`
   are impossible here (monotonic) but are dropped defensively.
4. **Plausibility bound — from TRAIN-normal only.** Reasoning: the register
   map/scale is undocumented, so no engineering `dP/dt` limit can be derived; but
   TRAIN-normal already contains the real process's fastest legitimate valve/pump
   transitions over ~14,951 normal windows. The bound is therefore the empirical
   upper tail of the TRAIN-normal `rate` distribution. Primary cutoff =
   **TRAIN-normal 99.9th percentile** (`method="linear"`): over ~21k normal pairs
   this drops the ~20 most extreme steps, robust to logging artefacts / the 13
   sub-cadence pairs, while still representing "as fast as the process was ever
   credibly seen to move". The TRAIN-normal **max** and **99.99th** are also
   computed and a stricter `max`-bound variant is reported. A round "k·σ" bound is
   explicitly rejected — EXP-0018 showed this statistic is too heavy-tailed for a
   Gaussian scale to transfer.
5. **Per-window verdict.** `rate_w` = the maximum `rate_i` over pairs whose later
   sample `i` falls in window `w` (a single implausibly fast jump is the signal;
   averaging would dilute it). Undefined (not flaggable) if `w` contains no such
   pair. Fire iff `rate_w > cutoff`. No rolling window (the hypothesis is about one
   step), so no `K`.
6. **Identity gate (before any score).** `exp0017_operational.load_result`
   re-verifies every tracked source sha256, the envelope checksum, the manifest
   identity and the VALIDATED status. Confirm
   `comb_pred == protocol_pred | pressure_pred | if_pred` element-wise and whole-TEST
   confusion `(4767, 40, 2166, 2374)`. `run_detector` is NOT called. Abort on any
   failure.

## Evaluation cohort (same discipline as EXP-0018)

Judged ONLY on **CMRI-labelled TEST windows with EXP-0017 `comb_pred == 0`** and a
defined `rate_w`. "New detection" = rate rule fires AND `comb_pred == 0`. Primary
cohort `pure` (`categories ⊆ {0, CMRI}`); `dominant` and `containing` also reported.

## Fixed decision rule

`new_recall` = new detections / previously-missed pure-CMRI windows with defined
rate. `new_normal_fp_rate` = rate-rule flags on pure-Normal TEST / pure-Normal TEST.
`combined_precision` = precision of (`comb_pred` OR rate rule) over all 9,347 TEST
windows.

- **STRONG** — `new_recall ≥ 0.25` AND `new_normal_fp_rate ≤ 0.0030` AND
  `combined_precision ≥ 0.970`.
- **ACCEPTABLE** — `new_recall ≥ 0.10` AND same two bars.
- **WEAK / HYPOTHESIS NOT SUPPORTED** — otherwise.

Justification (reconsidered, not copied): the FP bar `0.30%` is the project-wide
tolerance for a new OR-ed rule set at EXP-0016 — EXP-0017's Normal FPR is 0.83 %, so
a rule adding more than ~0.30 % would materially degrade headline precision. The
precision floor `97.0 %` allows ≤ ~1.3 pp erosion from EXP-0017's 98.34 %. The
recall bars: 25 % of the 544 missed pure-CMRI = ~136 windows, which would lift
pure-CMRI combined recall ~54.6 % → ~66 % (clearly worth wiring in); below 10 %
(~54 windows, ~58 %) the added rule is not worth its maintenance and false-positive
surface. These bars are structurally identical to EXP-0018 and remain the right
ones — the cohort and the "worth wiring in?" question are unchanged.

Threshold-independent: **Mann–Whitney U**, `rate_w` for previously-missed pure-CMRI
vs pure-Normal TEST windows (two-sided, report U and p, α = 0.01). This hypothesis
predicts missed-CMRI rate is **higher**; signal is "present" only if `p < 0.01` AND
missed-CMRI median rate > Normal median rate. A null result, or a significant result
in the wrong direction, is reported as the hypothesis failing.

## No-regression / context (reported)

Residual rate rule standalone recall/precision/F1/FPR on the missed-CMRI cohort,
pure-Normal TEST, and NMRI / MFCI / Recon `pure`; whole-TEST-block confusion delta
if OR-ed in. `run_detector` unchanged; an OR only adds flags.

## Outputs and tests

`data/experiments/exp0019_pressure_rate_plausibility.json` (atomic, JSON only):
method constants, the TRAIN-normal rate percentiles and chosen cutoff(s), identity
gates, per-cohort confusions (rate-alone / EXP-0017-combined / combined+rate), the
distributional test, the whole-block delta, the verdict, limitations.
New `tests/test_exp0019_pressure_rate_plausibility.py`: fast synthetic units
(rate feature, per-window max aggregation, TRAIN-normal cutoff, decision-rule
arithmetic, monotonic-Δt handling, measurement-only source check) + one
`@pytest.mark.slow` saved-result replay (no raw read; skips if absent).
Full suite before: **156 passed**. After: report exact counts.

## EXP-0019 execution outcome — TESTED — HYPOTHESIS NOT SUPPORTED (pre-registered rule); signal confirmed (2026-09-10)

The pre-registered method ran once against the frozen EXP-0017 saved output. The
pre-registered decision rule returns **WEAK / HYPOTHESIS NOT SUPPORTED** — but,
unlike EXP-0018, the underlying signal is real and points the hypothesised way, and
the false-positive failure is dominated by an identified artifact. This is a
near-miss, not a flat negative.

- **IDENTITY GATES (passed).** `exp0017_operational.load_result` verified every
  tracked source sha256, the envelope checksum, the manifest identity and the
  VALIDATED status. `comb_pred == protocol_pred | pressure_pred | if_pred`
  element-wise; whole-TEST confusion `(4767, 40, 2166, 2374)`. `run_detector` not
  called. No drift.
- **TIMING (re-confirmed).** TXT timestamps strictly monotonic. 68,848 egress
  `0x03` samples; 20,803 TRAIN-normal consecutive step-rate pairs.
- **CUTOFF.** TRAIN-normal `|Δp|/Δt` percentiles: p50 `0.0035`, p99 `1.1380`,
  p99.9 `2.1217`, p99.99 `3.5977`, max `4.2197`. Primary cutoff = p99.9 = `2.1217`;
  strict variant = TRAIN-normal max = `4.2197`.
- **SIGNAL TEST — PRESENT, and in the hypothesised direction (unlike EXP-0018).**
  Mann–Whitney U on `rate_w`, previously-missed pure-CMRI vs pure-Normal TEST:
  `U = 1,614,883`, `p = 2.07e-19`. Median `rate_w`: missed pure-CMRI **0.0139**,
  pure-Normal TEST 0.0067, TRAIN-normal steps 0.0035.
  `missed_cmri_rate_higher_than_normal = True`.
- **RECALL BAR — passed.** New detections on the 544 previously-missed pure-CMRI
  windows: **145 (26.65 %)** at the p99.9 cutoff (117 / 21.51 % at the strict max
  cutoff). dominant / containing: 25.86 % / 26.00 % (p99.9).
- **FP BAR — failed.** Rate rule flags **45 / 4,807 = 0.936 %** of pure-Normal TEST
  windows (bar ≤ 0.30 %; ~3× over). Strict max cutoff: 21 / 4,807 = 0.437 % (still
  over).
- **PRECISION FLOOR — failed (barely).** Combined precision (comb OR rate)
  **96.945 %** vs the 97.0 % floor. Whole-block delta (TN, FP, FN, TP) =
  `(-43, +43, -260, +260)`: +260 TP for +43 FP. The strict max cutoff clears the
  precision floor (97.71 %) but not the FP bar.
- **FALSE POSITIVES ARE MOSTLY AN ARTIFACT.** Of the 45 pure-Normal FPs, **35** are
  a window whose max-rate pair steps DOWN from a predecessor window that EXP-0017
  already flags or that is attack-labelled — the rule crediting a Normal window for
  pressure *returning to normal* after an anomaly, not for its own behaviour.
  Residual FP after excluding those: **10 / 4,807 = 0.208 %**, which would clear the
  0.30 % bar. (Diagnostic only — the pre-registered rule is NOT changed or rescored.)
- **CONTEXT.** The rate rule is a "large fast jump" detector: standalone it also
  catches NMRI pure 144 / 715 = 20.1 % at 76.2 % precision; whole attack class
  24.9 % recall / 96.2 % precision. MFCI / Recon essentially untouched.
- **VERDICT.** Pre-registered decision rule → **WEAK / HYPOTHESIS NOT SUPPORTED**
  (fails FP bar and precision floor). But the hypothesis is directionally confirmed
  and the dominant FP mechanism is specific and likely fixable.
- **RECOMMENDATION.** This earns a follow-up **EXP-0020** with a FRESH
  pre-registration and a refined per-window rate statistic — e.g. attribute a jump
  only to the window it enters from an in-bounds / unflagged predecessor, or score
  only the transition into an episode. Do NOT tweak-and-rescore EXP-0019 against the
  same TEST. Nothing is wired into `run_detector()`.
- **TESTED.** Full suite **164 passed, 0 skipped, 0 failed** (was 156; +8 EXP-0019
  tests — 7 fast synthetic units + 1 slow saved-result replay). No raw data read in
  pytest. Saved result:
  [exp0019_pressure_rate_plausibility.json](../data/experiments/exp0019_pressure_rate_plausibility.json),
  summary [EXP0019_RESULTS.md](EXP0019_RESULTS.md). `run_detector`, `app.py` and all
  protected / EXP-0018 files unchanged.

# EXP-0020 — PLANNED — refined rate-of-change rule with an in-bounds-predecessor gate (2026-09-10)

Pre-registration written before any EXP-0020 scoring. Direct follow-up to EXP-0019,
recommended in EXP-0019's own logs. Diagnostic-then-build, measurement only, same
discipline as EXP-0016 / EXP-0018 / EXP-0019. `run_detector`, `app.py`, DoS / MSCI /
MPCI files, Layer A, and protected EXP-0005..EXP-0019 (including every EXP-0018 and
EXP-0019 file) are NOT touched. New files only
(`ml/exp0020_pressure_rate_gated.py`, its test,
`data/experiments/exp0020_pressure_rate_gated.json`, `docs/EXP0020_RESULTS.md`).

## What EXP-0019 established, and what EXP-0020 changes

EXP-0019 tested `rate_w = |Δp|/Δt` (max step rate into a 5 s window) against a
TRAIN-normal 99.9th-percentile bound. The signal was real and in the hypothesised
direction (missed pure-CMRI median `rate_w` 0.0139 vs Normal 0.0067; Mann–Whitney
p = 2.07e-19) and recall passed (26.65 % of the 544 missed pure-CMRI), but the rule
failed the false-positive bar (0.936 %) and precision floor (96.945 %). **35 of the
45 pure-Normal false positives** were a window inheriting a large rate from a pair
that steps DOWN out of a preceding anomalous window — the rule crediting a Normal
window for pressure *returning to normal* after an anomaly. Residual FP excluding
that mechanism: 10 / 4,807 = 0.208 %.

EXP-0020 keeps the feature and the calibration approach and adds ONE change: a
**predecessor-eligibility gate** so a jump is only scored when its earlier sample
is a plausible baseline.

## Exact predecessor-eligibility rule (stated before scoring)

Reuse the EXP-0016 frozen TRAIN-normal pressure bounds
`[BOUND_LOW, BOUND_HIGH] = [0.482759, 38.7471]`, taken from the checksum-verified
EXP-0017 artifact (`load_result().pressure_bounds`) — not re-derived.

A consecutive sample pair `(i-1, i)` in the global egress `0x03` sequence is
**eligible** for rate scoring iff:

1. `Δt = t_i - t_{i-1} > 0` (always true here — monotonic timestamps), AND
2. `BOUND_LOW <= p_{i-1} <= BOUND_HIGH` — the **earlier** sample's pressure is
   within the frozen EXP-0016 bounds.

Only the earlier sample is constrained. The later sample `p_i` is deliberately
NOT constrained: the whole hypothesis is that a forgery can land *inside* the
bounds yet move there too fast. A pair whose earlier sample is out of bounds is
dropped (not scored); if that was a window's only pair, its `rate_w` is undefined
(not flaggable), exactly as in EXP-0019.

This is self-contained (a frozen value test, no dependence on EXP-0017's per-window
output). An alternative "earlier window `comb_pred == 0`" gate and an
"episode-entry transitions only" restriction were considered and rejected: the
first couples a standalone rule to the operational detector's verdict; the second
needs an "episode" definition that would require labels or the same flag coupling.

## Method (otherwise identical to EXP-0019)

1. **Time series.** `align_egress_pressure_timeseries()` — same as EXP-0019
   (reused, imported from `exp0019_pressure_rate_gated` is NOT allowed since
   EXP-0019 files are frozen; EXP-0020 re-implements the same verified alignment
   loop, or imports the pure function from `exp0019_pressure_rate_plausibility`
   read-only without modifying it — the module will `from
   exp0019_pressure_rate_plausibility import align_egress_pressure_timeseries,
   bucket_of, Blocks, confusion, classify_verdict` and add only the gate).
2. **Blocks / cohort / identity gate.** Identical to EXP-0019: manifest
   `verified_egress_5s_exp0008_pretest_v1.json`; TRAIN-normal from `build_windows`;
   EXP-0017 reproduced via `load_result` (all source sha256 + envelope checksum +
   manifest + VALIDATED), `comb_pred == protocol_pred | pressure_pred | if_pred`
   element-wise, whole-TEST `(4767, 40, 2166, 2374)`; `run_detector` NOT called.
3. **Rate feature.** `rate_i = |p_i - p_{i-1}| / Δt` over **eligible** pairs only.
   `rate_w` = max eligible step rate over pairs whose later sample lands in window
   `w`; undefined if no eligible pair.
4. **Plausibility bound — re-calibrated on the gated feature.** TRAIN-normal
   `rate` over eligible pairs whose BOTH endpoints are in TRAIN-normal buckets.
   Primary cutoff = **99.9th percentile**; strict variant = TRAIN-normal max.
   Report p50/p90/p99/p99.9/p99.99/max. `k·σ` rejected (EXP-0018 heavy tail).
5. **Per-window verdict.** Fire iff `rate_w > cutoff`.

## Evaluation cohort

Identical to EXP-0019: **CMRI-labelled TEST windows with EXP-0017 `comb_pred == 0`**
and a defined gated `rate_w`. "New detection" = rate rule fires AND `comb_pred == 0`.
Primary `pure`; `dominant` and `containing` also reported. Report how many
previously-missed pure-CMRI windows LOSE a defined `rate_w` under the gate (i.e. the
gate's cost in coverage).

## Fixed decision rule (unchanged from EXP-0019 — same cohort, same question)

`new_recall` = new detections / previously-missed pure-CMRI windows with a defined
gated rate. `new_normal_fp_rate` = gated-rate-rule flags on pure-Normal TEST /
pure-Normal TEST. `combined_precision` = precision of (`comb_pred` OR gated rate
rule) over all 9,347 TEST windows.

- **STRONG** — `new_recall ≥ 0.25` AND `new_normal_fp_rate ≤ 0.0030` AND
  `combined_precision ≥ 0.970`.
- **ACCEPTABLE** — `new_recall ≥ 0.10` AND same two bars.
- **WEAK / HYPOTHESIS NOT SUPPORTED** — otherwise.

Threshold-independent: **Mann–Whitney U**, gated `rate_w` for previously-missed
pure-CMRI vs pure-Normal TEST (two-sided, U + p, α = 0.01); "present" only if
`p < 0.01` AND missed-CMRI median > Normal median.

Also report, to confirm the gate did its job: the EXP-0019
boundary-artifact diagnostic re-run on the gated rule (count of pure-Normal FPs
whose max-rate pair steps from an EXP-0017-flagged / attack predecessor window —
expected to drop toward 0), and the EXP-0019 → EXP-0020 change in new detections and
in pure-Normal FP.

## Honest-disclosure note (multiple TEST scorings)

EXP-0018, EXP-0019 and now EXP-0020 have each scored the frozen TEST set once
against a pressure-derived hypothesis about the CMRI EXP-0017 misses. Each is a
distinct pre-registered method with its decision rule fixed in advance, but the
iterative refinement across experiments is a garden-of-forking-paths risk. A
genuinely held-out confirmation of any positive EXP-0020 result would require data
not used here. This is stated now, before scoring.

## Outputs and tests

`data/experiments/exp0020_pressure_rate_gated.json` (atomic, JSON only): the
eligibility rule and bounds used, TRAIN-normal gated-rate percentiles and cutoff(s),
identity gates, per-cohort confusions (gated-rate-alone / EXP-0017-combined /
combined+gated-rate), the distributional test, the boundary-artifact re-check, the
EXP-0019 deltas, the whole-block delta, the verdict, limitations.
New `tests/test_exp0020_pressure_rate_gated.py`: fast synthetic units (the
eligibility gate, gated rate feature, per-window max, cutoff, decision-rule
arithmetic, measurement-only source check) + one `@pytest.mark.slow` saved-result
replay (no raw read; skips if absent). Full suite before: **164 passed**. After:
report exact counts.

## EXP-0020 execution outcome — TESTED — pre-registered rule NOT SUPPORTED; gate validated the EXP-0019 diagnosis; a strict-cutoff variant reaches ACCEPTABLE (2026-09-10)

The pre-registered method ran once against the frozen EXP-0017 saved output.

- **IDENTITY GATES (passed).** EXP-0017 reproduced via `load_result` (all source
  sha256 + envelope checksum + manifest + VALIDATED). `comb_pred == protocol_pred |
  pressure_pred | if_pred` element-wise; whole-TEST `(4767, 40, 2166, 2374)`.
  EXP-0016 bounds `[0.482759, 38.7471]` read from the artifact. `run_detector` not
  called.
- **THE GATE IS A NO-OP ON TRAIN-NORMAL.** The EXP-0016 bounds ARE the TRAIN-normal
  pressure min/max, so every TRAIN-normal step pair already has an in-bounds
  predecessor: 20,803 eligible pairs (identical to EXP-0019), cutoff unchanged
  (p99.9 = `2.1217`, max = `4.2197`). The gate only changes TEST scoring.
- **THE GATE DID WHAT IT WAS DESIGNED TO DO.** EXP-0019 → EXP-0020:
  pure-Normal FP **45 → 18**; boundary-artifact FP (max-rate pair steps from a
  flagged/attack predecessor window) **35 → 8**; combined precision
  **96.945 % → 97.773 %** (now clears the 97.0 % floor).
- **BUT THE RECALL COST IS HEAVY.** New detections on missed pure-CMRI
  **145 → 64**; and 84 previously-missed pure-CMRI windows lose every eligible pair
  under the gate (their pressure steps come FROM out-of-bounds values), so the
  cohort denominator drops **544 → 460**. New pure-CMRI recall
  **26.65 % → 13.91 %** at the primary p99.9 cutoff.
- **SIGNAL TEST — still PRESENT, hypothesised direction, but much weaker.**
  Mann–Whitney U on gated `rate_w`, missed pure-CMRI vs pure-Normal:
  `U = 1,215,680`, `p = 1.84e-4` (was 2.07e-19 ungated). Median gated `rate_w`:
  missed pure-CMRI **0.0089**, Normal 0.0067, TRAIN-normal 0.0035. Removing the
  boundary jumps removed most of the signal strength too.
- **PRE-REGISTERED PRIMARY (p99.9) VERDICT — WEAK / HYPOTHESIS NOT SUPPORTED.**
  new recall 13.91 % (clears the 10 % ACCEPTABLE recall threshold, not the 25 %
  STRONG one); new pure-Normal FP **0.3745 %** (18 / 4,807) — still over the
  0.30 % bar, by ~4 windows; combined precision 97.773 % (clears the floor).
  Fails on the FP bar.
- **SECONDARY — strict TRAIN-normal-max cutoff → ACCEPTABLE.** new recall
  **12.17 %** (56 / 460), new pure-Normal FP **0.0832 %** (4 / 4,807), combined
  precision **98.239 %**. `classify_verdict` → **ACCEPTABLE**. Whole-block delta at
  this cutoff is not separately tabled here; at the primary cutoff it is
  `(TN −17, FP +17, FN −129, TP +129)`.
- **CONTEXT.** Standalone the gated rule (p99.9) catches NMRI pure 46 / 715 = 6.4 %
  and whole attack class 12.9 % at 97.0 % precision; MFCI / Recon untouched.
- **VERDICT (binding, pre-registered primary): WEAK / HYPOTHESIS NOT SUPPORTED.**
  The physical-rate hypothesis has a real but small effect on this data. After
  removing the false-positive-inflating boundary jumps (which EXP-0019's headline
  recall was partly riding on), only ~12–14 % of the CMRI EXP-0017 misses is
  recoverable, and the pre-registered cutoff still slightly over-fires on Normal.
  A strict cutoff of the same gated rule does clear all bars at ACCEPTABLE, so a
  defensible small detector exists — recovering ~56 pure-CMRI windows (lifting
  pure-CMRI combined recall ~54.6 % → ~59 %) for ~4 Normal false positives.
- **RECOMMENDATION (user judgement call).** Either (a) EXP-0021 pre-registers the
  gated rule with the **TRAIN-normal-max cutoff as primary** (justified: EXP-0020
  showed p99.9 over-fires) and, if it holds, weigh wiring it in for a modest CMRI
  gain; or (b) **close the pressure-rate line** — the effect is real but ~5 pp
  absolute pure-CMRI recall for added rule complexity and a small FP surface, and
  EXP-0018/0019/0020 have now each scored TEST once against a pressure hypothesis
  (garden-of-forking-paths risk). Nothing is wired into `run_detector()` either way.
- **TESTED.** Full suite **170 passed, 0 skipped, 0 failed** (was 164; +6 EXP-0020
  tests — 5 fast synthetic units + 1 slow saved-result replay). No raw data read in
  pytest. Saved result:
  [exp0020_pressure_rate_gated.json](../data/experiments/exp0020_pressure_rate_gated.json),
  summary [EXP0020_RESULTS.md](EXP0020_RESULTS.md). `run_detector`, `app.py` and all
  protected / EXP-0018 / EXP-0019 files unchanged.
- **LINE CLOSED (2026-09-10).** No EXP-0021. The pressure-rate line (EXP-0018 →
  EXP-0020) is closed per DECISION_LOG.md: across three experiments on the same
  544-window frozen missed-CMRI cohort the measured effect shrank from an
  artifact-inflated 26.65 % to a genuine ~12–14 % as diagnostics improved
  (p: 2e-19 → 1.8e-4), and the surviving ACCEPTABLE variant rests on only 4
  false-positive windows — too thin to trust, and a fourth iteration would risk the
  EXP-0009 → EXP-0011 validation-overfitting pattern. CMRI combined recall stays at
  60.1 % (EXP-0017). Next detection work: MSCI / MPCI (different cohort).

## PRE-REGISTRATION — EXP-0023 (recorded 2026-09-11, before the EXP-0023 script/run)

**Status: PLANNED — INVESTIGATIVE / DESCRIPTIVE ONLY; NO DETECTOR, RULE OR MODEL.**

1. **Question.** Characterize the 14 previously undecoded register-data bytes in the
   canonical 23-byte Modbus `0x03` egress read response. The 18-byte register-data
   region is `frame[3:21]`; the four-byte candidate at register-data offsets 14–17
   will be checked against ARFF `pressure measurement` as an offset/alignment sanity
   check, leaving offsets 0–13 under investigation. If the frame shape or the ARFF
   match fails, stop rather than infer a layout.
2. **Data / boundary.** Authoritative TXT/ARFF hashes must match. Egress only means
   `destination == 1`. TRAIN and VALIDATION membership come only from corrected
   manifest `verified-egress-5s-exp0008-pretest-v1`; TEST is not needed or read for
   this descriptive investigation. `source` is an unobservable F-02 rig artifact and
   is not parsed, bound, filtered on, reported, or used in any feature/decision logic.
3. **TRAIN-normal byte audit.** For every undecoded offset, report observed domain,
   count, range and entropy. Also test all nine aligned Modbus 16-bit register
   groupings and limited evidence-led alternatives (duplicate/discrete status bytes,
   bit frequencies, integer/raw-measurement association, and float candidates). A
   byte is called constant only if it is constant across every canonical response in
   pure-Normal TRAIN windows; `reserved/padding/unused` remains an empirical
   candidate, not a documented semantic claim.
4. **Known-field association.** Compare candidates with decoded pressure and time;
   function code is fixed by the canonical cohort, so its correlation is undefined
   rather than zero. Report Pearson/Spearman association and deterministic/near-
   deterministic relationships where applicable. Do not name pump, solenoid, valve,
   actuator state, or any other process meaning without documentation or a clean
   event-level coincidence test; unknown means unknown.
5. **Attack comparison.** For every non-constant, non-random candidate, aggregate
   descriptive features per existing 5-second eligible window. In fixed priority
   order, compare pure MSCI and MPCI windows first, then NMRI, CMRI, MFCI, DoS and
   Recon where the candidate is observable. Report both full pure-Normal and
   nearest-index matched pure-Normal Cohen's d using the EXP-0014/0015 population-SD
   convention and negligible/small/medium/large grades. This is descriptive signal
   measurement only; no acceptance bar, threshold, detector recall or TEST score.
6. **Outcome labels.** Assign each of the 14 bytes exactly one conservative class:
   (a) confirmed constant in TRAIN-normal / no observed variation (meaning still
   undocumented); (b) varies but appears noise/uninterpretable; (c) plausible pattern
   with unconfirmed meaning; or (d) real MSCI/MPCI Cohen's-d separation and genuine
   feature candidate. Only (d) is promising. No threshold is selected, no TEST score
   is produced and no operational file is touched.
7. **Tests / outputs.** New EXP-0023 script, tests, saved JSON and result summary only,
   plus completion entries in these two logs. Synthetic tests must prove byte slices,
   big-endian register grouping and pressure-float sanity. Full suite before any
   commit; full diff and all real findings shown first. No commit or push without an
   explicit go-ahead.

## EXP-0023 execution outcome — TESTED — no promising candidate; MSCI/MPCI unobservable in this field (2026-09-11)

- Identity gates passed: EXP-0017 reproduced from its checksummed artifact
  (`comb == protocol | pressure | IF`, whole-TEST `(4767, 40, 2166, 2374)`); TEST not
  read or scored.
- **Pressure-offset sanity check passed**: the big-endian float32 at `frame[17:21]`,
  decoded independently from raw bytes, matches the ARFF `pressure measurement`
  column on all 48,060 egress `0x03` canonical Normal-category rows (0 mismatches,
  1e-4 relative tolerance for ARFF's ~6-sig-fig text precision). Attack-category rows
  were excluded by design (pressure is attacker-falsified there — the known
  phenomenon, not an offset bug). Frame layout confirmed:
  `addr(1) func(1) byte_count=18 register-data(18) crc(2)`; the 14 undecoded bytes are
  `frame[3:17]` = exactly 7 big-endian 16-bit registers.
- **Per-byte audit (TRAIN-normal, n=21,384):** 8 of 14 bytes hard-constant. Byte 5
  varies but is noise-like (entropy 7.52/8 bits). Bytes 1/3/7/13 vary as small
  discrete sets (2-4 values), consistent with packed status/flag bits; bytes 1 and 3
  are numerically identical in every one of the 21,384 samples checked. **Byte 4
  correlates with decoded pressure at Pearson r=0.995** — the audit's one clear
  structural finding, consistent with a raw analog/ADC channel reading the same
  sensor before scaling.
- **Documentation check (thesis Appendix A, Figure A.1):** the RTU's documented READS
  register map begins with exactly 7 registers (Digital Outputs, Digital Inputs,
  Analog Input 0-4) followed by a 2-register float "Scaled Gas Pressure" — the same
  7-register + float shape observed on the wire. Named as a structural match, not
  confirmed: there is no ARFF ground-truth column for those registers the way there
  is for pressure.
- **Attack comparison (Cohen's d, population-SD, TRAIN+VAL, MSCI/MPCI priority):**
  **0 pure MSCI, MPCI, MFCI, DoS or Recon windows contain any egress `0x03` traffic at
  all** — the motivating MSCI/MPCI question is unanswerable from this field under the
  pure-window definition used throughout this project, not merely "no signal". CMRI
  (6,890 windows) and NMRI (4,018 windows) do have `0x03` traffic; every non-constant
  byte, register-pair and float candidate was compared there and **none reaches even
  a small effect (`|d| < 0.2` everywhere, including the pressure-correlated register)**.
- **Conclusion: no byte or byte-group qualifies as a genuine feature candidate
  (category d) under this experiment's bar.** 8 bytes classed (a) confirmed constant,
  1 byte (b) noise, 5 bytes (c) plausible-but-unconfirmed pattern (4 bit-flag-like,
  1 the pressure-correlated analog byte). This reinforces EXP-0022: MSCI/MPCI barely
  touch `0x03` read-response traffic, so features built from this frame type have a
  structural ceiling independent of which bytes are decoded.
- **TESTED.** Full suite **198 → 215 passed** (17 new: 16 fast synthetic units + 1
  slow saved-result replay). No raw data read in pytest outside the guarded scan
  script itself (run once outside pytest to produce the saved JSON).
- `run_detector`, `app.py`, DoS files, Layer A, the closed EXP-0018/0019/0020 CMRI
  files and all protected EXP-0005..EXP-0022 files are unchanged. `source` is never
  parsed, bound, filtered on, or used anywhere in `ml/exp0023_0x03_register_bytes_diag.py`
  (asserted by a static-analysis unit test). New files only:
  `ml/exp0023_0x03_register_bytes_diag.py`, `tests/test_exp0023_0x03_register_bytes_diag.py`,
  `data/experiments/exp0023_register_bytes.json`, `docs/EXP0023_RESULTS.md`.
- Saved result:
  [exp0023_register_bytes.json](../data/experiments/exp0023_register_bytes.json),
  summary [EXP0023_RESULTS.md](EXP0023_RESULTS.md).

## PRE-REGISTRATION — ACK-001 (recorded 2026-09-11, before any ACK-001 script/run)

**Status: PLANNED — FEASIBILITY / COVERAGE CHECK ONLY. No classifier, detector, rule
or threshold is built or scored in this task.**

1. **Question.** Before investing in the fuller "acknowledgement-anchored
   consequence detector" design (anchor observation on every observable `0x10`
   write-acknowledgement, examine subsequent pressure behaviour, matched-reference
   detector / trajectory templates / supervised heads to follow only if justified),
   check whether the data even supports it: do MSCI and MPCI acks have enough
   post-ack pressure observations to be scorable at all?
2. **Population.** Every observable `0x10` write-acknowledgement — egress
   (`destination == 1`), `function_code == 0x10`, `frame_len_bytes == 8`
   (`is_request == 0`, the echo-response shape per `features_txt.py`) — in the
   TRAIN+VALIDATION population only, per the corrected manifest
   `verified-egress-5s-exp0008-pretest-v1`. TEST is never read or referenced for
   filtering. `source` is not parsed, bound, filtered on, reported, or used in any
   feature/decision logic anywhere in this task.
3. **Ground truth.** Each ack's own per-record `categorized_attack` label
   (Normal / MSCI / MPCI) is used **for reporting only**, never as a runtime feature.
   Acks labelled NMRI/CMRI/MFCI/DoS/Recon are counted and reported separately as
   out of scope for this design, not silently dropped.
4. **Measurements per ack**, using the proposed design's exact numbers (no
   improvisation): a valid pre-ack baseline requires ≥5 `0x03` pressure-response
   timestamps in the 30s strictly before the ack; post-ack horizons are 10/30/60/120s
   with minimum scorable sample counts 2/5/10/20 respectively; an ack is part of a
   cluster if another `0x10` ack (any label) falls within 10s of it (either
   direction); the truncation/censoring rule compares each horizon against the gap to
   the *next* ack after this one (any label) — a horizon is censored if that gap is
   shorter than the horizon.
5. **Report**, separately for Normal / MSCI / MPCI acks: total count; % with a valid
   pre-ack baseline; % scorable at each horizon; % censored at each horizon and where
   censoring typically falls; % pure (ack's 5s bucket contains only that category, or
   only Normal for Normal acks) vs mixed (co-occurring with another attack category
   in the same 5s bucket, per `features_windowed.Window.categories`).
6. **Pre-registered stopping rule.** If the majority of MSCI or MPCI acks have no
   scorable post-ack pressure data within 120s, that category's line is flagged
   **likely infeasible** for this approach and reported as such — not proceeded past
   regardless of how any other number looks.
7. **Tests / outputs.** New ACK-001 script + tests + saved JSON + result summary
   only, plus these two log entries. Synthetic tests must prove ack identification
   (echo-response shape), clustering/censoring arithmetic, and horizon
   scorability thresholds. Full suite before any commit; full diff and all real
   findings shown first. No commit or push without explicit go-ahead.
8. **Scope discipline.** `run_detector`, `iforest_detector.py`, `features_windowed.py`
   (imported read-only for `build_windows`/`Window`, not modified), `rules.py`,
   Layer A, `app.py`, DoS files, and CMRI's closed files are not touched. New files
   only.

## ACK-001 execution outcome — TESTED — INFEASIBLE for MSCI/MPCI (and Normal) once the design's own censoring rule is applied (2026-09-11)

- Identity gates passed: EXP-0017 reproduced from its checksummed artifact
  (`comb == protocol | pressure | IF`, whole-TEST `(4767, 40, 2166, 2374)`); TEST not
  read or scored.
- Population (TRAIN+VAL only): 51,229 observable egress `0x10` acks, 53,261
  observable egress `0x03` pressure responses. By ground-truth label (reporting
  only): Normal 38,807; MPCI 8,341; MSCI 3,274; DoS 807 (out of scope for this
  design, reported not dropped); no NMRI/CMRI/MFCI/Recon acks observed.
- **Cadence finding (the root cause):** median inter-arrival is ~3.4s for BOTH
  `0x03` pressure responses and `0x10` acks — the master's polling/control cycle
  interleaves reads and writes at essentially the same rate. 100% of acks (every
  category) are "clustered" under the design's own 10s definition.
- **Raw (nominal-horizon) scorability looks fine**: 94.7–99.8% scorable across all
  three categories and all four horizons (10/30/60/120s) — and the pre-registered
  stopping rule, read literally against this raw number, does **not** flag MSCI or
  MPCI (unscorable-at-120s only 3.7%/4.6%).
- **That raw number is misleading**: it ignores the design's own truncation/
  censoring rule (a horizon must be cut to the gap-to-the-next-ack when that gap is
  shorter). Applying it: **censoring-aware scorability is exactly 0.00% at every
  horizon, for Normal, MSCI, and MPCI alike** — verified both in aggregate and by
  direct per-ack inspection (all 162 acks that escape even 10s censoring — the most
  favourable cases in the whole population — reach a maximum of 1 pressure sample
  against a minimum requirement of 2, zero exceptions).
- **Corrected stopping-rule verdict: LIKELY INFEASIBLE for both MSCI and MPCI**, and
  the same collapse hits Normal too — this is a population-wide data-density
  problem (0x03/0x10 cadence), not a per-category detection problem. MSCI and MPCI
  acks are additionally 0% "pure" (always co-occurring with another category in
  their 5s bucket) — a second, independent complication for the design.
- **Conclusion: the ack-anchored consequence detector as specified is not worth
  building.** This hits the same wall as EXP-0023 (payload bytes) — the data does
  not support the question, not because of a subtle effect too small to see, but
  because the required observation (several attributable post-ack pressure samples)
  essentially never exists in this capture.
- **TESTED.** Full suite **215 → 237 passed** (22 new: 21 fast synthetic units + 1
  slow saved-result replay). No raw data read in pytest outside the guarded scan
  script itself.
- `run_detector`, `app.py`, DoS files, Layer A, the closed EXP-0018/0019/0020 CMRI
  files and all protected EXP-0005..EXP-0023 files are unchanged. `source` is never
  parsed, bound, filtered on, or used anywhere in `ml/ack001_ack_anchored_coverage.py`
  (asserted by a static-analysis unit test). New files only:
  `ml/ack001_ack_anchored_coverage.py`, `tests/test_ack001_ack_anchored_coverage.py`,
  `data/experiments/ack001_coverage.json`, `docs/ACK0001_RESULTS.md`.
- Saved result:
  [ack001_coverage.json](../data/experiments/ack001_coverage.json),
  summary [ACK0001_RESULTS.md](ACK0001_RESULTS.md).

## PRE-REGISTRATION — ACK-002 (recorded 2026-09-12, before any ACK-002 script/run)

**This is a feasibility check only. No model, classifier, rule, or threshold is
built or scored here.** This is the one remaining cheap check on the ack-anchored
MSCI/MPCI line before it is treated as fully, definitively closed: ACK-001 found
per-write attribution structurally impossible because write-acks and pressure-reads
share a ~3.4s cadence, so a second write almost always lands before enough pressure
samples accumulate after the first (censoring-aware scorability was 0.00% at every
horizon). An independent review confirmed relaxing the censoring threshold would
launder contaminated samples, not fix attribution. ACK-002 asks a different
question: not "what happened after THIS write" but "does a clean window exist after
an entire BURST of writes ends, before the next burst begins."

1. **Burst-merging gap threshold — derived label-blind.** Compute the empirical
   distribution of inter-ack gaps (consecutive egress `0x10` write-acks, sorted by
   timestamp) across ALL acks in TRAIN+VALIDATION scope (corrected manifest
   `verified-egress-5s-exp0008-pretest-v1`), Normal and attack alike, with NO label
   information used in choosing the threshold. Method fixed in advance: report the
   full gap-distribution summary (median, mean, percentiles up to p99, max) first;
   the merging threshold is **3x the median inter-ack gap**, a fixed principled
   multiple chosen before looking at the distribution's shape or any label-based
   outcome — not a value search over what best separates attack from normal. If the
   distribution shows an obvious natural knee near that value it will be reported as
   corroborating evidence, but the 3x-median rule is the pre-committed choice either
   way.
2. **Burst construction.** Merge consecutive acks (any label) into a burst whenever
   the gap to the previous ack is ≤ threshold. A burst is 1+ acks; record start ts,
   end ts, ack count, duration (end - start; 0 for single-ack bursts).
3. **Post-burst uncontaminated window.** For each COMPLETED burst (one with a
   following burst, or reaching end-of-scope counts as completed too — end-of-data
   is a real boundary, not contamination), count `0x03` pressure samples with
   timestamp strictly after the burst's end and strictly before the next burst's
   start (or before end-of-scope if last). Record count and window duration
   (next_burst_start - burst_end, or scope_end - burst_end if last).
4. **Reporting groups (labels applied only now, for reporting):** a burst is
   "MSCI-containing" if any of its acks has ground-truth label MSCI, "MPCI-
   containing" analogously, "Normal-only" if every ack in the burst is Normal. (A
   burst can be both MSCI- and MPCI-containing; report all three groups
   independently, not mutually exclusive partitions.) For each group: N bursts; %
   with ≥1/≥2/≥3 post-burst pressure samples; median sample count; median
   uncontaminated window duration (seconds).
5. **Decision criterion (fixed before running).** If the large majority (>50%) of
   MSCI-containing or MPCI-containing bursts have fewer than 2 uncontaminated
   post-burst pressure samples, this closes the ack-anchored MSCI/MPCI line
   definitively, same reporting standard as ACK-001's stopping rule. This is
   expected per ACK-001's cadence finding — treated here as checking a small
   (~5%) chance the burst-level view resolves it. If bursts unexpectedly DO show
   real coverage (majority of MSCI/MPCI bursts with ≥2 clean samples), that is
   reported as a genuine, surprising finding warranting a new pre-registered
   follow-up — not built into a detector in this task regardless of outcome.
6. **Identity gate.** EXP-0017 reproduced from its checksummed artifact before any
   new computation, exactly as ACK-001 did; TEST is not read.
7. **Scope discipline.** New files only:
   `ml/ack002_burst_anchored_coverage.py`,
   `tests/test_ack002_burst_anchored_coverage.py`,
   `data/experiments/ack002_coverage.json`, `docs/ACK0002_RESULTS.md`. `run_detector`,
   `iforest_detector.py`, `rules.py`, Layer A, `app.py`, DoS files, and CMRI's closed
   files (EXP-0018/0019/0020) are not touched. `source` is never parsed, bound,
   filtered on, or used — egress is `destination == 1` only, via the corrected
   split manifest. A static-analysis test asserts `source` is absent from the new
   script.
8. **Tests.** Synthetic units for burst-merging logic: threshold computation on a
   known synthetic gap distribution, merging behavior at exactly-threshold and
   just-over-threshold gaps, single-ack bursts, post-burst window counting
   (inclusive/exclusive boundaries), end-of-scope handling as a valid completed
   burst. Full suite must pass before any commit.
9. **Before any commit:** full diff and all real findings shown; wait for explicit
   go-ahead. No push without separate explicit go-ahead. No force-push ever.

## ACK-002 execution outcome — TESTED — literal stopping rule NOT triggered, but the coverage found is not usable (line closed) (2026-09-12)

- Identity gate passed: EXP-0017 reproduced (whole-TEST `(4767, 40, 2166, 2374)`);
  TEST not read.
- **Label-blind threshold:** median inter-ack gap 3.382s (p99 3.775s, max 640.1s) →
  threshold = 3× median = 10.147s, fixed before any label was examined.
- **Burst construction:** only 167 bursts across 51,229 acks — the threshold
  (10.15s) is barely above the tight ~3.4s cadence, so splits only occur at the
  rare tail gaps (166 splits / 51,228 gaps ≈ 0.32%). Bursts are mega-chunks:
  median 218 acks/burst (mean 306.8, max 1264), median duration 770.2s (mean
  1055.4s, max 4570.9s) — not attacker-scale write clusters.
- **Coverage by group:** MSCI-containing (n=81): 98.77% ≥2 clean samples, median
  13 samples over a median 237.7s window. MPCI-containing (n=121): 95.04% ≥2,
  median 12 samples over 231.8s. Normal-only (n=35): 97.14% ≥2. **The literal
  stopping rule is NOT triggered for either MSCI or MPCI** (1.23%/4.96% below the
  50% threshold) — read alone, this looks like a GO signal, unlike ACK-001.
- **Why it is not a real positive:** composition check (supporting evidence, not
  part of the pre-registered rule) shows 100% of MSCI-/MPCI-containing bursts
  also contain Normal traffic and span multiple categories, with hundreds of acks
  each. A post-burst pressure sample after a 300+-ack, multi-category, ~13-minute
  burst cannot be attributed to any single write inside it. The 95–99% coverage
  describes pressure density during the capture's rare long pauses (episode/
  recording-segment boundaries), not a usable post-attack observation window —
  the same territory EXP-0021/0022 already explored at the episode grain
  (negative for MPCI there).
- **Conclusion: this is NOT the ~5% surprising-positive case anticipated in the
  pre-registration.** The numbers pass the literal rule but the underlying
  question (does a clean, attributable window exist after a burst) is not
  answered affirmatively once composition is checked. No further build effort is
  warranted on the ack-anchored MSCI/MPCI line via burst construction.
- **Combined with ACK-001 (0.00% per-write censoring-aware scorability) and
  EXP-0021/0022/0023 (episode/payload checks, both negative): the ack-anchored /
  write-response line for MSCI/MPCI is now treated as fully, definitively
  investigated**, per this task's own closing condition.
- **TESTED.** Full suite **237 → 263 passed** (26 new: 25 fast synthetic units + 1
  slow saved-result replay). `source` never parsed/used (asserted by a
  static-analysis test); `run_detector`, `app.py`, DoS files, Layer A, and the
  closed EXP-0018/0019/0020 CMRI files unchanged.
- New files only: `ml/ack002_burst_anchored_coverage.py`,
  `tests/test_ack002_burst_anchored_coverage.py`,
  `data/experiments/ack002_coverage.json`, `docs/ACK0002_RESULTS.md`.
- Saved result:
  [ack002_coverage.json](../data/experiments/ack002_coverage.json),
  summary [ACK0002_RESULTS.md](ACK0002_RESULTS.md).

## PRE-REGISTRATION — EXP-0025 (recorded 2026-09-12, before any EXP-0025 script/run)

**This wires a THIRD rule into the deterministic rule layer (protocol OR pressure
OR rate), targeting Type 2 (egress-channel/diode-termination flood) DoS
specifically.** EXP-0010 (2026-09-09) measured, but never wired in, a candidate
`packets_per_sec > TRAIN-normal-max` rule against synthetic egress-flood
injections: 100% detection at severities 2x-20x (profiles A/B), zero new false
positives on real Normal TEST windows. Since EXP-0010 ran, EXP-0017 wired in a
DIFFERENT rule (`PressureBoundsRule`, for NMRI) and became the current
operational detector: protocol OR pressure OR Isolation Forest, frozen TEST
confusion `(4767, 40, 2166, 2374)`, 52.29% recall / 98.34% precision.

**Explicit scope statement (repeated in the results doc, not just here): this
targets Type 2 DoS only. Type 1 (external-flood) DoS remains at 0% recall and is
a SEPARATE, structurally different problem** — the flood lives entirely in the
*inbound* command direction and a diode already blocks it from the egress view
(`ml/features_windowed.py` docstring, EXP-0003/0013). This experiment must not be
reported or cited as "DoS solved."

1. **Re-verify EXP-0010's finding under the CURRENT detector state**, not just
   re-cite the old number. Re-run the identical synthetic-injection methodology
   (frame-level injection, profiles A_distinct/B_duplicate, severities
   1x/2x/5x/10x/20x, uniform re-spacing, no RNG) from `ml/exp0010_egress_flood.py`
   — reused directly (`synthesize_flood`, `_window_from_frames`,
   `egress_frame_buckets`), not reimplemented — against a freshly reproduced
   EXP-0017 state (protocol OR pressure OR IF), identity-gated against the saved
   `exp0017_detector.json` exactly as ACK-001/EXP-0016 gate against their
   references. Confirm the rate rule ALONE (fit fresh on current TRAIN-normal
   `packets_per_sec`, not the stale EXP-0004-era number) reproduces ~100%
   detection / 0 new FP before building anything permanent.
2. **Threshold:** re-derive fresh from current TRAIN-normal `packets_per_sec` (max
   over the manifest's TRAIN-normal windows) rather than reusing EXP-0010's cited
   0.8 verbatim — the split/window construction has not changed since EXP-0010,
   so this is expected to reproduce ~0.8, but stated and verified, not assumed.
3. **Build `rules.RateFloodRule`** — new additive class in `ml/rules.py`, same
   style as `PressureBoundsRule` (single upper-bound membership test, `fit`/
   `evaluate`/`predict`, `RuleHit` reasons). `DeterministicRuleLayer` and
   `PressureBoundsRule` are not modified.
4. **Wire into `iforest_detector.run_detector()`** as a permanent third OR
   condition: `rule_pred = protocol OR pressure OR rate`; `comb_pred = rule OR
   IF`. `DetectorResult` gets an additive `rate_pred` field (and the rate
   threshold recorded). Because TEST must only ever be scored once (EXP-0017
   already consumed that one guarded evaluation, and its `if_pred`/`if_scores`/
   `mu`/`sd`/`threshold` are frozen and must not be recomputed), the new combined
   TEST confusion is DERIVED analytically from the existing frozen
   `exp0017_detector.json` arrays: `rate_pred` is a closed-form function of (a)
   the TRAIN-normal `packets_per_sec` threshold (TRAIN-only, unlimited reads) and
   (b) each TEST window's already-recorded `packets_per_sec` feature (already
   saved in `test_windows`, not a new read of raw TEST data). No new TEST
   scoring event occurs; this is stated explicitly in the results, not left
   implicit. `test_detector.py`'s regression constants are updated to the new
   frozen confusion, with the derivation's exactness argued and checked (not
   merely asserted) before freezing.
5. **Report** the new overall confusion matrix and the full per-category table
   (all 7 categories + Normal), same format as EXP-0017's report.
6. **Honest reporting requirements:**
   - Confirm Type 1 DoS TEST numbers are literally unaffected (0 new rate-rule
     flags on DoS-labeled TEST windows) — investigate rather than assume if this
     is not exactly true.
   - Confirm no other category's flag rate changes except via the intended
     mechanism.
   - Confirm Normal FPR does not regress (0 new false positives expected, since
     the threshold is the TRAIN-normal max).
7. **Update `app.py`/dashboard and docs** to state the rate rule exists, is part
   of the operational detector, and explicitly what it does and does not cover
   (Type 2 flood, not Type 1).
8. **Tests:** update/add tests; full suite must pass; exact before/after count
   reported. Same identity-check discipline throughout (reproduce old state
   first, confirm no drift, then compute and freeze the new state).
9. **Scope discipline.** Do not touch DoS Type 1's invalidated files (EXP-0011/
   0011b), MSCI/MPCI's closed files (EXP-0014/0021/0022/0023, ACK-001/002), Layer
   A, or CMRI's closed files (EXP-0018/0019/0020). New files:
   `ml/exp0025_dos_rate_rule.py`, `tests/test_exp0025_dos_rate_rule.py`,
   `data/experiments/exp0025_dos_rate_rule.json`, `docs/EXP0025_RESULTS.md`.
   Modified (additive only): `ml/rules.py` (+`RateFloodRule`),
   `ml/iforest_detector.py` (`run_detector`/`DetectorResult`), `tests/
   test_detector.py` (updated regression constants), `tests/conftest.py` (if the
   frozen artifact path needs to change), `app.py`/dashboard docs.
10. **Before any commit:** full diff and all real results shown; wait for
    explicit go-ahead. No push without separate explicit go-ahead. No
    force-push ever. If anything about re-deriving the threshold or re-running
    the synthetic injection is ambiguous, EXP-0010's exact original methodology
    is followed rather than improvising a new one.

## EXP-0025 execution outcome — VALIDATED — rate rule wired in; ZERO effect on real TEST data, Type 1 DoS unaffected (2026-09-12)

- **Step 1 (re-verification):** freshly re-derived TRAIN-normal
  `packets_per_sec` threshold = 0.8 (14,951 TRAIN-normal windows; matches
  EXP-0010's cited value exactly). Standalone rate-rule dose-response against
  EXP-0010's exact synthetic-injection methodology (reused unmodified): 2x =
  94.92% recall / 0 FP, 5x/10x/20x = 100% recall / 0 FP, both profiles
  identical. **Honest correction:** EXP-0010 never actually measured the rate
  rule standalone (only an informal "fix note"); its implied "100% at all
  severities 2x-20x" does not hold exactly at 2x (244/4,807 windows tie the
  threshold from integer frame-count rounding on already-low-rate windows) —
  disclosed rather than silently re-cited.
- **Identity-gate collision (flagged to and resolved with the user):** editing
  `ml/rules.py`/`ml/iforest_detector.py` changed hashes pinned by
  `exp0017_detector.json`'s own checksummed identity gate, which ACK-001/002
  and EXP-0021/22/23 all depend on via `load_result()`. **User explicitly
  approved** refreshing only the `identity.source_sha256` ledger entries for
  those two files inside the existing frozen artifact (envelope checksum
  recomputed); the scored `result` payload was not touched. Verified by
  reloading `load_result()` successfully and confirming the full suite
  (including ACK-001/002/EXP-0021/22/23) still passes.
- **Step 2:** `rules.RateFloodRule` added (additive, `PressureBoundsRule`
  pattern). **Step 3/4:** wired into `run_detector()` permanently
  (`protocol OR pressure OR rate`, then `OR IF`); `DetectorResult` gains
  `rate_pred`/`rate_threshold`. TEST is NOT rescored — the new combined TEST
  confusion is derived analytically from the frozen EXP-0017 arrays plus a
  closed-form `rate_pred` (TRAIN-normal threshold × each TEST window's
  already-recorded `packets_per_sec`), checked against the frozen split
  identity before use.
- **New combined TEST confusion: `(4767, 40, 2166, 2374)` — numerically
  IDENTICAL to EXP-0017.** Verified directly: `rate_pred.sum() == 0` across
  every one of the 9,347 TEST windows, every category, DoS included. No real
  captured Type 2 (egress-channel) flood example exists in this dataset, so the
  rule (correctly built, for a threat type not present here) never fires on
  real data.
- **Step 6 (honest checks, all verified not assumed):** DoS (Type 1) unaffected
  — 136 windows, 0 rate flags, 0% combined recall, identical to EXP-0017. Every
  other category's flagged count delta is exactly 0. Normal FPR unchanged at
  0.832% (40/4,807), zero new false positives.
- **Explicit scope restatement:** this is Type 2 (egress-channel flood) DoS
  only. **Type 1 (external inbound-flood) DoS remains at 0% recall**,
  structurally invisible on egress, completely unaffected by this experiment.
  This is NOT "DoS solved."
- **Step 7:** `app.py` updated — loads the EXP-0025 result, title/caption/
  `CAVEAT` updated, new `DOS_SCOPE_NOTE` states what the rule covers and does
  not cover.
- **TESTED/VALIDATED.** Full suite **263 → 275 passed** (12 new: 10 fast
  synthetic units + 2 slow saved-result replays in `test_exp0025_dos_rate_rule.py`;
  2 new tests added to `test_detector.py`). `source` never parsed/used
  (asserted by a static-analysis test); DoS Type 1's invalidated files,
  MSCI/MPCI's closed files, Layer A, and CMRI's closed files unchanged.
- Files: new `ml/exp0025_dos_rate_rule.py`, `tests/test_exp0025_dos_rate_rule.py`,
  `data/experiments/exp0025_detector.json`, `docs/EXP0025_RESULTS.md`. Modified
  (additive): `ml/rules.py`, `ml/iforest_detector.py`, `tests/test_detector.py`,
  `tests/conftest.py`, `app.py`. Also modified (identity ledger only, user-
  approved): `data/experiments/exp0017_detector.json`.
- Saved result:
  [exp0025_detector.json](../data/experiments/exp0025_detector.json),
  summary [EXP0025_RESULTS.md](EXP0025_RESULTS.md).

## PRE-REGISTRATION — EXP-0026 (recorded 2026-09-12, before any EXP-0026 script/run)

**This explores window size as a NEW, SEPARATE pipeline variant. It does NOT
modify the existing 5-second EXP-0017/EXP-0025 production pipeline in any way**
— `ml/features_windowed.py`, `run_detector()`, `ml/iforest_detector.py` are not
touched or imported for construction. This is descriptive/diagnostic first;
a detector is only built if the pre-registered gate below passes.

**Motivation.** ACK-001/002 closed ack-anchored per-write/per-burst MSCI/MPCI
consequence attribution as structurally impossible (polling-cycle collision).
Independently, EXP-0021's episode-level aggregation found MPCI's `p_std` effect
size nearly doubles (window-level Cohen's d 0.242 → episode-level 0.446,
reproduced from `data/experiments/exp0021_msci_mpci.json`) when the SAME five
pressure features are computed across a whole labelled attack episode (~15
consecutive 5s windows, median) instead of one window at a time — though this
did **not** clear EXP-0021's own gate (`|d| >= 0.5`) either. This experiment
asks a different question: does redefining the observation unit natively
longer, BEFORE any feature computation (not aggregating after the fact, and not
tied to variable-length attack-label episodes), reveal more separation than the
current fixed 5s window dilutes?

1. **Window sizes tested:** 5s (baseline, must reproduce EXP-0021's window-level
   numbers as a consistency check), 15s, 30s, 60s. Native windows are built by
   `floor(timestamp / W)`, W a multiple of 5s.
2. **Feature scope (disclosed choice, not run yet):** the five EXP-0021 pressure
   features — `p_std`, `p_range`, `p_max_abs_step`, `p_trend_abs`, `p_mean_shift`
   — computed directly from each native window's own `0x03` canonical pressure
   samples (not EXP-0014's 16 protocol/rate/entropy features). Reason: EXP-0014
   already established that MSCI/MPCI write frames are byte-identical to Normal
   writes (`start_register 3049, quantity 18, byte_count -1, length_anomaly 0,
   entropy 3.0000` — see EXP-0014's per-category `egress_frame_note`), so
   protocol/rate/entropy features are structurally invariant to window size;
   only the pressure-consequence signal EXP-0021 flagged is a plausible
   candidate for a window-size effect. `p_mean_shift` is redefined at native
   granularity as the shift versus the mean pressure of the immediately
   preceding native window of the same size (0.0 if that window has no
   pressure samples) — EXP-0021's own convention for an unavailable "prior",
   generalized from episode-relative to native-window-relative.
3. **Cohen's d formula:** EXP-0021's own (`exp0021_msci_mpci.cohens_d`, pooled
   sample variance, ddof=1), reused directly — enables an exact reproduction
   check against EXP-0021's saved TRAIN+VALIDATION window-level numbers at
   W=5s before trusting any new window size.
4. **Split-boundary handling (stated before running, per the task's explicit
   ask):** a native window of size W comprises `n5 = W/5` consecutive 5-second
   buckets. It is **discarded entirely (never truncated)** unless ALL `n5` of
   those 5s-bucket ids belong to the SAME block (all TRAIN, all VALIDATION, or
   all TEST) per the frozen manifest (`ml/splits/verified_egress_5s_exp0008_pretest_v1.json`,
   reused read-only via `exp0021_msci_mpci.Blocks`). This also naturally
   discards windows overlapping the internal gaps already present inside the
   manifest's TRAIN/VALIDATION bucket-id sets (confirmed non-contiguous: TRAIN
   has 28,040 ids spanning a 32,804-wide numeric range). No frame or feature
   value is ever computed from a partial-duration window.
5. **Descriptive stage scope:** TRAIN+VALIDATION only, pooled together (matching
   EXP-0021's own pooling), pure-MSCI(+Normal)/pure-MPCI(+Normal) native windows
   vs the full population of pure-Normal native windows in the same pooled
   scope — same "vs full population" comparison EXP-0021's window-level number
   used (not nearest-matched; matched sampling is EXP-0021's episode-level
   comparison, not reproduced here since episodes are not the observation unit
   under test).
6. **Reported per window size:** Cohen's d per feature (MSCI vs Normal, MPCI vs
   Normal), n pure-attack native windows, n pure-Normal native windows, n
   discarded (boundary/gap) native windows.
7. **Decision bar (fixed before running):** `|d| >= 0.5` (matching EXP-0021's
   own gate) AND at least 30 pure-attack native windows for that category at
   that window size (conventional "large enough" threshold — EXP-0021 itself
   flagged wide Wilson CIs at 28/79 TEST episodes; 30 is not treated as
   precise, just a floor below which effect-size estimates are reported but
   not acted on). Both conditions must hold for the SAME (window size,
   category, feature) triple to proceed to step 8.
8. **If the bar is cleared:** build a standalone detector at that window size
   (new file, TRAIN-only fitting, VALIDATION-first) and measure recall/
   precision/FPR against MSCI/MPCI at VALIDATION. TEST is not touched without
   a separate, explicit go-ahead (same discipline as EXP-0021 sub-experiment
   B). If the bar is not cleared at any size, STOP — report descriptive
   findings only, no detector built. This is treated as a valid outcome.
9. **Honest reporting:** if larger windows just spread the same effect across
   fewer examples without improving the pure-population Cohen's d, or if the
   5s-baseline reproduction check itself fails, this is stated plainly, not
   glossed over.
10. **Scope discipline.** New files only: `ml/exp0026_window_size.py`,
    `tests/test_exp0026_window_size.py`, `data/experiments/exp0026_window_size.json`,
    `docs/EXP0026_RESULTS.md`. `run_detector()`, the 5s production pipeline
    (`ml/features_windowed.py`, `ml/iforest_detector.py`), DoS Type 1's
    invalidated files, CMRI's closed files, Layer A, and `app.py` are not
    touched. `exp0021_msci_mpci.Blocks`/`cohens_d`/`grade_effect` are imported
    read-only for the split-boundary/statistics reuse explicitly requested by
    this task's step 3. `source` is never parsed, bound, filtered on, or used.
11. **Before any commit:** full diff and all real findings shown; wait for
    explicit go-ahead. No push without separate explicit go-ahead. No
    force-push ever.

## EXP-0026 execution outcome — TESTED — gate NOT PASSED at any window size; a real implementation bug caught by the pre-registration's own consistency check (2026-09-12)

- **A genuine bug caught before any conclusion was drawn:** the first run
  failed the pre-registered 5s-baseline reproduction check (MSCI p_std came
  back 0.643 vs EXP-0021's saved 0.144). Root cause: the initial
  implementation used EXP-0014's "pure" cohort (no other attack category
  co-occurring) instead of EXP-0021's actual window-level "containing" cohort
  (any window with >=1 frame of the category, regardless of co-occurrence).
  Fixed to use `_containing` as the primary/gate cohort, matching EXP-0021
  exactly, and kept `_pure` as disclosed secondary context. **After the fix,
  the 5s baseline reproduces EXP-0021's saved numbers exactly** (MSCI 0.144/
  0.245, MPCI 0.242/0.263, all within 0.01) — the consistency check did
  precisely what it was pre-registered to do.
- **Native window population** shrinks as expected with window size: TRAIN+
  VALIDATION windows 28,040+9,345 (5s) -> 8,778+2,928 (15s) -> 4,325+1,446
  (30s) -> 2,091+700 (60s); discarded (boundary/gap) counts disclosed at every
  size (3,379 / 3,819 / 2,022 / 1,137).
- **Primary ("containing") cohort result: the effect grows monotonically with
  window size but plateaus below the pre-registered bar at every size.** MPCI
  `p_std`: 0.242 (5s) -> 0.317 (15s) -> 0.384 (30s) -> 0.421 (60s). MSCI's
  strongest feature (`p_mean_shift`/`p_range`) follows the same pattern,
  topping out at 0.450 at 60s. **No (window size, category, feature) triple
  reaches |d| >= 0.5.**
- **Decision gate: NOT PASSED.** Per the pre-registration, STOP — no detector
  built at any native window size. Comparable to, not better than, EXP-0021's
  episode-level number (0.446), which also did not clear its own gate — native
  fixed-grid windows do not recover the (small) extra separation
  episode-alignment provided, plausibly because a fixed grid frequently
  starts/ends mid-episode while EXP-0021's aggregation followed the actual
  episode boundary.
- **Secondary, NOT-gate-authorized finding, disclosed honestly:** the "pure"
  cohort (EXP-0014's methodology) shows a much larger and sharply growing
  MSCI effect (0.643 -> 1.426, n shrinking 606 -> 117) while MPCI's pure-cohort
  effect stays negligible throughout — the opposite asymmetry from the
  primary cohort. Reported as a genuinely surprising exploratory result that
  was never the pre-registered decision metric; pursuing it would need its
  own fresh pre-registration, not retroactive gate substitution.
- **TESTED.** Full suite **275 → 293 passed** (18 new: 17 fast synthetic units
  + 1 slow saved-result replay). `run_detector`, `ml/features_windowed.py`,
  DoS Type 1's invalidated files, CMRI's closed files, Layer A, and `app.py`
  unchanged. `source` never parsed/used (asserted by a static-analysis test).
- New files only: `ml/exp0026_window_size.py`, `tests/test_exp0026_window_size.py`,
  `data/experiments/exp0026_window_size.json`, `docs/EXP0026_RESULTS.md`.
- Saved result:
  [exp0026_window_size.json](../data/experiments/exp0026_window_size.json),
  summary [EXP0026_RESULTS.md](EXP0026_RESULTS.md).

## ERRATUM — EXP-0026's `p_mean_shift` feature is contaminated by neighbouring-window CMRI injections (found 2026-09-12 while diagnosing the MSCI "pure cohort" finding)

**Known limitation of `p_mean_shift` as defined in `ml/exp0026_window_size.py`
— do not reuse it uncritically.** While diagnosing whether the MSCI pure-cohort
60s `p_std` effect (d=1.426) was a small-n artifact (user-requested diagnostic,
not a new experiment), a small number of `p_mean_shift` values were found to
be astronomically large (~3.36e38, close to float32's max representable value)
for both the MSCI and Normal cohorts at 60s. Root cause: `p_mean_shift` looks
at the pressure of the immediately PRECEDING native window regardless of that
window's category — and a small number of neighbouring windows are
CMRI-labelled (categorized_result 2) with a genuinely huge forged pressure
value, consistent with CMRI's own definition as naive out-of-bounds response
injection (the same phenomenon `PressureBoundsRule`/EXP-0016 was built to
catch). This is real attack-injected data, not a parsing bug (`_parse_optional_float`
correctly excludes non-finite values, but a huge *finite* forged value passes
through as valid, exactly as any legitimate consumer of "pressure value" must
handle).
- **Scope of the contamination:** `p_std`, `p_range`, `p_max_abs_step`, and
  `p_trend_abs` are computed ONLY from a window's own pressure samples and are
  NOT affected — the MSCI pure-cohort finding above is unaffected by this.
  `p_mean_shift` is the only one of the five features that reads a
  neighbouring window's data, and is therefore the only one at risk.
- **Effect on EXP-0026's reported conclusions: none.** `p_mean_shift`'s
  Cohen's d was already reported as small/negligible at every window size in
  EXP-0026 and never drove the decision gate (which failed on `p_std`/`p_range`
  in the primary "containing" cohort, and passed only informally in the
  disclosed-as-exploratory "pure" cohort via `p_std`/`p_range`/`p_trend_abs`,
  not `p_mean_shift`). No conclusion in EXP-0026's results doc rests on
  `p_mean_shift`'s numeric value.
- **Action:** none required to EXP-0026 itself (its conclusions stand); this
  entry exists so a future experiment does not reuse `p_mean_shift` (as
  currently defined, unbounded neighbour lookup) as a trusted feature without
  first either winsorizing/clipping pressure values or restricting the
  "preceding window" lookup to same-category (or pure-Normal) neighbours only.
  `ml/exp0026_window_size.py` itself is NOT modified by this erratum (the
  script and its saved JSON remain the frozen record of what was actually
  run); this is a documentation-only flag.

## PRE-REGISTRATION — EXP-0027 (recorded 2026-09-12, before any EXP-0027 script/run)

**Tests whether EXP-0026's MSCI 60s `p_std` pure-cohort effect (d=1.426,
verified not small-n noise: bootstrap 95% CI (1.12, 1.75), broad not
outlier-driven, spread across 74 distinct episodes) survives against the
REALISTIC evaluation population — every MSCI-containing 60s window (pure +
mixed with a co-occurring attack category), not just the pure-and-isolated
subset.** The pure cohort is not what a deployed detector would see: it
cannot know in advance which windows are "pure," so a detector built only on
the pure-cohort's stronger separation could be measuring a selection effect
(MSCI windows that happen not to co-occur with another attack may be
systematically different from MSCI windows in general) rather than a
deployable signal.

1. **Decision rule for "the effect survives" (fixed before running):** the
   SAME bar as EXP-0021/0026, `|Cohen's d| >= 0.5`, applied to the ALL-
   MSCI-containing-windows-vs-pure-Normal comparison, AND `n >= 30`
   containing windows (same floor as EXP-0026). No new/different bar is
   proposed — the realistic population is a harder test of the SAME
   hypothesis, not a different one, so changing the bar to make it easier
   would defeat the point of running this check. If this passes, proceed to
   step 4 (build/measure a standalone detector, VALIDATION-first). If it does
   not pass, STOP and report the pure-cohort finding as a documented,
   honestly-caveated selection-effect artifact — not a deployable signal,
   still a valuable negative result given the rigor already spent ruling out
   small-n noise.
2. **Reused, not modified:** `ml/exp0026_window_size.py`'s `scan_egress`,
   `build_native_windows`, `native_window_features`, `_containing`, `_pure`,
   `_pure_normal`, and `exp0021_msci_mpci.cohens_d`/`grade_effect` — all
   imported read-only. Native window construction (60s only — the size the
   pure-cohort finding was measured at; other sizes are out of scope for this
   follow-up) and the split-boundary discard rule are UNCHANGED from EXP-0026.
3. **Reported, TRAIN+VALIDATION only:**
   - (a) pure MSCI vs pure Normal, `p_std` — reproduce EXP-0026's d=1.426 as a
     sanity/identity check before anything else is trusted.
   - (b) ALL MSCI-containing windows (pure + mixed) vs pure Normal, `p_std` —
     the real test.
   - (c) if (b) differs meaningfully from (a): break down the "mixed" windows
     by which OTHER category co-occurs (CMRI/MPCI/NMRI/MFCI/DoS/Recon), with
     per-co-occurring-category `p_std` mean/median and count, to understand
     WHY the population changed the effect (e.g., does a co-occurring CMRI
     injection's own huge forged pressure — see the EXP-0026 `p_mean_shift`
     erratum, same underlying phenomenon — inflate or deflate the mixed
     cohort's `p_std`?).
4. **If the bar is cleared:** build a standalone `p_std`-threshold detector at
   60s native windows (new file). TRAIN-only threshold fitting, VALIDATION-
   first measurement of recall/precision/FPR against MSCI-containing 60s
   windows. TEST is NOT read or scored without a separate, explicit
   go-ahead — same discipline as every prior experiment.
5. **Erratum cross-reference:** EXP-0026's `p_mean_shift` contamination
   (neighbouring-window CMRI injections producing ~3.36e38 values) is
   documented in EXPERIMENT_LOG.md/DECISION_LOG.md as of this same session,
   prior to this pre-registration. EXP-0027 does not use `p_mean_shift` at
   all (scope is `p_std` only, per the diagnostic that motivated this
   follow-up), so it is not at risk of the same contamination, but the
   co-occurring-category breakdown in step 3(c) will make it visible if a
   similar effect appears in `p_std` itself (it should not, since `p_std` only
   reads a window's OWN samples — pure-MSCI and pure-Normal windows by
   definition exclude CMRI frames; only the "mixed" cohort in step 3(b)/(c)
   could, in principle, include a window that ALSO contains a CMRI frame
   whose forged pressure inflates that window's OWN `p_std` — this is
   exactly the mechanism step 3(c) is designed to surface, not a bug to avoid
   but the actual object of study for the "mixed" population).
6. **Scope discipline.** New files only: `ml/exp0027_msci_realistic_population.py`,
   `tests/test_exp0027_msci_realistic_population.py`,
   `data/experiments/exp0027_msci_realistic_population.json`,
   `docs/EXP0027_RESULTS.md`. `ml/features_windowed.py`, `run_detector()`, the
   5s production pipeline, `ml/exp0026_window_size.py` (reused read-only, not
   modified), DoS Type 1's invalidated files, CMRI's closed files, Layer A,
   and `app.py` are not touched. `source` is never parsed, bound, filtered
   on, or used.
7. **Tests:** synthetic units for the co-occurring-category breakdown logic;
   full suite must pass, exact before/after count reported.
8. **Before any commit:** full diff and all real findings shown; wait for
   explicit go-ahead. No push without separate explicit go-ahead. No
   force-push ever. TEST-blindness discipline: VALIDATION only until
   explicitly approved to score TEST once, frozen.

## EXP-0027 execution outcome — TESTED — gate NOT PASSED; pure-cohort effect confirmed as a selection artifact, not a deployable signal (2026-09-12)

- **Identity check passed:** reproduced EXP-0026's pure-cohort d exactly
  (1.4263 vs reference 1.426, within tolerance) before trusting anything new.
- **The three populations:** pure MSCI vs pure Normal d=+1.426 (n=117, large);
  ALL MSCI-containing (pure+mixed) vs pure Normal d=+0.448 (n=310, small);
  mixed-only vs pure Normal d=+0.697 (n=193, medium).
- **Gate: NOT PASSED.** `|d| >= 0.5` required on the realistic (all-
  containing) population; got 0.448. Per the pre-registration: STOP, no
  detector built.
- **Explained, not just observed, why pooling drops below both sub-
  populations:** pure (1.426) and mixed (0.697) each show a real effect, but
  "MSCI-containing" is a heterogeneous mixture of different distributions
  depending on co-occurrence — pooling inflates the combined group's variance
  more than it moves the mean, which is exactly what Cohen's d penalizes.
- **Step 2c breakdown by co-occurring category, with an honest data-quality
  caveat:** 36/310 (12%) of containing windows have `p_std` > 1e6, all in
  groups co-occurring with CMRI (naive out-of-bounds response injection —
  real attack data, not a bug, consistent with the `p_mean_shift` erratum
  below). **Informational cross-check (does not change the gate) shows CMRI
  co-occurrence is NOT the reason the gate fails** — excluding every
  CMRI-co-occurring window entirely drops d further, to 0.178, confirming
  population-heterogeneity pooling is the dominant mechanism, not CMRI
  contamination.
- **Honest interpretation: the pure-cohort effect is a real, verified,
  non-small-n-noise effect that is nonetheless a selection artifact — not a
  deployable signal**, because a real detector cannot select for "pure"
  windows in advance. This closes the MSCI-60s-`p_std` standalone-detector
  lead. Does not reopen ACK-001/002 or invalidate EXP-0026's primary
  (containing-cohort, all sizes) findings.
- **TESTED.** Full suite **293 → 303 passed** (10 new: 9 fast synthetic units
  + 1 slow saved-result replay). `ml/features_windowed.py`, `run_detector`,
  the 5s production pipeline, `ml/exp0026_window_size.py` (reused read-only),
  DoS Type 1's invalidated files, CMRI's closed files, Layer A, `app.py`
  unchanged. `source` never parsed/used (asserted by a static-analysis test).
- New files only: `ml/exp0027_msci_realistic_population.py`,
  `tests/test_exp0027_msci_realistic_population.py`,
  `data/experiments/exp0027_msci_realistic_population.json`,
  `docs/EXP0027_RESULTS.md`.
- Saved result:
  [exp0027_msci_realistic_population.json](../data/experiments/exp0027_msci_realistic_population.json),
  summary [EXP0027_RESULTS.md](EXP0027_RESULTS.md).

## EXP-0028 execution outcome — TESTED — NO-GO; trajectory-matching (DTW/discord) fails both bars, fourth and closing CMRI angle (2026-09-13)

- **Pre-registration:** DTW / matrix-profile-style discord distance from a
  candidate window's trailing pressure sub-sequence to a Normal reference
  library built from TRAIN only, as a shape-based alternative to the
  single-point / single-derivative CMRI angles EXP-0018/0019/0020 already
  closed. Reused the frozen manifest and EXP-0017's window definition (no
  rederivation); threshold fit on VAL only; TEST scored exactly once.
- **Library implementation:** `dtaidistance`/`stumpy` pip installs did not
  finish inside the session's time budget (slow network). DTW is a
  hand-written, numpy-batched O(n·m) dynamic program; discord is a
  z-normalized Euclidean nearest-neighbor distance to the same library
  (equals the matrix-profile distance for fixed-length, non-warped
  sub-sequences). Both spot-checked against hand-computed small cases.
- **Compute-tractability cap, fixed before any VAL/TEST score:** the raw
  Normal library (14,148 length-15 sub-sequences from TRAIN-normal
  contiguous runs, after dedup) made an unbounded batched DTW against
  ~10k+ VAL/TEST candidates intractable (an earlier unbounded run was
  killed after >10 minutes, >2 GB RSS, no output). Deterministically
  subsampled to 300 library rows (fixed seed) before any score was computed.
- **Step 3 artifact check — clean, no gate needed:** pure-Normal windows
  following an attack-labelled predecessor vs pure-Normal windows with an
  in-bounds predecessor showed no meaningful DTW/discord inflation (DTW
  d=+0.128, discord d=+0.010; discord p=0.60). The EXP-0019 "returning to
  normal" artifact does NOT reappear here; VAL/TEST scored ungated.
- **VAL threshold selection:** DTW threshold 8.3283 (VAL Normal FPR 0.2577%,
  VAL pure-CMRI recall 4.60%); discord threshold 3.8895 (same FPR, 0.00%
  recall). DTW selected as primary (higher VAL recall), fixed before TEST.
- **TEST scored once:** DTW (primary) — Normal FPR 0.4630%, pure-CMRI recall
  7.68% (92/1198), dominant 6.79%, containing 6.90%. discord — FPR 0.1984%,
  pure-CMRI recall 0.08% (1/1198).
- **Decision-rule verdict: `NO-GO`** — fails BOTH pre-registered bars: TEST
  pure-CMRI recall (7.68%) does not beat the 54.59% PressureBoundsRule
  baseline, and Normal FPR (0.4630%) exceeds the 0.30% bar. No amendment to
  the decision rule after seeing TEST results. Per the pre-registration,
  window length / distance metric / library size were NOT iterated as a
  post-hoc rescue.
- **This closes the CMRI missed-detection line** (fourth angle after
  EXP-0018 residual smoothness, EXP-0019 raw rate-of-change, EXP-0020 gated
  rate-of-change — all CLOSED / negative or marginal). `run_detector`,
  `app.py` and all protected EXP-0005..0027 files unchanged.
- **Deliverables note:** the spec asked for a NO-GO summary to be appended to
  a "Major saga #3: CMRI" section of `docs/overview.md`. Neither that file
  nor any "Major saga" text exists anywhere in this repository (searched
  recursively) — flagged rather than invented; this log entry plus
  `docs/experiments/EXP-0028_RESULTS.md` serve as the record instead.
- **TESTED.** Full suite **303 → 322 passed** (19 new: 18 fast synthetic
  units + 1 slow saved-result replay). No raw data read in fast tests.
- New files only: `ml/exp0028_cmri_trajectory.py`,
  `tests/test_exp0028_cmri_trajectory.py`,
  `data/experiments/exp0028_cmri_trajectory.json`,
  `docs/experiments/EXP-0028_RESULTS.md`.
- Saved result:
  [exp0028_cmri_trajectory.json](../data/experiments/exp0028_cmri_trajectory.json),
  summary [EXP-0028_RESULTS.md](experiments/EXP-0028_RESULTS.md).

## EXP-0029 execution outcome — TESTED — NO-GO; regime-aware rolling baseline fails the mandatory diagnostic for NMRI (2026-09-13)

- **Pre-registration:** causal rolling median/MAD relative-deviation z-score
  `z_t = (P_t - median(P[t-k:t-1])) / (MAD(P[t-k:t-1]) + epsilon)` over
  decoded pressure, candidate window sizes k = 5, 10, 20 samples fixed before
  any VAL/TEST score, targeting the 150/715 (23.4%) pure-NMRI TEST windows
  EXP-0017 misses despite being inside the EXP-0016 global pressure bounds.
  Explicitly a different baseline model from EXP-0019/0020's rate-of-change
  framing (no elapsed-time division). Secondary generalization check
  pre-registered for CMRI, same rule, same EXP-0028 bar (54.59% pure-CMRI
  recall / 0.30% FPR).
- **Identity gates:** all passed — EXP-0017 artifact checksum-verified,
  `comb == protocol | pressure | IF` element-wise, whole-TEST confusion
  4767/40/2166/2374, EXP-0016 bounds `[0.482759, 38.7471]` unchanged, split
  manifest identity matches. The 150 known pure-NMRI false negatives were
  re-derived directly from the artifact (`comb_pred == 0` on the pure-NMRI
  TEST cohort) and matched the pre-registered figure exactly (150/150) — no
  ambiguity, EXP-0017's combined result was reproducible.
- **Step 2 mandatory diagnostic (before any detector built) — FAILED:**
  Cohen's d between `|z_t|` for the 150 known false negatives and pure-Normal
  TEST windows was negligible for every candidate: k=5 d=+0.075 (p=0.80),
  k=10 d=+0.052 (p=0.046), k=20 d=+0.040 (p=5.07e-08). Best candidate (k=5,
  by effect size) is far below the pre-registered `d >= 0.5` bar. Two
  candidates reach statistical significance at the repo's large TEST sample
  size despite a negligible effect size — reported honestly per the EXP-0014
  standard rather than treated as support.
- **Steps 3-5 (VAL threshold fit, artifact check, CMRI generalization) were
  NOT performed** — per the pre-registered decision rule, a diagnostic
  effect size below 0.5 is a NO-GO that closes the line before any detector
  is built; window size k was **not** iterated further as a post-hoc rescue.
- **Decision-rule verdict: NMRI `NO-GO`, CMRI (secondary) `NO-GO`** — the
  CMRI check was not independently run because it depends on the same z_t
  feature that already failed the mandatory diagnostic for its primary
  (NMRI) target, per the fixed decision rule. No amendment to the decision
  rule after seeing results.
- **Deliverables note:** the spec's fallback `docs/overview.md` deliverable
  location does not exist anywhere in this repository (confirmed, same
  finding as EXP-0028) — flagged rather than invented; this log entry plus
  `docs/experiments/EXP-0029_RESULTS.md` serve as the record instead.
- **TESTED.** Full suite **322 → 341 passed** (19 new: 18 fast synthetic
  units + 1 slow saved-result replay). No raw data read in fast tests.
  `run_detector`, `app.py` and all protected EXP-0005..0028 files unchanged.
- New files only: `ml/exp0029_regime_baseline.py`,
  `tests/test_exp0029_regime_baseline.py`,
  `data/experiments/exp0029_regime_baseline.json`,
  `docs/experiments/EXP-0029_RESULTS.md`.
- Saved result:
  [exp0029_regime_baseline.json](../data/experiments/exp0029_regime_baseline.json),
  summary [EXP-0029_RESULTS.md](experiments/EXP-0029_RESULTS.md).

## EXP-0032 execution outcome — TESTED — PROCEED-BOTH (NMRI) / PROCEED-BOTH (CMRI); admissible-information ceiling audit finds real signal after five prior NO-GOs (2026-09-13)

- **Pre-registration:** diagnostic-only probe (NOT a detector build) asking
  whether ANY signal recoverable from admissible pressure-byte features
  exists for the residual NMRI/CMRI false negatives, after EXP-0018 (AR(1)
  residual energy), EXP-0019 (rate-of-change plausibility), EXP-0020
  (rate-bound gated on in-bounds predecessor), EXP-0028 (DTW/discord
  trajectory matching) and EXP-0029 (regime-local median/MAD baseline) were
  all NO-GO. Three feature families pre-registered: F1 (numeric
  pressure/derivative, baseline sanity), F2 (IEEE-754 representation —
  exponent, mantissa bit pattern, ULP distance to nearest TRAIN-normal
  value, quantization/ADC-lattice distance, local mantissa entropy), F3
  (event-level trailing-buffer distribution — quantiles, skew/kurtosis,
  repetition rate, entropy, Wasserstein-1 distance to TRAIN-normal). An
  `XGBClassifier` was used purely as a flexible information probe, per
  family and combined, per attack type (NMRI, CMRI), with a fixed decision
  rule: VAL event-grouped-bootstrap recall-at-<=0.30%-FPR 95% CI lower bound
  must exceed a label-permutation null's 95th percentile.
- **Identity gates:** all passed — EXP-0017 artifact checksum-verified,
  `comb == protocol | pressure | IF` element-wise, whole-TEST confusion
  4767/40/2166/2374, EXP-0016 bounds `[0.482759, 38.7471]` unchanged, split
  manifest identity matches. Known TEST false negatives re-derived exactly:
  pure-NMRI 150, pure-CMRI 544.
- **Adaptation disclosed (same convention as EXP-0028's dtaidistance
  substitution):** the frozen EXP-0017 artifact only carries `comb_pred` for
  TEST. TRAIN/VALIDATION residual cohorts are approximated via the
  EXP-0016 pressure-bounds component ALONE (the only cheaply, exactly
  reproducible rule piece outside the frozen TEST artifact), since
  reproducing the full combined rule for TRAIN/VAL would require calling
  `run_detector`, forbidden beyond the frozen-artifact identity gate. TEST
  itself uses the exact frozen `comb_pred`. Documented as a mild
  over-approximation of the true TRAIN/VAL residual population, a
  limitation, not a silent shortcut.
- **Results — NMRI:** VAL recall-at-fixed-FPR (bootstrap 95% CI) vs
  permutation-null p95: F1 49.13% [38.67,60.23]% vs null 1.24% (clears); F2
  12.72% [8.57,18.61]% vs null 1.79% (clears); F3 4.62% [1.09,8.07]% vs
  null 0.58% (clears); combined 71.68% [54.87,80.65]% vs null 0.00%
  (clears). Combined model dominated by `ulp_distance_to_train_normal`
  (importance 0.825, F2). TEST scored once (honest, not decision-rule
  input): combined-model recall 58.0% (87/150), Normal FPR 0.42%
  (20/4,957).
- **Results — CMRI:** F1 76.91% [69.64,82.87]% vs null 2.72% (clears); F2
  14.80% [9.27,20.75]% vs null 1.80% (clears); F3 9.87% [3.96,16.97]% vs
  null 0.71% (clears); combined 73.77% [65.84,80.37]% vs null 0.72%
  (clears). Combined model again dominated by `ulp_distance_to_train_normal`
  (importance 0.828, F2). TEST scored once: combined-model recall 80.5%
  (438/544), Normal FPR 0.60% (29/5,351).
- **Feature-causality audit:** every top-10-importance feature in both
  combined models is derived directly from the decoded egress pressure
  value (raw or IEEE-754 bit-level), strictly causal (trailing-buffer or
  predecessor only), and uses no label information indirectly. No
  `source`, `crc_rate`, or testbed-collection metadata referenced anywhere
  in the feature code (enforced by an automated forbidden-field test, same
  as EXP-0028/0029). Audit: **clean** for both attack types.
- **Decision-rule verdict: NMRI `PROCEED-BOTH`, CMRI `PROCEED-BOTH`** — F2
  (dominant in the combined model) clears the bar for both attack types
  with a clean causality audit -> PROCEED-0030 condition satisfied for
  both; F3-only also independently clears the bar (narrowly) with distinct
  winning features (quantile/entropy/max-gap statistics) -> PROCEED-0031
  condition also satisfied for both. Per the fixed pre-registration this
  is reported as PROCEED-BOTH for both attack types; EXP-0030 and EXP-0031
  remain separate, later pre-registered detector-build decisions — nothing
  was wired.
- **Honesty notes (see EXP-0032_RESULTS.md for full discussion):** F1
  (raw pressure/derivative, the same feature family EXP-0018/19/20 already
  tested with single-threshold rules) also clears the bar with a high
  point estimate — not a contradiction of those NO-GOs, since a
  gradient-boosted classifier can carve multiple non-monotone regions out
  of the same raw features, a materially different hypothesis class than
  a single global threshold. The dominant F2 signal
  (`ulp_distance_to_train_normal`) is measured against this one testbed's
  specific attack-generation tooling; whether it generalizes to a
  different forging method is flagged explicitly as unresolved, not
  claimed. The TRAIN/VAL residual-cohort proxy (pressure-bounds-alone) is
  a real limitation whose effect is bounded by comparing against the
  once-scored, exact-cohort TEST number. F3's clearance is comparatively
  weak (narrow margins over a small null) and should be treated as a weak
  positive by whoever pre-registers EXP-0031.
- **Deliverables note:** the spec's fallback `docs/overview.md` deliverable
  location does not exist anywhere in this repository (confirmed, same
  finding as EXP-0028/0029) — flagged rather than invented; this log entry
  plus `docs/experiments/EXP-0032_RESULTS.md` serve as the record instead.
- **TESTED.** Full suite **341 → 376 passed** (35 new: 34 fast synthetic
  units + 1 slow saved-result replay). No raw data read in fast tests.
  `run_detector`, `app.py` and all protected EXP-0005..0029 files
  unchanged.
- New files only: `ml/exp0032_admissible_ceiling_audit.py`,
  `tests/test_exp0032_admissible_ceiling_audit.py`,
  `data/experiments/exp0032_admissible_ceiling_audit.json`,
  `docs/experiments/EXP-0032_RESULTS.md`.
- Saved result:
  [exp0032_admissible_ceiling_audit.json](../data/experiments/exp0032_admissible_ceiling_audit.json),
  summary [EXP-0032_RESULTS.md](experiments/EXP-0032_RESULTS.md).

## EXP-0032b execution outcome — TESTED — CORRECTED re-run; PROCEED-0030 (NMRI) / PROCEED-0030 (CMRI); EXP-0032's PROCEED-BOTH is PARTIALLY SUPERSEDED — PROCEED-0031 not confirmed for either attack type (2026-09-13)

- **Pre-registered amendment context:** EXP-0032's `PROCEED-BOTH` verdict was
  SUSPENDED (not accepted) pending this corrected re-run, per three
  disclosed flaws in EXP-0032 itself: (1) the VAL/TRAIN decision-rule
  cohort used a pressure-bounds-only proxy, not the true protocol+pressure+
  Isolation Forest residual; (2) bootstrap/permutation controls were
  reduced (60/20 vs the spec's 200/50-200); (3) no leave-one-attack-run-out
  generalization check existed for the dominant feature
  `ulp_distance_to_train_normal` (~0.83 importance).
- **Fix 1 (corrected cohort):** new `FrozenExp0017Detector`
  (`ml/exp0032b_ceiling_audit_corrected.py`) reproduces EXP-0017's true
  combined rule (protocol OR pressure-bounds OR Isolation Forest) for
  TRAIN, VALIDATION, and TEST — not approximated. Reuses every frozen
  scalar from the EXP-0017 artifact unchanged (mu, sd, threshold,
  valid_func_codes, valid_addresses, pressure_bounds); only the Isolation
  Forest is refit in-process (identical hyperparameters/seed), verified by
  EXACT element-wise agreement with the frozen TEST if_pred/protocol_pred/
  pressure_pred/comb_pred and the frozen TEST confusion (4767/40/2166/2374)
  before anything else ran. `run_detector()` itself was NEVER called.
  Cohort-size effect was small: corrected residual-positive counts were
  2-14 rows lower than EXP-0032's proxy (≤1.1% of cohort) — a real,
  disclosed flaw, but not the reason the verdict below changes.
- **Fix 2 (restored controls):** bootstrap restored to the full spec value
  (200; cheap, resamples already-computed scores); permutation draws
  restored to 50 (spec's disclosed 50-200 low end, for session
  compute-time tractability — full run took ~751s). Reduced (60/20) and
  restored (200/50) counts were BOTH run on the corrected cohort and
  agreed on every family's clears/does-not-clear result for both attack
  types — control strength was NOT the reason the verdict changed either.
- **Full-strength (200/50) per-family results — NMRI:** F1 49.71%
  [39.45,61.17]% vs null 1.17% (clears); F2 11.70% [5.71,17.75]% vs null
  3.30% (clears); F3 3.51% [0.00,8.16]% vs null 1.55% (does NOT clear);
  combined 78.36% [65.97,89.14]% vs null 1.17% (clears). TEST scored once:
  combined recall 60.0% (90/150), Normal FPR 0.478%.
- **CMRI:** F1 77.32% [70.10,84.97]% vs null 4.65% (clears); F2 24.26%
  [17.14,30.70]% vs null 2.85% (clears); F3 11.11% [3.25,19.42]% vs null
  2.39% (clears); combined 69.16% [60.17,78.24]% vs null 2.17% (clears).
  TEST scored once: combined recall 76.47% (416/544), Normal FPR 0.707%.
  Dominant feature both attacks: `ulp_distance_to_train_normal` (F2),
  causality audit clean.
- **Fix 3 (leave-one-attack-run-out) — the check that changed the
  verdict:** residual-positive rows pooled TRAIN+VAL (disclosed, this
  sub-check only), grouped into contiguous-window-index attack "runs" (≥3
  examples), each run held out and its OWN recall measured after retraining
  without it. F2 (`ulp_distance_to_train_normal`): NMRI 66 runs, mean
  94.06% recall, std 9.59pp, min 50%, max 100% — **not run-dependent**.
  CMRI: 107 runs, mean 95.29%, std 8.13pp, min 50%, max 100% — **not
  run-dependent**. F3 (distribution features): NMRI 66 runs, mean 17.65%,
  std **26.61pp**, range 0-100% — **run-dependent**. CMRI: 107 runs, mean
  22.53%, std **34.40pp**, range 0-100% — **run-dependent**. F2 generalizes
  robustly across dozens of held-out attack episodes; F3 does not — exactly
  the distinction EXP-0032's own honesty notes flagged as unresolved.
- **Corrected decision-rule application:** each verdict component (F2 ->
  PROCEED-0030, F3 -> PROCEED-0031) is gated by ITS OWN family's LORO
  result, not just whichever family dominates the combined model's
  importances (an earlier draft of this correction let CMRI's independently
  F3-clearing PROCEED-0031 ride through ungated on F2's generalization
  result alone — fixed before this was reported). NMRI: PROCEED-0030
  clears (F2 generalizes); PROCEED-0031 never cleared the bar in the first
  place (F3 does not clear permutation null for NMRI) -> **PROCEED-0030**.
  CMRI: PROCEED-0030 clears (F2 generalizes); PROCEED-0031 clears the
  permutation-null bar but F3 fails the LORO gate -> PROCEED-0031
  RETRACTED for CMRI -> **PROCEED-0030**.
- **FINAL VERDICT: PROCEED-0030 (NMRI) / PROCEED-0030 (CMRI).** This
  PARTIALLY SUPERSEDES EXP-0032's original `PROCEED-BOTH` finding for both
  attack types (docs/experiments/EXP-0032_RESULTS.md, entry above,
  untouched/not edited per this project's append-only discipline): the
  EXP-0030 (float-provenance / `ulp_distance_to_train_normal`) candidate is
  CONFIRMED and now more solidly supported than EXP-0032 knew (cohort-
  corrected, control-restored, generalization-tested across 66-107
  held-out attack episodes with no run-dependence). The EXP-0031
  (event-level distribution fingerprint) candidate is **NOT CONFIRMED**
  for either attack type — it clears the (weak) permutation-null bar
  exactly as EXP-0032 found, but fails the leave-one-attack-run-out
  generalization check, meaning it is a real but run-specific effect, not
  an admissible population-level signal. EXP-0031 should NOT be separately
  pre-registered as a detector build on EXP-0032's evidence alone. Per the
  pre-registered amendment this verdict is final for this line: no further
  amendments.
- **Honesty notes:** Fix 1 and Fix 2 did not change the outcome (small
  cohort effect; stable across control strengths) — Fix 3 is what changed
  it, and it is exactly the check EXP-0032's own write-up flagged as
  missing. The refit Isolation Forest inside `FrozenExp0017Detector` is not
  a stored object (none exists in the frozen artifact); its exact TEST
  element-wise match against the frozen `if_pred` is the strongest
  available evidence the refit is faithful on TRAIN/VAL too, disclosed as
  a residual limitation. `run_detector()`, `app.py`, and all protected
  EXP-0005..0032 files unchanged.
- **TESTED.** New files only: `ml/exp0032b_ceiling_audit_corrected.py`,
  `tests/test_exp0032b_ceiling_audit_corrected.py`,
  `data/experiments/exp0032b_ceiling_audit_corrected.json`,
  `docs/experiments/EXP-0032b_RESULTS.md`.
- Saved result:
  [exp0032b_ceiling_audit_corrected.json](../data/experiments/exp0032b_ceiling_audit_corrected.json),
  summary [EXP-0032b_RESULTS.md](experiments/EXP-0032b_RESULTS.md).

### EXP-0030
- Experiment ID: EXP-0030
- Date: 2026-09-13
- Dataset: egress traffic extracted from Mississippi State ICS testbed dataset, used as a
  simulated diode-observer view (never real diode capture data); same frozen manifest as
  EXP-0017/EXP-0025/EXP-0032/EXP-0032b.
- Framing (repeated intentionally): this is **float/representation-provenance detection**,
  NOT physical-anomaly detection — the signal most likely reflects a forged pressure value
  being produced by a different quantization/generation pipeline than the real sensor.
- What this is: the first ACTUAL DETECTOR BUILD (not a diagnostic probe) for the
  `ulp_distance_to_train_normal` IEEE-754 float-representation signal EXP-0032 discovered
  and EXP-0032b confirmed (run-independent, leave-one-attack-run-out recall never below
  50%, mean ~94-95%, across 66 NMRI / 107 CMRI held-out episodes).
- Method: `ml/exp0030_float_provenance_detector.py`. `FrozenCombinedWithRateDetector`
  extends EXP-0032b's `FrozenExp0017Detector` with EXP-0025's `RateFloodRule` term,
  reproducing the CURRENTLY WIRED combined detector (protocol OR pressure-bounds OR rate
  OR Isolation Forest — `data/experiments/exp0025_detector.json`), verified element-wise
  against that frozen artifact before anything else was trusted. F2-only feature set
  (IEEE-754 bit-structure features), one `XGBClassifier` per attack type (NMRI, CMRI),
  threshold fit on VAL to keep VAL Normal FPR ≤ 0.30%. `F2_NAMES`, `SeriesIndex`,
  `build_cohort_frame`, `nearest_reference_distance` reused unchanged from EXP-0032;
  `_dataset_for`, `_run_family`, `leave_one_run_out` reused unchanged from EXP-0032b.
- Results: VAL clears the permutation-null bar for both attacks (NMRI 11.70%
  [5.40%,17.50%] CI; CMRI 24.26% [16.78%,30.51%] CI). Leave-one-attack-run-out on the
  FINAL FITTED model matches EXP-0032b's raw-feature finding almost exactly (NMRI: 66
  runs, mean 94.06%, no run-dependence; CMRI: 107 runs, mean 95.29%, no run-dependence).
  TEST (scored once): baseline (currently wired) confusion (4767, 40, 2166, 2374), FPR
  0.832%. Adding the float-provenance rule: (4740, 67, 1923, 2617), FPR 1.394% — marginal
  contribution +243 TP / +27 FP. Pure-cohort TEST recall: NMRI 79.02% → 83.50% (+4.48pp),
  CMRI 54.59% → 66.61% (+12.02pp).
- Decision: **NO-GO for both NMRI and CMRI.** Per the pre-registered decision rule
  (system-wide combined-detector Normal FPR must stay ≤ 0.30% after adding this rule), the
  resulting absolute FPR (1.394%) exceeds the bar — but honestly, the bar was ALREADY
  broken by the currently-wired baseline (0.832%) before this rule was ever added; this is
  a disclosed specification gap discovered during execution, not a flaw in the
  float-provenance signal itself, which passed every other gate (recall improvement, VAL
  permutation-null bar, leave-one-run-out generalization on the fitted model) cleanly for
  both attack types. Per "no amendments after seeing TEST results," this is scored NO-GO
  as literally specified. **No production code was modified** — `ml/rules.py` and
  `ml/iforest_detector.py` are untouched.
- Full test suite: 399/400 passing before and after (the 1 failure is a pre-existing,
  unrelated environment issue — a `pyarrow` DLL blocked by a local Windows Application
  Control policy in `test_exp0017_operational.py`'s dashboard test — confirmed unrelated
  since no file it depends on was touched this session).
- **TESTED.** New files only: `ml/exp0030_float_provenance_detector.py`,
  `tests/test_exp0030_float_provenance_detector.py`,
  `data/experiments/exp0030_float_provenance_detector.json`,
  `docs/experiments/EXP-0030_RESULTS.md`.
- Saved result:
  [exp0030_float_provenance_detector.json](../data/experiments/exp0030_float_provenance_detector.json),
  summary [EXP-0030_RESULTS.md](experiments/EXP-0030_RESULTS.md).

# RETRACTION — EXP-0030's original FPR bar was a spec error (2026-09-13)

EXP-0030's original decision rule required the FULL combined-detector Normal FPR to stay
≤ 0.30% after adding the float-provenance rule. That bar was copied from EXP-0032/0032b's
per-classifier VAL-threshold-fitting convention (a diagnostic-probe threshold, not a
system-wide SLA) and misapplied as an absolute ceiling on the production combined detector.
The production baseline (protocol OR pressure OR rate OR IF, EXP-0025) already runs at
0.832% FPR — already 2.8x over that bar before EXP-0030's rule was ever added — so no
detector could ever have passed under the literal bar. EXP-0030's NO-GO verdict, scored
under that literal (broken) bar per this project's "no amendments after seeing TEST
results" discipline, is **retracted for that specific reason: corrected FPR bar spec
error, see EXP-0030b.** The original EXP-0030 entry above is kept, unedited, for the
historical record — this is an append-only correction, not a rewrite.

# EXP-0030b — Corrected re-score of EXP-0030 against a proper isolated-marginal bar —
# PARTIAL-GO (CMRI), NO-GO (NMRI, different reason) (2026-09-13)

Pre-registered AMENDMENT (not a new experiment, not a retrain): re-evaluates EXP-0030's
already-obtained TEST predictions (`data/experiments/exp0030_float_provenance_detector.json`)
against a corrected bar. No retraining, no TEST re-scoring, no change to
`exp0030_float_provenance_detector.py` or its saved JSON artifact.

- Corrected decision rule: no fixed absolute ceiling on total combined FPR (reported
  plainly, flagged for human demo-readiness decision instead). Gate that applies: the float
  rule's ISOLATED marginal trade ratio (marginal TP / marginal FP, isolated from the other
  rules' overlap the same way EXP-0017 isolates a rule's own marginal contribution) must be
  ≥ 3:1, independently per category (NMRI, CMRI).
- Isolation methodology: reproduced EXP-0017's own attribution style (before/after OR-ing
  a term onto the rest of the already-wired chain, in wiring order) on EXP-0017's frozen
  TEST arrays for the IF term specifically (protocol OR pressure, then adding IF):
  protocol|pressure = (4803, 4, 2192, 2348); protocol|pressure|IF (comb) = (4767, 40, 2166,
  2374). **EXP-0017's own IF isolated marginal: +26 TP / +36 FP = 0.72:1** — worse than
  break-even, disclosed explicitly as the historical comparison point (not assumed to
  already meet 3:1).
- For a monotonic two-term OR, "isolated marginal restricted to windows the rest of the
  chain misses" is mathematically identical to the plain before/after delta (no possible
  overlap-inflation for a two-way union) — so EXP-0030's already-reported combined delta
  (+243 TP / +27 FP) IS the correctly isolated combined marginal. **Combined isolated
  ratio: 243/27 = 9.00:1** — clears 3:1 and beats EXP-0017's own accepted 0.72:1 IF ratio.
- Per-category isolated TP splits exactly from the saved pure-cohort recall-gain figures:
  NMRI +32 TP (n=715 pure), CMRI +144 TP (n=1198 pure), remaining +67 TP from
  mixed-category (non-pure) windows unattributed to either. FP cannot be split per category
  from the saved artifact (per-classifier fire arrays were never serialized; Normal windows
  carry no NMRI/CMRI label) — disclosed as a genuine limitation, not resolved by
  re-scoring (out of this amendment's scope). Conservative worst-case bound (charging the
  full +27 FP to each category independently, a valid upper bound on each category's true
  FP cost): **NMRI 32/27 = 1.19:1 (fails 3:1); CMRI 144/27 = 5.33:1 (clears 3:1)**.
- Leave-one-run-out re-confirmed unchanged and independent of the FPR question (NMRI 66
  runs mean 94.06% std 9.59% not run-dependent; CMRI 107 runs mean 95.29% std 8.13% not
  run-dependent) — no double-counting interaction found between the two checks.
- **Verdict: PARTIAL-GO (CMRI only).** CMRI — GO, reason "corrected FPR bar spec error,
  see EXP-0030b," supersedes EXP-0030's original NO-GO for CMRI. NMRI — NO-GO, reason
  "isolated trade-quality shortfall" (a DIFFERENT, now-correct reason than EXP-0030's
  original spec-bug NO-GO); NMRI's true ratio is unresolved (bounded between 1.19:1 worst
  case and unbounded best case) without re-scoring, and per pre-registered discipline
  ambiguity is not resolved in the category's favor.
- Total resulting FPR with the rule added, as originally scored in EXP-0030 (both
  NMRI+CMRI models): 1.394% (TN 4740 / FP 67), up from the 0.832% wired baseline. **Flagged
  plainly for Navin's demo-readiness/precision trade-off decision — not auto-decided here.**
- Wiring: **NOT performed.** The float-provenance rule is a fitted XGBClassifier over 7
  IEEE-754 bit-structure features not currently computed anywhere in the production
  feature pipeline, and the fitted CMRI classifier itself was never serialized to disk
  (only aggregate stats were saved) — reconstructing it requires re-running the
  deterministic fit, which is confirmed bit-identical but still falls under "do not
  re-run the model" for this amendment's scope. This is surfaced as a genuine architectural
  gap: `ml/rules.py` and `ml/iforest_detector.py` are UNCHANGED. Recommended follow-up:
  a separate pre-registered "EXP-0030c — CMRI float-provenance rule production wiring."
- Full test suite: 399/400 passing, unchanged (only docs touched this session; confirmed
  by direct re-run, same pre-existing pyarrow/DLL failure in
  `test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation`).
- **TESTED (re-analysis of an existing frozen artifact; no new run).** New file:
  `docs/experiments/EXP-0030b_RESULTS.md`. No source or data files modified.
- Saved result: no new JSON artifact (this amendment re-analyzes
  `data/experiments/exp0030_float_provenance_detector.json` in place); summary
  [EXP-0030b_RESULTS.md](experiments/EXP-0030b_RESULTS.md).

# EXP-0030c — CMRI-only float-provenance rule: PRODUCTION WIRING (2026-09-14)

**ORDERING IRREGULARITY, disclosed explicitly:** this PLANNED entry is being appended
RETROACTIVELY, at the point the run was already underway (the task arrived from the
orchestrator with method/decisions already specified and user-approved) — it should have
preceded the run per this project's standing "pre-registration first" discipline. Both this
PLANNED entry and the TESTED entry below are appended together, in the same session, rather
than smoothed over as if pre-registration had happened on time.

- PLANNED: turn EXP-0030b's CMRI-only paper verdict (isolated marginal ratio worst-case
  5.33:1, GO; NMRI worst-case 1.19:1, NO-GO, out of scope) into a real production artifact —
  materialize the F2 (IEEE-754 bit-structure) feature pipeline into `ml/`, retrain + serialize
  a CMRI-only XGBoost classifier, wire it as a new OR-term in `ml/rules.py` /
  `ml/iforest_detector.py`, refresh the `exp0017_detector.json` / `exp0025_detector.json`
  identity-ledger checksums for the two touched source files only (payload/result untouched),
  leave-one-run-out re-check on the freshly retrained model, score TEST exactly once as a
  single deliberate exception (a fresh serialization/reproducibility touch on the SAME
  already-evaluated hypothesis, not a new hypothesis test), CMRI ONLY throughout.

# EXP-0030c — CMRI-only float-provenance rule: PRODUCTION WIRING — GO, wired (2026-09-14)

Precondition 2 (independent confirmation of the previously "known-failing"
`test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation`)
came back **contradicting the prior memory note**: the test PASSED on both the reverted
(`git stash`) state and the current state (400/400 full-suite passing on the reverted state).
The coordinator confirmed with the user this finding is correct, corrected the stale memory
note, and set 400/400 as the new "no regressions" baseline for this experiment.

Identity-ledger refresh performed on BOTH `data/experiments/exp0017_detector.json` and
`data/experiments/exp0025_detector.json` (the latter not named in the original brief but
structurally required — it independently SHA-256-tracks `ml/rules.py` /
`ml/iforest_detector.py` too) — `source_sha256` entries for the two touched files updated
only; `result`/`payload` byte-for-byte unchanged, confirmed by structural diff against the
pre-refresh git-tracked version.

Retrained a CMRI-only `XGBClassifier` on the TRAIN residual cohort (windows the currently-
wired protocol|pressure|rate|IF chain already misses, `cmri_pure`, F2 features only),
threshold fit on VAL (0.268% achieved Normal FPR). Serialized via XGBoost's native JSON
format to `data/artifacts/exp0030c_cmri_float_provenance_model.json` (fixed a real bug in
the temp-file rename pattern that silently broke XGBoost's format auto-detection). Built and
persisted a versioned TRAIN-normal reference set (`data/experiments/
exp0030c_train_normal_reference.json`, 2387 values), independently re-derived from scratch
and confirmed identical. Leave-one-attack-run-out on the freshly retrained model: 107 runs,
mean recall 95.29%, std 8.13%, **not run-dependent** — matches EXP-0030b's cited figures.

**Scored TEST exactly once** (this experiment's own single, deliberate final touch for the
newly retrained/serialized artifact, per user-approved exception — distinct from EXP-0030/
0030b's already-spent touches on the earlier unserialized research model):

- Baseline (protocol|pressure|rate|IF, EXP-0025 wired): TN 4767 / FP 40 / FN 2166 / TP 2374
  (FPR 0.832%, recall 52.29%).
- Baseline OR CMRI-float rule: TN 4749 / FP 58 / FN 2002 / TP 2538 (FPR 1.207%, recall 55.90%).
- **Isolated marginal: +164 TP / +18 FP = 9.11:1** — EXACT (not a worst-case bound, unlike
  EXP-0030b's 5.33:1, because only the CMRI classifier exists in this experiment; no NMRI
  model to conflate FP with) and clears the 3:1 bar comfortably, beating even the historical
  bound.
- CMRI pure-cohort recall: 54.59% -> 63.52% (+8.93pp, n=1198) — smaller than EXP-0030's
  combined NMRI+CMRI figure (->66.61%) because this rule is CMRI-only; expected, disclosed.
- Total resulting FPR: 0.832% -> 1.207% with the rule added. Flagged for the human's
  demo-readiness/precision decision, not auto-decided.

**Decision rule (fixed before running): GO iff isolated ratio >= 3:1 AND leave-one-run-out
generalizes. Both hold. Verdict: GO — wired into production.** `ml/rules.py`
(`CmriFloatProvenanceRule`, additive) and `ml/iforest_detector.py` (`DetectorResult
.cmri_float_pred` field, new OR-term in `run_detector()`'s permanent definition for any
FUTURE fresh run — NOT called this session) remain wired; no unwind needed.

A real regression was found and fixed: `test_exp0017_operational.py
::test_synthetic_pipeline_fits_train_normal_only_and_test_changes_do_not_tune` broke because
the newly-wired CMRI code path inside `run_detector()` tried to read real raw data on a fully
synthetic fixture; fixed by extending that test's existing monkeypatch pattern to the new
data sources (`exp0019_pressure_rate_plausibility.align_egress_pressure_timeseries`,
`float_provenance_features.load_reference`/`load_model`), same lazy-import-driven
monkeypatch convention already used there for the other rules.

**Full test suite: 400/400 (corrected baseline, confirmed via precondition 2) -> 420/420
(400 + 20 new tests), zero regressions.**

- **TESTED — GO, wired.** New files: `ml/float_provenance_features.py`,
  `ml/exp0030c_cmri_production_wiring.py`, `tests/test_float_provenance_features.py`,
  `tests/test_exp0030c_cmri_production_wiring.py`, `docs/experiments/EXP-0030c_RESULTS.md`.
  Modified: `ml/rules.py`, `ml/iforest_detector.py` (additive wiring),
  `tests/test_exp0017_operational.py` (one fixture extended, no assertions weakened),
  `data/experiments/exp0017_detector.json` + `exp0025_detector.json` (identity-ledger
  checksum refresh only). `overview.md` was searched for and does not exist in this
  repository — the requested proposed-update deliverable could not be produced for that
  reason (flagged, not guessed).
- Saved result: [exp0030c_cmri_production_wiring.json](../data/experiments/exp0030c_cmri_production_wiring.json),
  summary [EXP-0030c_RESULTS.md](experiments/EXP-0030c_RESULTS.md).
- **No git commit or push performed in this session**, per instruction.
