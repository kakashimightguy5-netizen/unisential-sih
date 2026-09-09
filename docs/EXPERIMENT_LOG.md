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

Every model run, split, audit, and benchmark gets an entry here. EXP-0004 is the
current verified-dataset result. Retracted entries remain below only as an audit trail.

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
