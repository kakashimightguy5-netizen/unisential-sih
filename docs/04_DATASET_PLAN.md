# 04 — Dataset Plan

This document is the single source of truth for what data the project uses, how the
one-way constraint is simulated, and how leakage is prevented. It consolidates the
verified reconnaissance in `docs/00-dataset-provenance.md`,
`docs/02-feature-schema.md`, and `docs/03-data-split-protocol.md`. Every measured
figure below comes from `scripts/inspect_dataset.py` run 2026-09-01 and recorded in
`data/reconnaissance/`. Nothing is asserted from memory.

---

## Dataset Record

| Field | Value |
|---|---|
| **Name** | Mississippi State University SCADA Laboratory — **Gas Pipeline** dataset (Morris / Turnipseed testbed family) |
| **Author (ARFF header, verbatim)** | Ian Turnipseed; advisor Dr. Morris; header date "Fri Dec 19 09:53:19 2014" |
| **Commonly cited as** | Turnipseed (2015), MSU SCADA gas-pipeline dataset |
| **URL / reference** | Originating publication (held locally, `docs/references/turnipseed-2015-scada-dataset-thesis.pdf`): Turnipseed, I. P. *A New SCADA Dataset for Intrusion Detection System Research.* MS thesis, Mississippi State University, Aug 2015. https://scholarsjunction.msstate.edu/td/209 . Companion: Morris, Thornton & Turnipseed (2015). Historical distribution: T. Morris (UAH) ICS datasets page; DHS/IMPACT mirror (dataset 1322, DOI 10.23721/100/1504364). Canonical dataset **download page still to be recorded** before any public artifact. |
| **License / redistribution terms** | **No explicit licence exists** (checked 2026-09-02). Authors (UAH page) request *citation only*; the IMPACT mirror's "commercial allowed" tag is third-party and non-authoritative. See BLOCKER 4 below for the mitigation (raw data kept out of public repos; mandatory citation; team verifies terms before any public release). Does not block the internal demo. |
| **Protocols included** | Modbus-style (function-code field `function` with 28 distinct observed values; dominated by `3` = read and `16` = write-multiple) |
| **Attack classes included** | **`categorized result` {0..7}** (thesis Table 3.1 p.24 / Table 3.5 p.36): 0=Normal, 1=NMRI, 2=CMRI, 3=MSCI, 4=MPCI, 5=MFCI, 6=DoS, 7=Reconnaissance. **`specific result` {0..35}** (thesis Tables 3.6–3.8, pp.37–40): 0=Normal, 1–35 = 21 named attacks (setpoint / PID-param / pump / solenoid / system-mode / critical-condition / bad-CRC / clean-registers / device-scan / force-listen / restart / read-ID / function-code-scan / rise-fall / slope / random-value / negative-pressure / fast / slow). Full table in `docs/00-dataset-provenance.md` (BLOCKER 1). Verified against the local ARFF cross-tab. |
| **Normal traffic description** | A steady SCADA polling loop between a master and the gas-pipeline control equipment. Highly periodic; adjacent frames near-identical. |
| **Capture format in repo** | `data/raw/IanArffDataset.arff` — ARFF, relation `gas`, 20 attributes, **274,628 instances** (verified by direct parse, twice), 0 malformed rows, 0 exact-duplicate rows. `@data` starts at file line 31. **Thesis states 274,627** (§3.5 p.27) — a **+1-row discrepancy**, documented and not normalised (see `docs/00-dataset-provenance.md`). |
| **Time span** | 2014-12-15T22:22:43.170388Z → 2014-12-19T02:57:34.165377Z (~3.2 days), `time` strictly increasing in file order, microsecond resolution, 274,628 distinct timestamps, 0 duplicates. |
| **Supporting file** | `data/raw/gas_pipeline_raw.txt` — **different schema** (6 fields: `hexframe,categorized(0-7),specific(0-35),source,dest,timestamp`), 209,668 data rows, **self-labelled** (the 2026-09-01 "no labels" recon was wrong — see `00-dataset-provenance.md` §CORRECTION), **contains hex payload frames** (mean Shannon entropy 3.1327 bits/byte). Not row-aligned to the ARFF; no ARFF join key (BLOCKER 3) — but not needed, the TXT carries its own labels. Now the basis for the `ml/` windowed detector (EXP-0001/0002). |
| **Discarded file** | `data/processed/gas_pipeline_ml_ready.csv` — derived from the unlabelled text file, no label column, bakes in inter-arrival computed in raw order before filtering/splitting. **DISCARD — do not use as a pipeline input.** |

### Dataset Limitations (must be repeated in every doc that reports a result)

1. **This dataset does not capture real data-diode traffic patterns.** It is a
   bidirectional testbed capture. Results are **indicative, not definitive**, of
   real diode-observer performance.
2. **Label codebook — RESOLVED from the thesis (BLOCKER 1).** `binary result`
   0=normal / 1=attack; `categorized result` 0..7 = Normal/NMRI/CMRI/MSCI/MPCI/MFCI/
   DoS/Recon; `specific result` 0=normal, 1–35 per thesis Tables 3.6–3.8. Counts:
   `binary result` 0 → 214,580 (78.1%), 1 → 60,048 (21.9%) — matches thesis
   Table 3.11. Class imbalance (~1:3.6 attack:normal, and much larger within
   individual `specific result` values) must be handled in evaluation (report raw
   confusion counts, use PR-AUC, per-attack-type recall).
3. **Direction semantics — RESOLVED from the thesis (BLOCKER 2).** `command response`
   {0,1} splits 137,013 / 137,615. Thesis §3.5.2 (p.34): **"'0' for response or '1'
   for command."** Egress (outbound telemetry) = response = `command response == 0`.
4. **No raw payload bytes in the authoritative ARFF.** Payload entropy is computable
   only from `gas_pipeline_raw.txt`. That file has no join key to the *ARFF* labels
   (BLOCKER 3) — but it is **self-labelled**, so on the TXT egress path entropy IS
   evaluable against ground truth and is a headline IF feature (amended 2026-09-04,
   EXP-0002). On the ARFF path entropy stays demonstrable-only.
5. **Effectively single-source.** `address` is near-constant (value `4` on 274,026
   of 274,628 rows). "Per-source" windowing collapses to one logical source; the
   per-source design is retained for general PCAP input but is not stress-tested by
   this dataset.
6. **Instrumentation-artifact risk.** MSU testbed captures are documented to contain
   unintended artifacts that can make attacks trivially separable (`crc rate`,
   fixed `length` templates, tail function codes that appear exactly 40 times,
   field-presence bitmasks). The artifact audit
   (`docs/03-data-split-protocol.md`, and `09_TEST_VALIDATION_PLAN.md`) must pass
   before any metric is reported.
7. **`categorized result` / `binary result` / `specific result` are LABELS** — never
   model inputs. Using them as features is target leakage.

---

## Novelty Claim (stated explicitly, as in `00_PROJECT_CHARTER.md`)

To the best of the team's knowledge of the literature, **no published work has
reframed the Turnipseed / MSU SCADA gas-pipeline dataset as a one-way / diode-observer
anomaly-detection problem with no bidirectional request-response correlation.**
Prior work assumes full bidirectional visibility and often uses the process-variable
columns (attributes 4–14) directly. Our contribution is to (a) restrict observation
to a single (egress) direction, (b) drop the process-variable columns as
diode-invisible / artifact-suspect, and (c) detect compromise from behavioural
egress features alone. This is a modest but genuine and citable originality point.

We make **no claim** to possess real diode data. See "Simulation" below.

---

## Pipeline

```
RAW DATA
  data/raw/IanArffDataset.arff  (274,628 verified rows, read-only)
        │
        ▼
DIRECTION FILTERING  (egress-only)
  keep `command response == 0`  (RESPONSE = outbound telemetry = egress; thesis §3.5.2 p.34)
  discard `command response == 1` (COMMAND); record discarded count
  [kept configurable; `== 1` is a labelled sensitivity run, not the headline]
        │
        ▼
WINDOWING
  5-second time windows, grouped per source
  (single logical source for this dataset — limitation 5)
  windows computed WITHIN a split block only; none spans a boundary
        │
        ▼
FEATURE EXTRACTION  (Tier 1 only for MVP — see 05_FEATURE_ENGINEERING_SPEC.md)
  packet count, packets/sec, bytes/sec,
  mean/std/min/max IAT,
  function-code validity + per-source frequency distribution,
  payload entropy mean/std  (one signal among several; evaluable vs labels on the self-labelled TXT path — headline IF feature, amended 2026-09-04)
        │
        ▼
TRAIN / VALIDATION / TEST SPLIT
  contiguous, time-ordered, non-overlapping blocks over the filtered stream
  TRAIN   = earliest block, NORMAL-ONLY rows   [normal = `binary result == 0`, thesis-confirmed]
  VALIDATION = middle block — the ONLY place the alert threshold is chosen
  TEST    = final block — touched once, at the end
  guard gap discarded at each boundary (>= largest feature window)
```

### Order of operations (fixed)

```
1. parse ARFF (274,628 rows, verified)
2. apply egress direction filter: keep `command response == 0` (response/egress)
3. cut contiguous time blocks on `time` (absolute cut points, recorded)
4. compute windowed features WITHIN each block
5. select normal-only training subset: `binary result == 0`
```

Filtering **before** splitting is mandatory: filtering after would make block sizes
unreproducible and would allow inter-arrival to be computed across both directions
then silently thinned — the exact defect that got `gas_pipeline_ml_ready.csv`
discarded.

---

## How the Unidirectional Constraint Is Simulated

**Plainly stated: this is a simulation, not real diode data.**

The gas-pipeline dataset is a **bidirectional** testbed capture (it contains both
command and response frames). To approximate what a diode's low-side observer would
see, we **keep only one direction** — the egress direction leaving the protected
side — by filtering on `command response`, and discard the other direction entirely
*before* any feature is computed. The model and evaluation then only ever see the
egress half-stream.

This substitution is imperfect: a real diode observer would also lack any of the
protocol-response context that shaped how this testbed was instrumented, and real
diode links carry different framing/timing characteristics. Every document, demo
script, and slide that uses these results must state: **"unidirectional constraint
simulated by direction-filtering a bidirectional dataset; not real diode data."**

---

## Leakage-Prevention Measures

1. **Contiguous time-block split only. Random row splits are forbidden.** Justified
   by polling-loop self-similarity, windowed features straddling boundaries,
   contiguous attack episodes, and the train-past/test-future deployment story
   (`docs/03-data-split-protocol.md`).
2. **Train on normal-only.** Isolation Forest sees only normal-labelled egress
   windows from the TRAIN block — "normal" = `binary result == 0` (thesis-confirmed,
   BLOCKER 1 resolved).
3. **No time-window overlap between train and test.** Windows are computed within a
   block; a guard gap (≥ largest feature window) is discarded at each boundary so no
   window can reach across.
4. **Threshold chosen on VALIDATION only.** Never on TEST. Any threshold value in
   code or docs must cite the split it was chosen against.
5. **TEST touched once.** No hyperparameter or threshold selection against it.
6. **Labels never used as features.** `binary/categorized/specific result` excluded
   by construction.
7. **Artifact audit on the TRAIN block only**, output recorded, must pass before any
   metric is reported. Attributes that separate classes on their own
   (`crc rate`, field-presence bitmask, tail function codes) stay excluded unless the
   audit explicitly clears them.
8. **Inter-arrival computed after filtering and within blocks**, never in raw record
   order.
9. **Reproducibility:** split cut points recorded as absolute epoch + ISO 8601;
   dataset sha256 recorded (`970a7bcd…af459` for the ARFF); seeds fixed.

---

## What We Do NOT Claim

- We do **not** claim to possess a physical data-diode attack dataset.
- We do **not** claim the text-file payload frames are joined to the labels.
- We do **not** claim any code→attack-class mapping until BLOCKER 1 is resolved with
  a cited source.
- We do **not** claim any detection performance until it is produced by a recorded
  experiment (`EXPERIMENT_LOG.md`).

## Blockers Summary

| Blocker | Blocks | Status (2026-09-02) |
|---|---|---|
| BLOCKER 1 — label codebook | normal-only training subset; every label-dependent audit check; every metric | **RESOLVED (thesis).** `binary result` 0=normal/1=attack; `categorized result` 0..7 = Normal/NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Recon (Table 3.1 p.24, Table 3.5 p.36); `specific result` 0=normal, 1–35 per Tables 3.6–3.8 (pp.37–40). Verified against the local ARFF `categorized × specific` cross-tab — exact match for all 35 IDs. Full tables + citations in `docs/00-dataset-provenance.md`. **Metric gate LIFTED.** |
| BLOCKER 2 — `command response` direction semantics | fixing the egress filter value; final split boundaries | **RESOLVED — CONFIRMED BY PRIMARY SOURCE (thesis, §3.5.2 p.34, verbatim):** *"The sixteenth feature is provided to allow an IDS to learn the difference between commands and responses. The value can either be a '0' for response or '1' for command."* Egress (telemetry leaving the protected OT network) = **response** = `command response == 0`. This is a verbatim thesis definition, not an inference; it also confirms the earlier exception-code inference. |
| BLOCKER 3 — text↔ARFF join key | pairing payload entropy with ground truth | **RESOLVED BY DECISION + 2026-09-04 correction.** No reliable ARFF↔TXT join; fuzzy timestamp join NOT attempted. **But the raw TXT is self-labelled** (`00-dataset-provenance.md` §"CORRECTION (2026-09-04)"), so on the **TXT egress path** payload entropy IS evaluable against ground truth — it is a headline IF feature there (EXP-0002), and TS-5 is counted in headline recall on that path. On the ARFF path (no payload bytes) entropy remains a described-only mechanism. |
| BLOCKER 4 / LICENSE — dataset terms | any *public* submission / repo push | **PARTIALLY RESOLVED — open action item.** No explicit dataset licence exists; authors request citation only; IMPACT "commercial allowed" tag is third-party / non-authoritative. (The *thesis PDF* is distributed Open Access — separate from the dataset.) Mitigation active: raw files kept out of public repos (download script + checksums committed instead); public artifacts must cite Turnipseed 2015 + Morris/Thornton/Turnipseed 2015 and disclose the simulation. Team must personally verify official terms before any public release. Does **not** block the 2026-09-15 internal demo. |
| — dataset-count discrepancy | nothing (documented) | Thesis says 274,627 instances (§3.5 p.27); local ARFF has **274,628** (verified twice, 0 malformed rows). **+1 row locally.** Not normalised — local ARFF is the implementation artifact, thesis is the semantics authority. Immaterial to label semantics. |

Full detail of each resolution: `docs/00-dataset-provenance.md` §"Open provenance
blockers", §"Dataset-count discrepancy", §"Local ARFF label-domain cross-check".

None of these block *writing* pipeline code. **BLOCKER 1's metric gate is now
lifted** (label-based metrics may be computed once the split + artifact audit pass).
BLOCKER 3 no longer removes entropy from headline metrics on the TXT path (amended
2026-09-04 — the TXT is self-labelled). BLOCKER 4 blocks only *public* artifacts.

### Governing constraints for the first real experiment (pre-registered)

Recorded here and in `EXPERIMENT_LOG.md` so the first experiment cannot silently
deviate:

- **Direction filter:** keep `command response == 0` (**confirmed** = response =
  egress, thesis §3.5.2 p.34). Run `command response == 1` as a labelled sensitivity
  check, not as the headline.
- **Entropy inclusion (amended 2026-09-04, `DECISION_LOG.md` / `EXPERIMENT_LOG.md`
  pre-reg §2):** `payload_entropy_mean` / `payload_entropy_std` **ARE** headline
  Isolation Forest inputs on the TXT egress path, and TS-5 is counted in aggregate
  recall there. The earlier exclusion assumed no payload↔label join (BLOCKER 3); the
  raw TXT is self-labelled so that is void. On the ARFF path (no payload bytes)
  entropy stays a described-only mechanism.
- **Deterministic rule layer:** `function_code_valid` and address-novelty checks are
  **not** IF inputs (constant on normal traffic → IF can't split on them); they run as
  a deterministic rule OR-ed with the IF.
- **Normal-only training subset** = rows with `binary result == 0` (equivalently
  `categorized result == 0` / `specific result == 0`) — thesis-confirmed as normal.
- **Label-based metrics are now permitted** (BLOCKER 1 resolved), conditional on the
  split (`03-data-split-protocol.md`) and the instrumentation-artifact audit
  (`09_TEST_VALIDATION_PLAN.md` T-15) passing and being recorded in the same
  `EXPERIMENT_LOG.md` entry.
- **Per-attack-type reporting** uses `categorized result` (7 families) as the primary
  breakdown and may drill into `specific result` where a family's detectability
  varies by specific attack.
