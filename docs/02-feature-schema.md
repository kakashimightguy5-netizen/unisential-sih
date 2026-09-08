<!-- Companion to 05_FEATURE_ENGINEERING_SPEC.md. This file is AUTHORITATIVE for the
     raw ARFF attribute schema, per-attribute availability/missingness, exclusions,
     and the direction-filter plan. 05_FEATURE_ENGINEERING_SPEC.md is authoritative
     for the derived per-window Tier 1/2/3 feature set built on top of it. -->

# Feature Schema

Source of truth: `data/raw/IanArffDataset.arff` (relation `gas`, 274,628 verified
instances). Provenance and blockers: `00-dataset-provenance.md`. Every availability
figure below is measured, not estimated.

This document defines *what the data contains and what may be used as model input*.
It does not define model training, hyperparameters, or feature-engineering code.

## Full 20-attribute schema (ARFF order)

| # | attribute | ARFF type | missing `?` | missing % | availability |
|---|---|---|---|---|---|
| 1 | `address` | real | 0 | 0.0 | fully populated |
| 2 | `function` | real | 0 | 0.0 | fully populated |
| 3 | `length` | real | 0 | 0.0 | fully populated |
| 4 | `setpoint` | real | 210528 | 76.66 | effectively unavailable |
| 5 | `gain` | real | 210528 | 76.66 | effectively unavailable |
| 6 | `reset rate` | real | 210528 | 76.66 | effectively unavailable |
| 7 | `deadband` | real | 210528 | 76.66 | effectively unavailable |
| 8 | `cycle time` | real | 210528 | 76.66 | effectively unavailable |
| 9 | `rate` | real | 210528 | 76.66 | effectively unavailable |
| 10 | `system mode` | real | 210528 | 76.66 | effectively unavailable |
| 11 | `control scheme` | real | 210528 | 76.66 | effectively unavailable |
| 12 | `pump` | real | 210528 | 76.66 | effectively unavailable |
| 13 | `solenoid` | real | 210528 | 76.66 | effectively unavailable |
| 14 | `pressure measurement` | real | 205740 | 74.92 | effectively unavailable |
| 15 | `crc rate` | real | 0 | 0.0 | fully populated (**artifact-suspect**) |
| 16 | `command response` | nominal {0,1} | 0 | 0.0 | fully populated (**0 = response, 1 = command** — thesis §3.5.2 p.34; used as the direction filter, not a feature) |
| 17 | `time` | real | 0 | 0.0 | fully populated |
| 18 | `binary result` | nominal {0,1} | 0 | 0.0 | **LABEL — never an input** |
| 19 | `categorized result` | nominal {0..7} | 0 | 0.0 | **LABEL — never an input** |
| 20 | `specific result` | nominal {0..35} | 0 | 0.0 | **LABEL — never an input** |

### Note on the 11 `?`-dominated attributes

Attributes 4-14 are missing on roughly three quarters of rows. This is not random
missingness: field presence tracks frame type, and therefore tracks
`command response`. That coupling is exactly why these fields are **artifact-suspect
as well as sparse** — a per-row "which fields are present" pattern can act as a
near-proxy for frame type and possibly for label. See the artifact audit in
`03-data-split-protocol.md`.

## Candidate model inputs vs excluded

### Candidate inputs (P1)

| attribute | why | condition |
|---|---|---|
| `function` | Modbus function code, 28 distinct values observed | none |
| `address` | 20 distinct values; value `4` dominates (274,026 of 274,628) | low cardinality in practice — near-constant, may add little |
| `length` | frame size, feeds both protocol-structure and byte-volume views | audit `length` templates first |
| `time` | epoch seconds, microsecond resolution; basis for all windowed rate features | must not leak across split boundary |
| `command response` | frame-type / direction indicator | used **only** as the direction filter (`== 0` = response = egress, thesis-confirmed, BLOCKER 2 resolved); constant post-filter, so never also a feature |

Derived features (windowed packet rate, byte rate, per-function rate, interarrival)
are constructed from `time`, `length` and `function`. Interarrival must be computed
**after** direction filtering and **within** split blocks — the discarded
`gas_pipeline_ml_ready.csv` got this wrong (`00-dataset-provenance.md`).

### Excluded from model input

| attribute | reason |
|---|---|
| `binary result`, `categorized result`, `specific result` | **Labels.** Using any of these as an input is target leakage. Non-negotiable, regardless of how BLOCKER 1 resolves. |
| `setpoint`, `gain`, `reset rate`, `deadband`, `cycle time`, `rate`, `system mode`, `control scheme`, `pump`, `solenoid`, `pressure measurement` | ~75-77% missing; presence pattern is frame-type-coupled and artifact-suspect. Excluded for P1. |
| `crc rate` | Fully populated on every row and flagged by the recon as a suspected label-correlated instrumentation artifact. **Excluded pending audit** (`03-data-split-protocol.md`). Do not include on the grounds that it is "free" — that is the failure mode the audit exists to catch. |

The exclusion list is deliberately aggressive. Adding any excluded attribute back
requires a recorded audit result, not a judgement call.

## Direction-filter plan

The diode simulation requires reducing the capture to a single direction — the egress
side an outbound observer would see.

- Filtering on `command response == 0` yields **137,013** rows.
- Filtering on `command response == 1` yields **137,615** rows.

**BLOCKER 2 — RESOLVED (thesis, primary source).** Turnipseed (2015) §3.5.2 p.34,
verbatim: *"The value can either be a '0' for response or '1' for command."* So
**`command response == 0` = response = the outbound telemetry direction a diode
observer sees = egress.** The earlier data evidence (mean `length` 30.901 vs 50.383;
exception codes 128–142 exclusively under 0) agrees.

Plan:

1. ~~Resolve BLOCKER 2~~ — done; recorded in `00-dataset-provenance.md` (BLOCKER 2).
2. Apply the filter `command response == 0` (egress = response). `== 1` is kept
   available only as a labelled sensitivity run.
3. After filtering, drop any attribute populated only on the excluded (command)
   direction — the command-payload attributes 4–13 (`setpoint` … `solenoid`), which
   are already excluded above, so the P1 input set does not change.
4. `command response` itself becomes constant post-filter and is therefore dropped as
   a feature by construction.

The filter value is fixed at `command response == 0`; a config parameter may still
expose it for the `== 1` sensitivity run.

## P1 capability classification

Mapped to the three P1 threat classes in `01-threat-model.md`.

### 1. Protocol / function-code violations — **SUPPORTED**

Supporting attributes: `function`, `address`, `length`, `command response`
(`crc rate` available but excluded pending audit).

`function` has 28 distinct values. The distribution is heavily concentrated —
`3` (137,696) and `16` (128,200) account for the overwhelming majority, with
`8` (3,123), `136` (2,521), `171` (1,024) and `43` (1,024) next, and a long tail of
codes appearing exactly 40 times each. Out-of-profile function codes and out-of-spec
lengths are therefore expressible. Caveat: the concentration means a detector can
look strong simply by memorising the ~7 dominant codes; the audit in
`03-data-split-protocol.md` exists to surface that.

### 2. Payload entropy / exfiltration — **SUPPORTED ON THE VERIFIED TXT PATH**

The ARFF alone contains no raw payload bytes. The current
`data/raw/gas_pipeline_raw.txt`, however, carries hex frames and is verified row-aligned
to the ARFF across all 274,628 rows (BLOCKER 3 resolved 2026-09-08; see
`00-dataset-provenance.md`). Entropy can therefore be computed and evaluated against
authoritative labels without a fuzzy join. EXP-0004 confirms it adds measured IF
signal; entropy remains one signal among several, never sufficient alone.

### 3. Volume / frequency anomalies — **SUPPORTED**

Supporting attributes: `time` (epoch, microsecond resolution, ~3.2-day span, strictly
increasing, 0 duplicates), `length` (byte volume), `function` (per-operation rates).

Windowed packet-rate and byte-rate features are well defined. The capture is a steady
polling loop, which means windows are regular but adjacent windows are highly
self-similar — the direct reason the split must be by contiguous time block.

## Downstream consistency

- `06-alert-schema.md`: `timestamp` maps to the ARFF `time` attribute (unix epoch
  float, microsecond resolution) — it does **not** need the null/ordinal fallback
  described there, since every row has a distinct timestamp. `source_id` has no
  strong candidate: `address` is near-constant at value `4` (274,026 of 274,628), so
  it is a weak device identifier; expect a synthetic per-record index labelled as
  such. `feature_name` values in `feature_contributions` must come from the candidate
  input list above.
- `01-threat-model.md`: its three `[TBD - confirm against real dataset]` markers are
  answered by the capability classification above and should be updated to reference
  this file.
- `04-model-and-threshold.md`: the Isolation Forest input set is the candidate list
  above, minus anything the audit rejects. All hyperparameters remain
  `[TBD - pending experiment]`.
