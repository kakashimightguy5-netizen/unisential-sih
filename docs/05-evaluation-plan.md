> **EXTENDED (2026-09-02) by `06_AI_MODEL_EVALUATION_PLAN.md`.** That document is the
> authoritative evaluation plan (baseline vs Isolation Forest, metric list,
> thresholding, explainability, per-attack-type honesty). This file remains valid and
> is fully consistent with it: the standing "no fabricated numbers" rule, the
> BLOCKER-1 metric gate, the artifact-audit gate, and the "what can be evaluated now"
> list all still hold. One update: throughput/latency are now tracked NFRs
> (`02_REQUIREMENTS_SPEC.md`) though still not demo-success criteria
> (`10_DEMO_SUCCESS_CRITERIA.md`). BLOCKER 4 here == "LICENSE" blocker in the
> numbered docs.

# Evaluation Plan

Governs what may be measured and reported, and when. Depends on
`00-dataset-provenance.md`, `02-feature-schema.md`, `03-data-split-protocol.md`,
`04-model-and-threshold.md`.

## Standing rule

**No accuracy, precision, recall, F1, ROC-AUC, false-positive rate, latency or
throughput number appears anywhere in this repository until the experiment producing
it has actually been run and its output recorded.** Placeholders are written as
`[TBD - pending experiment]`. A plausible-looking number is worse than no number,
because it survives into slides.

As of 2026-09-01: no model has been trained, no threshold selected, no metric
computed. Every performance field in this repo is `[TBD - pending experiment]`.

## Metric reporting gate — BLOCKER 1 LIFTED (2026-09-02)

The primary gate was **BLOCKER 1 (label codebook)**. It is **RESOLVED**: the
Turnipseed (2015) thesis label tables (§3.4–3.5, Tables 3.5–3.8) are transcribed
into `00-dataset-provenance.md` with citations and cross-checked exactly against the
local ARFF `categorized × specific` cross-tab. `binary result` 0=normal/1=attack;
`categorized result` 0..7 = Normal/NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Recon;
`specific result` 0=normal, 1–35 named attacks. **Label-based metrics are now
permitted.**

Remaining gate: the artifact audit in `03-data-split-protocol.md`. A metric computed
on features that failed the audit measures instrumentation leakage, not detection.
Audit results must be recorded in the same `EXPERIMENT_LOG.md` entry as any metric
reported alongside them.

## What CAN be evaluated now (blocker-free)

These require no labels and no trained model. They are the honest deliverable for the
current phase.

### 1. Capability coverage
Restate, per P1 threat class, whether the authoritative dataset's fields support it.
Already determined in `02-feature-schema.md`:

| P1 threat class | status | basis |
|---|---|---|
| protocol / function-code violations | SUPPORTED | `function`, `address`, `length`, `command response` all 0% missing |
| payload entropy / exfiltration | PARTIALLY SUPPORTED | no payload bytes in ARFF; frames only in unlabeled TXT with no join key (BLOCKER 3) |
| volume / frequency anomalies | SUPPORTED | `time` strictly increasing, 0 duplicates, ~3.2-day span; `length`, `function` populated |

This is a coverage statement, not a performance claim. It says what the data *can
express*, never how well anything detects.

### 2. Artifact / leakage audit
The six checks in `03-data-split-protocol.md`. Checks 1-5 are label-dependent; the
label codebook is now available (BLOCKER 1 resolved), so all six are runnable once
the split exists. Check 6 (boundary sanity) needs no labels.

### 3. Data-integrity reproduction
Re-run `scripts/inspect_dataset.py` and confirm it reproduces: sha256
`970a7bcd...4af459` for the ARFF, 274,628 instances, 0 malformed rows, 0 duplicate
timestamps, 0 duplicate rows, and the stated missing-value percentages. This is a
determinism check on the pipeline's foundation and is fully reportable today.

### 4. Blocker-resolution status
Track each blocker as OPEN / RESOLVED with the citation that resolved it. This is a
first-class evaluation output for this phase, not project-management overhead — the
blockers are what stands between the project and any real number.

| id | blocker | status |
|---|---|---|
| BLOCKER 1 | label codebook semantics | **RESOLVED** — Turnipseed (2015) thesis, transcribed + cited in `00-dataset-provenance.md`, cross-checked vs local ARFF |
| BLOCKER 2 | `command response` direction semantics | **RESOLVED — confirmed by primary source** (thesis §3.5.2 p.34: 0=response=egress) |
| BLOCKER 3 | TXT-to-ARFF join key / payload linkage | RESOLVED BY DECISION + 2026-09-04 correction — no ARFF join, but the raw TXT is self-labelled so entropy IS evaluable and IS a headline detector feature on the TXT path (EXP-0002) |
| BLOCKER 4 | dataset license and citation | PARTIALLY RESOLVED — mitigation active; verify before public release |

## What is explicitly NOT evaluated now

- Detection performance of any kind — gated above.
- Threshold quality — no threshold has been selected. Selection happens on the
  validation block only (`04-model-and-threshold.md`), never on test.
- Hyperparameter sweep outcomes — all `[TBD - pending experiment]`.
- Runtime performance — no timing has been measured, and P1 is a batch CLI run
  (`07-scope-and-cuts.md`), so throughput is not a P1 success criterion.
- Anything about physical diode hardware. This is a dataset-based unidirectional
  simulation (`00-dataset-provenance.md`); no claim about real diode deployments is
  supported by any result this project can produce.

## Planned evaluation once gates lift

Recorded so the design is settled in advance and cannot be retrofitted to flatter a
result. BLOCKER 1 is lifted; execution is now gated only on the split + artifact
audit being run and recorded.

1. **Protocol violation and volume/frequency classes**: score the TEST block once,
   using the threshold selected on VALIDATION. Report the confusion matrix in raw
   counts alongside any derived rate — raw counts are not optional, since the class
   balance is skewed (214,580 vs 60,048 at raw `binary result` level, pre-filter).
2. **Report the audit alongside the metric**, in the same table. A metric published
   without its audit result is not a valid claim.
3. **Payload entropy**: on the **TXT egress path** entropy is fully evaluable — the
   TXT is self-labelled (`00-dataset-provenance.md` §CORRECTION), so entropy is a
   headline Isolation Forest feature and TS-5 counts in headline recall (EXP-0002).
   On the **ARFF path** (no payload bytes) it stays PARTIALLY SUPPORTED,
   demonstrated-only. Never substitute a proxy label.
4. **Single-touch discipline on TEST.** If the test block is scored more than once,
   every scoring after the first must be disclosed, since repeated looks turn the
   test block into a validation block.

## Consistency notes

- `04-model-and-threshold.md` leaves threshold-selection method
  `[TBD - pending experiment; depends on whether validation-set labels are
  available]`. This document resolves the dependency direction: validation labels
  are now fully documented (BLOCKER 1 resolved — `binary result` 0=normal/1=attack),
  so a precision/recall trade-off point on validation is available; the exact method
  stays `[TBD - pending experiment]`.
- `06-alert-schema.md` `anomaly_score` and `is_alert` remain unpopulated by any real
  run. Its example values (`0.0`, `false`) are schema placeholders, not results, and
  must not be quoted as output.
- `01-threat-model.md` should be updated to drop its three
  `[TBD - confirm against real dataset]` markers in favour of the capability table
  above and `02-feature-schema.md`.
