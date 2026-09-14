# EXP-0030b — Corrected FPR-bar re-score of EXP-0030 (float-provenance rule) — PARTIAL-GO (CMRI), NO-GO (NMRI, different reason)

**This is a pre-registered AMENDMENT, not a new experiment.** It re-evaluates EXP-0030's already-obtained TEST predictions (`data/experiments/exp0030_float_provenance_detector.json`) against a corrected decision bar. Nothing was retrained, nothing on TEST was re-touched or re-derived. EXP-0030's original artifact, its NO-GO verdict, and its results doc are retained unchanged — this is a superseding re-score for one specific, disclosed reason (see Retraction note below).

Pressure is egress traffic extracted from Mississippi State ICS testbed dataset, used as a simulated diode-observer view — never real diode capture data.

## Why EXP-0030's original bar was wrong

EXP-0030 required the FULL combined-detector Normal FPR to stay ≤ 0.30% after adding the float-provenance rule. That bar is the per-classifier VAL-threshold-fitting convention EXP-0032/0032b used for a diagnostic probe (fit a threshold on VAL Normal scores to keep that classifier's own FPR ≤0.30%) — it was never validated as an appropriate ABSOLUTE ceiling on the full production combined detector. The production baseline (protocol OR pressure OR rate OR IF, EXP-0025) already runs at **0.832% FPR (TN 4767 / FP 40, TEST)**, already 2.8x over that bar before EXP-0030's rule was ever added. No detector could ever pass an absolute 0.30% ceiling layered on top of an already-0.832% baseline. EXP-0030's own results doc disclosed this gap honestly at the time ("Honesty notes" section) but, per this project's "no amendments after seeing TEST results" discipline, did not correct it in-session. This document is that correction, done as a separate, explicitly pre-registered step.

## Corrected decision rule (fixed before running this amendment)

- No fixed absolute ceiling on total combined FPR. Total resulting FPR is reported plainly and flagged for the human (Navin) to decide on demo-readiness/precision trade-offs — this experiment does not auto-accept or auto-reject on that basis.
- The gate that DOES apply: the float rule's **isolated marginal trade ratio** (marginal TP gained ÷ marginal FP added, both isolated from the other rules' overlap the same way EXP-0017 isolated a rule's own marginal contribution) must be **≥ 3:1**, per category, independently for NMRI and CMRI.
- GO (per category) requires: isolated ratio ≥ 3:1 AND the existing leave-one-run-out generalization result still holds.
- NO-GO (per category): isolated ratio < 3:1 once properly isolated — a genuinely different reason than EXP-0030's original NO-GO (which was a spec bug, not a trade-quality finding).

## Isolation methodology (replicating EXP-0017's own attribution, not the naive delta)

EXP-0017's own accepted historical attribution isolates a rule's marginal contribution by comparing confusion **before** and **after** OR-ing that rule onto the *rest of the already-wired chain*, in wiring order — i.e. NOT "rule alone from scratch," but "rule added on top of everything already wired ahead of it." Reproducing that exact methodology on EXP-0017's own frozen TEST arrays (`ml/exp0017_operational.load_result()`), for the IF term specifically (the last term in `protocol OR pressure OR IF`):

| step | tn | fp | fn | tp |
|---|---:|---:|---:|---:|
| protocol OR pressure (IF excluded) | 4803 | 4 | 2192 | 2348 |
| protocol OR pressure OR IF (comb, historical EXP-0017) | 4767 | 40 | 2166 | 2374 |
| **IF's isolated marginal** | — | **+36** | — | **+26** |

**EXP-0017's own IF isolated marginal ratio: 26 TP / 36 FP = 0.72:1** — worse than break-even, let alone 3:1 — and this was the term EXP-0017 accepted into the currently-wired production baseline. This is disclosed explicitly per the pre-registration's instruction to report it plainly, not assume 3:1 was already historically met.

For a monotonic OR-combination, this "added on top of the rest of the chain" isolation is mathematically identical to "restricted to windows the rest of the chain does not already catch" (baseline_pred=0): for any two boolean predictions A (rest of chain) and B (new rule), TP(A|B) − TP(A) = count(y=1 & B=1 & A=0), exactly the same for FP. There is no double-counting or overlap-inflation possible in a simple two-term OR union — the "naive delta" EXP-0030 already reported (+243 TP / +27 FP) is therefore **already exactly the correctly isolated combined marginal**, not a distinct, incorrect quantity. This is disclosed explicitly since the task brief flagged a risk of naive-delta overlap-inflation that does not, in fact, apply to a plain two-way OR.

**Combined isolated marginal (float rule on top of protocol OR pressure OR rate OR IF):**

| step | tn | fp | fn | tp |
|---|---:|---:|---:|---:|
| baseline (protocol\|pressure\|rate\|IF, EXP-0025 wired) | 4767 | 40 | 2166 | 2374 |
| baseline OR float-provenance rule | 4740 | 67 | 1923 | 2617 |
| **float rule's isolated marginal (combined)** | — | **+27** | — | **+243** |

**Combined isolated ratio: 243 / 27 = 9.00:1** — clearly beats both the 3:1 bar and EXP-0017's own historically-accepted 0.72:1 IF ratio.

### Per-category isolated attribution

The float rule is two separate per-attack XGBoost classifiers OR-ed together (`float_pred = nmri_model_fires OR cmri_model_fires`), so the +243 TP splits by pure cohort exactly (recall-gain × cohort n, both exact integers in the saved artifact):

| category | pure-cohort n (TEST) | isolated marginal TP (pure cohort) |
|---|---:|---:|
| NMRI | 715 | 32 |
| CMRI | 1198 | 144 |
| (mixed / non-pure windows containing NMRI or CMRI alongside other attack types) | — | 67 |
| **total** | — | **243** (matches combined) |

**FP cannot be split by category from the saved artifact.** False positives occur only on Normal-labelled TEST windows, which have no NMRI/CMRI category label to attribute causation to, and the individual per-classifier fire arrays (`float_fires_by_attack["NMRI"]` vs `["CMRI"]`) were never serialized to `exp0030_float_provenance_detector.json` — only the OR'd aggregate. Recovering that split would require re-scoring the fitted classifiers on TEST Normal windows, which this amendment's scope explicitly excludes ("do not re-run the model"). This is disclosed as a genuine, unresolved limitation, not silently assumed away.

**Conservative (worst-case) per-category ratio** — charging the FULL +27 FP against each category independently. This is a valid worst-case bound: the true category-specific FP is somewhere ≤ 27 (bounded above by the total, since a normal window flagged by only one classifier contributes its FP to only that classifier), so a category that clears 3:1 even under this pessimistic charge is guaranteed to clear it under the true, unknown split too. A category that fails under this pessimistic charge may or may not fail under the true split — that ambiguity is reported, not resolved in the category's favor.

| category | isolated marginal TP | FP charged (worst-case, full total) | isolated ratio | ≥ 3:1? |
|---|---:|---:|---:|---|
| NMRI | 32 | 27 | **1.19:1** | **No** |
| CMRI | 144 | 27 | **5.33:1** | **Yes** |

## Leave-one-run-out re-confirmation (no double-counting issue found)

The leave-one-attack-run-out result (EXP-0030/0032b) evaluates recall generalization of the FITTED model on held-out attack episodes — it is independent of the FPR-attribution question above (it never touches Normal windows or FP at all), so there is no double-counting interaction between the two checks. Re-confirmed from the saved artifact, unchanged:

| attack | runs evaluated | mean recall | std | run-dependent? |
|---|---:|---:|---:|---|
| NMRI | 66 | 94.06% | 9.59% | **False** |
| CMRI | 107 | 95.29% | 8.13% | **False** |

## Verdicts (corrected, per category)

| category | isolated ratio (worst-case) | ≥ 3:1? | LORO generalizes? | verdict | reason |
|---|---:|---|---|---|---|
| **CMRI** | 5.33:1 | Yes | Yes (False = not run-dependent) | **GO** | corrected FPR bar spec error, see EXP-0030b — supersedes EXP-0030's original NO-GO for CMRI |
| **NMRI** | 1.19:1 | No | Yes (False = not run-dependent) | **NO-GO** | isolated trade-quality shortfall (conservative attribution) — a DIFFERENT, now-correct reason than EXP-0030's original spec-bug NO-GO |

**Overall: PARTIAL-GO (CMRI only).**

NMRI's true isolated ratio cannot be pinned down more precisely than "somewhere between 1.19:1 (worst case) and unbounded (best case, if none of the +27 FP is attributable to the NMRI classifier)" without re-scoring the fitted classifiers on TEST — out of scope for this amendment. Per the pre-registered discipline of not resolving ambiguity in a category's favor, NMRI is scored NO-GO on the conservative bound.

## Total resulting FPR — flagged for Navin's decision, NOT auto-decided here

- Current wired baseline (protocol OR pressure OR rate OR IF): **FPR 0.832%** (TN 4767 / FP 40)
- With float-provenance rule added (both NMRI+CMRI models, as originally scored in EXP-0030 — the CMRI-only wiring below has NOT been separately re-scored on TEST, per "TEST is scored once"): **FPR 1.394%** (TN 4740 / FP 67)
- This experiment does not accept or reject based on this number. **This is a demo-readiness/precision trade-off decision for the human to make**: is +1.63pp NMRI/CMRI combined recall (52.29% → 57.64% overall; NMRI pure 79.02%→83.50%, CMRI pure 54.59%→66.61%) worth going from 0.832% to 1.394% Normal FPR for the demo.

## Wiring — NOT performed in this pass; architectural/scope constraint surfaced explicitly

EXP-0030's float-provenance rule is **not a simple boolean threshold rule** like EXP-0025's `RateFloodRule` (a fitted `(mean, std)` threshold class evaluated inline in `ml/rules.py`/`ml/iforest_detector.py` against an already-computed feature). It is a **fitted XGBoost classifier per attack type**, scored against 7 IEEE-754 bit-structure features (`F2_NAMES`) that are not currently computed anywhere in the production feature pipeline (`ml/features_windowed.py`, `ml/rules.py`, `ml/iforest_detector.py`) — they only exist in the EXP-0032/0032b/0030 research modules. The fitted classifier object itself was also never serialized to disk (only aggregate confusion-matrix statistics were saved to `exp0030_float_provenance_detector.json`); reconstructing it exactly requires re-running `exp0030_float_provenance_detector.run_experiment()`'s deterministic fit step, which is confirmed bit-identical (`refit_reproduces_reported_val_recall: True`) but is still, categorically, "re-running the model" — which this amendment's own scope explicitly excludes ("do NOT retrain, do NOT re-run the model").

Because CMRI's GO verdict is the only one earned here, and because doing the wiring properly would require (a) serializing the fitted CMRI XGBClassifier as a production artifact, and (b) adding a live F2 feature-extraction path to the production feature pipeline that does not exist today, **this is surfaced as a real architectural gap, not silently worked around**: wiring EXP-0030b's CMRI-only float-provenance rule into `ml/rules.py` / `ml/iforest_detector.py` is recommended as a distinct, explicitly pre-registered follow-up (e.g. "EXP-0030c — CMRI float-provenance rule production wiring") rather than forced into this re-scoring amendment.

**`ml/rules.py` and `ml/iforest_detector.py` are UNCHANGED in this amendment.**

## Test suite

Full existing suite: **399/400 passing, unchanged**, before and after this amendment (only documentation and this analysis were touched; no production or research module was edited). The one pre-existing failure (`test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation`) is the same known-unrelated `pyarrow` DLL/Windows Application Control policy issue, confirmed by direct re-run:

```
FAILED tests/test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation
1 failed, 399 passed in 30.57s
```

## Deliverables

- `docs/experiments/EXP-0030b_RESULTS.md` — this file.
- `docs/EXPERIMENT_LOG.md` — a RETRACTION entry for EXP-0030's original bar (append-only; original EXP-0030 entry untouched) plus the new EXP-0030b entry.
- No source files modified. `ml/rules.py`, `ml/iforest_detector.py`, `ml/exp0030_float_provenance_detector.py`, and `data/experiments/exp0030_float_provenance_detector.json` are all unchanged — this amendment only reads and re-analyzes the existing saved artifact.

## Limitations (disclosed)

- Per-category FP attribution is a worst-case bound, not an exact split (per-classifier fire arrays were never serialized; recovering them requires re-scoring, out of this amendment's scope).
- The "mixed/non-pure" 67 TP (windows with NMRI or CMRI alongside another attack category) are not assigned to either category's isolated-ratio table; this is conservative (undercounts both categories' true credit) rather than inflationary.
- Wiring was not performed; CMRI's GO is a paper/attribution verdict pending a separate production-wiring pre-registration (F2 feature pipeline + model serialization do not exist in production code today).
- One testbed; egress-only; measurement only; pressure is the ARFF-aligned value, not a live 0x03 byte decode (unchanged limitation, inherited from EXP-0017/0030).
