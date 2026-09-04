<!-- AUTHORITATIVE for the train/validation/test split mechanics and the
     instrumentation-artifact audit. Referenced by 04_DATASET_PLAN.md (leakage
     controls) and 09_TEST_VALIDATION_PLAN.md (T-12..T-16). -->

# Data Split Protocol

Applies to `data/raw/IanArffDataset.arff` (274,628 verified instances). Facts from
`00-dataset-provenance.md`; attribute usability from `02-feature-schema.md`.

## Ruling: contiguous time-block split. Random row splits are forbidden.

### Why the data permits it

The `time` attribute is strictly increasing in file order across all 274,628 rows,
with 274,628 distinct timestamps and 0 duplicates, spanning
2014-12-15T22:22:43Z to 2014-12-19T02:57:34Z (~3.2 days). File order is therefore a
genuine temporal order, and any prefix/suffix of the file is a genuine time block.

### Why random splitting would be invalid

1. **Polling-loop self-similarity.** The capture is a steady SCADA polling loop.
   Adjacent records are near-identical frames. A random split puts row *i* in train
   and row *i+1* in test, so the model is scored on effectively the same frames it
   trained on. Any resulting number measures memorisation, not detection.
2. **Windowed features straddle the boundary.** Volume/frequency features
   (`02-feature-schema.md`) are computed over time windows of `time` and `length`.
   Under a random split, a test row's window includes training rows. That is direct
   leakage through the feature itself.
3. **Attack episodes are contiguous.** Attacks in a testbed capture occur as runs of
   consecutive records, not scattered singletons. Randomly splitting a single attack
   episode leaks its signature from train to test.
4. **It contradicts the deployment story.** A diode observer sees traffic forward in
   time and must generalise to *later* traffic. Train-on-past / test-on-future is the
   only split that matches the threat model in `01-threat-model.md`.

## Protocol

Three contiguous, non-overlapping, time-ordered blocks over the direction-filtered
stream:

```
|<---- TRAIN ---->|<-- VALIDATION -->|<---- TEST ---->|
   earliest                                    latest
```

- **TRAIN** — earliest block. Per `04-model-and-threshold.md`, Isolation Forest is
  trained on **normal-only** rows within this block. "Normal" = `binary result == 0`
  (equivalently `categorized result == 0`) — thesis-confirmed, BLOCKER 1 resolved
  (`00-dataset-provenance.md`).
- **VALIDATION** — middle block. The **only** place the alert threshold may be
  selected (`04-model-and-threshold.md`).
- **TEST** — final block. Touched once, at the end. Never used for threshold or
  hyperparameter selection.

Block boundaries are defined as **absolute `time` cut points**, recorded explicitly
(epoch value and ISO 8601) in whatever artifact the split produces, so the split is
reproducible from the raw file alone. Exact boundary values and block proportions are
`[TBD - pending experiment]` — BLOCKER 1 and BLOCKER 2 are now resolved, so the
boundaries can be chosen against known label + direction semantics; they must give
each block a workable mix of frame types and labels.

### Rules

- No row may appear in more than one block.
- Windowed / interarrival features are computed **within** a block only. No window
  may span a boundary. Records in the first window of a block have incomplete history
  and must be either dropped or explicitly flagged — never silently zero-filled.
- A **guard gap** (a short discarded interval at each boundary) should be inserted so
  that no feature window can reach across. Gap size is `[TBD - pending experiment;
  determined by the largest feature window used]`.
- The split is defined **after** direction filtering, on the filtered stream, so block
  sizes are stated in filtered-row counts, not raw ARFF row counts.

## Interaction with the direction filter

Order of operations is fixed:

```
1. parse ARFF (274,628 rows, verified)
2. apply direction filter: keep `command response == 0` (response = egress; thesis-confirmed)
3. cut contiguous time blocks on `time`
4. compute windowed features within each block
5. select normal-only training subset: `binary result == 0` (thesis-confirmed)
```

Filtering **before** splitting matters. Filtering after would leave block boundaries
defined over rows that are then removed, giving unequal and unreproducible effective
block sizes. It would also allow an interarrival feature to be computed over both
directions and then silently thinned — the same defect that got
`gas_pipeline_ml_ready.csv` discarded (`00-dataset-provenance.md`).

Post-filter block sizes will be roughly half the raw counts: the egress filter
(`command response == 0`, response = telemetry leaving the protected side —
thesis-confirmed, BLOCKER 2 resolved) keeps 137,013 rows. The `== 1` direction
(137,615 rows) is used only for the labelled sensitivity run.

## Artifact / leakage audit checklist

Morris et al. have documented that MSU testbed captures contain unintended
instrumentation artifacts that can make attacks trivially separable. Treat a
suspiciously clean separation as a bug until proven otherwise.

Run this audit on the **training block only** — never on test — and record the raw
output. No metric may be reported before it passes (`05-evaluation-plan.md`).

1. **`crc rate`** — populated on 100% of rows and flagged as artifact-suspect.
   Check: is `crc rate` value distribution conditional on the label? If it separates
   classes on its own, it is an instrumentation artifact, not a detection signal.
   Currently excluded from inputs (`02-feature-schema.md`); this audit is the only
   route to reinstatement.
2. **`length` templates** — enumerate distinct `length` values and their frequencies.
   Check whether a small set of exact lengths maps near-deterministically to a class.
   Mean `length` already differs sharply by `command response` (30.901 vs 50.383);
   confirm that this is frame-type structure and not label structure.
3. **`function` code cardinality** — 28 distinct values, but ~7 dominate (`3`:137,696;
   `16`:128,200; `8`:3,123; `136`:2,521; `171`:1,024; `43`:1,024), with a long tail of
   codes occurring exactly 40 times each. A tail code that appears only under one
   class is a memorisation shortcut. Report the per-class breakdown of the tail
   explicitly.
4. **Field-presence pattern** — attributes 4-14 are `?` on ~75-77% of rows in fixed
   patterns. Build the per-row presence bitmask, count distinct masks, and cross-tab
   against the label. If the mask alone separates classes, the sparse fields must
   stay excluded and any feature derived from them is invalid.
5. **The exactly-40 pattern** — a large number of `function` codes appear exactly 40
   times. That regularity looks scripted rather than organic. Check whether these
   40-count groups are contiguous in time; if so, they are injected episodes and must
   be distributed across blocks deliberately, not accidentally.
6. **Boundary sanity** — after cutting, confirm 0 overlapping rows between blocks,
   0 windows spanning a boundary, and that each block's `time` range is disjoint.

Each check has three outcomes: **PASS** (no label correlation), **FAIL** (attribute
excluded permanently, recorded here), or **NEEDS DOCUMENTATION** (cannot be assessed
yet). Checks 1–5 depend on the label; the label codebook is now available
(BLOCKER 1 resolved), so they are runnable once the split exists.

## Blockers

- **BLOCKER 1 (label codebook)** — **RESOLVED** (thesis, `00-dataset-provenance.md`).
  Normal-only training subset = `binary result == 0`; label-dependent audit checks
  can now be run.
- **BLOCKER 2 (direction semantics)** — **RESOLVED, confirmed by primary source**
  (thesis §3.5.2 p.34). Egress filter fixed at `command response == 0`.

Reporting anything derived from a split still requires the split + artifact audit to
be run and recorded in `EXPERIMENT_LOG.md`.
