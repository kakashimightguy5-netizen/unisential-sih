# ACK-002 — Burst-level feasibility check for an ack-anchored consequence detector

**Status: TESTED.** Feasibility/coverage check only — no classifier, detector, rule
or threshold was built or scored. `run_detector`, `iforest_detector.py`, `rules.py`,
Layer A, `app.py`, DoS files and CMRI's closed files are unchanged.

## Bottom line

**The literal, pre-registered stopping rule does NOT trigger — the numbers look
like real coverage — but the coverage found is not usable for the original
per-attack consequence-attribution goal, because the label-blind gap threshold
merges almost the entire capture into ~167 enormous, heterogeneous "bursts"
(median 218–364 acks each, spanning tens of minutes), not attacker-scale bursts of
malicious writes.** What is actually being measured is pressure-sample density
during the *rare* long pauses between these mega-bursts (166 such pauses in
51,229 acks) — a property of the capture's recording/episode structure, not of any
individual attack. This is the same conclusion direction as ACK-001 (the
ack-anchored line does not support per-attack attribution) but via a different
mechanism: not censoring density, but attribution ambiguity from burst
heterogeneity.

## Identity gate

EXP-0017 reproduced from its checksummed artifact (`comb == protocol | pressure |
IF`, whole-TEST confusion `(4767, 40, 2166, 2374)`). TEST was not read or scored by
this experiment.

## Population (TRAIN+VALIDATION only, corrected manifest)

- 51,229 observable egress `0x10` write-acks, 53,261 observable egress `0x03`
  pressure responses (identical scan to ACK-001).

## Step 1 — label-blind gap threshold

Computed over **all** 51,228 inter-ack gaps (Normal + attack, unlabeled):

| stat | value (s) |
|---|---|
| median | 3.382 |
| mean | 4.269 |
| p90 | 3.673 |
| p95 | 3.708 |
| p99 | 3.775 |
| max | 640.12 |

Pre-committed method: threshold = 3× median = **10.147s**, fixed before any label
was examined. The gap distribution is extremely tight up to p99 (3.4–3.8s,
consistent with ACK-001's ~3.4s cadence finding) with a long thin tail out to
640s — there is no ambiguous "knee" to argue about; the 3× rule sits just above
the p99 cluster and below the tail, which is exactly what a label-blind multiple
rule is supposed to do.

## Step 2/3 — burst construction and post-burst windows

167 bursts total in scope. Because the threshold (10.15s) is barely above the tight
~3.4s cadence, splits only occur at the rare tail gaps (166 splits over 51,228
gaps, ≈0.32%) — bursts are **not** attacker-scale clusters of writes; they are the
capture split at its rare long pauses.

| | value |
|---|---|
| median acks/burst | 218 |
| mean acks/burst | 306.8 |
| max acks/burst | 1264 |
| % single-ack bursts | 0.00% |
| median burst duration | 770.2s |
| mean burst duration | 1055.4s |
| max burst duration | 4570.9s |

## Step 5 — coverage by group (labels applied only now)

| group | N bursts | %≥1 sample | %≥2 samples | %≥3 samples | median count | median window (s) |
|---|---|---|---|---|---|---|
| MSCI-containing | 81 | 100.00% | 98.77% | 92.59% | 13.0 | 237.7 |
| MPCI-containing | 121 | 99.17% | 95.04% | 90.08% | 12.0 | 231.8 |
| Normal-only | 35 | 100.00% | 97.14% | 91.43% | 12.0 | 214.6 |

## Step 6 — pre-registered stopping-rule verdict

| category | % bursts with <2 clean samples | verdict |
|---|---|---|
| MSCI-containing | 1.23% | **not flagged** (far below the 50% majority threshold) |
| MPCI-containing | 4.96% | **not flagged** (far below the 50% majority threshold) |

Read literally, this is a GO signal — the opposite of ACK-001's result.

## Why this is not the surprising positive result it looks like

ACK-001's warning applies again, in reverse: **a number that passes a literal rule
must still be checked against what the rule was meant to measure.** Composition
evidence (computed after the coverage numbers, as supporting context, not as part
of the pre-registered rule):

| group | median acks/burst | % spanning >1 category | % also containing Normal |
|---|---|---|---|
| MSCI-containing | 364 | 100.00% | 100.00% |
| MPCI-containing | (see JSON; comparable order) | 100.00% | 100.00% |
| Normal-only | 56 | 0.00% (by construction) | 100.00% |

**Every single MSCI- or MPCI-containing burst also contains Normal traffic and at
least one other category, with a median of hundreds of acks inside it.** A
post-burst pressure sample following a 364-ack, multi-category, ~13-minute burst
cannot be attributed to "the MSCI write" or "the MPCI write" within it — there is
no single write to attribute it to. The 95–99% coverage numbers are real, but they
describe pressure-sample density during the capture's rare long pauses (likely
episode/recording-segment boundaries), not a clean post-attack observation window
for any specific write or attack episode. This is the same territory EXP-0021/0022
already explored at the episode/window grain (with a negative MPCI result there);
ACK-002 does not add a new usable observation unit, it just confirms the pauses
between mega-segments have data in them, which was never in doubt.

## Honest interpretation (step 7)

This is **not** the ~5% surprising-positive case described in the pre-registration.
The literal numbers pass the stopping rule, but the underlying design question
("does a clean window exist to attribute a burst's own consequence") is not
answered affirmatively — the "bursts" this threshold produces are not
attack-scale objects, they are the whole capture minus its rare pauses. Reporting
this as a straightforward GO would be dishonest given how the coverage arises.
**No further build effort is warranted on the ack-anchored MSCI/MPCI line via this
burst construction.** Combined with ACK-001 (per-write attribution: 0.00%
censoring-aware scorable) and EXP-0021/0022/0023 (episode- and payload-level
checks, both negative), the ack-anchored / write-response line is now treated as
fully investigated for MSCI/MPCI, per the task's own closing condition.

## Tests

`tests/test_ack002_burst_anchored_coverage.py`: 25 fast synthetic units (gap
distribution/threshold derivation including the "no label used" contract via
direct multiple-of-median arithmetic, burst merging at exactly-threshold and
just-over-threshold gaps, single-ack bursts, multi-cluster merging, post-burst
window counting with strict boundary exclusivity, burst-window scope-end handling,
group summarisation and percentages, composition-summary heterogeneity metrics,
the stopping rule including its zero-data branch, and static-analysis checks that
`source` and the protected files/DoS/CMRI-closed files are never touched) + 1
`@pytest.mark.slow` saved-result replay (no raw-data read; skips if the JSON is
absent). Full suite: **237 → 263 passed** (26 new: 25 fast + 1 slow; 0 skipped, 0
failed with the JSON present).

## Files

New only: `ml/ack002_burst_anchored_coverage.py`,
`tests/test_ack002_burst_anchored_coverage.py`,
`data/experiments/ack002_coverage.json`, this file. `run_detector`, `app.py`, DoS
files, Layer A, the closed EXP-0018/0019/0020 CMRI files, and all prior EXP/ACK
files are unchanged.

## Limitations / honest disclosure

- The 3×-median gap threshold is a pre-committed, principled but ultimately
  arbitrary choice; a different label-blind multiple (e.g. 2× or 5×) would produce
  different burst boundaries. Given the gap distribution's shape (extremely tight
  up to p99, then a thin tail to 640s), any multiple between roughly 1.1× and 100×
  median would still split only at the tail and produce qualitatively the same
  "mega-burst" outcome — this conclusion is not sensitive to the exact multiple
  chosen, but that sensitivity was not swept here (would itself be a form of
  post hoc tuning against a rule already applied once).
- Composition statistics (multi-category %, contains-Normal %) were computed
  after seeing the coverage numbers, as supporting evidence for interpreting an
  unexpected result — consistent with the pre-registration's step 7 (an
  unexpected outcome, positive or negative, gets honest follow-up context), not
  as a second attempt to re-derive the label-blind threshold itself, which was
  fixed in step 1 before any label was examined.
- This check does not evaluate whether a coarser, deliberately episode-scale
  observation unit could work — that is the design EXP-0021/0022 already tried
  (negative for MPCI) and is out of scope for this task per its own instructions.
