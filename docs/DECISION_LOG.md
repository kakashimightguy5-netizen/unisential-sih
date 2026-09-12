# Decision Log

Format: **DATE · DECISION · OPTIONS CONSIDERED · WHY CHOSEN · IMPACT**

---

### 2026-09-10 · DECISION — EXP-0016 builds a decoded-pressure out-of-bounds rule for NMRI (first built fix; touches the rule layer)

- **DECISION:** build one additive rule — flag an egress window whose decoded `0x03`
  response pressure falls outside the TRAIN-normal observed range `[0.4828, 38.7471]` —
  as `PressureBoundsRule` in `ml/rules.py`, alongside the untouched `DeterministicRuleLayer`,
  OR-ed into the operational verdict. Target a rule-layer-style fix (deterministic, frozen
  bound), not an ML model. Fixed decision rule: **strong** = rule-alone pure-NMRI TEST
  recall ≥ 50 % with new pure-Normal FP ≤ 0.30 %; **acceptable** = recall ≥ 30 % with
  FP ≤ 0.30 %.
- **OPTIONS CONSIDERED:** (a) add pressure-value features to the Isolation Forest and let
  it learn the bound — rejected: the IF already fails to use the two entropy features it
  has (EXP-0014/0015), and NMRI out-of-bounds values are an unambiguous, non-statistical
  signal that a hard rule handles exactly like the existing func-code / novel-address
  checks handle MFCI/Recon; (b) a supervised classifier on decoded-value features —
  rejected as premature for a signal this clean; (c) one deterministic bound rule in the
  existing rule layer — chosen.
- **WHY NOW, WHY NMRI FIRST:** EXP-0015 identified NMRI as the cheapest, highest-yield row
  in the per-category review — response-side (no diode limit), healthy class size, and
  *defined* as naive out-of-bounds injection. EDA (to derive the empirical bound, since no
  documented range exists) shows the rule alone would catch ~79 % of pure-NMRI TEST
  windows at ~0.08 % new Normal FP, well past the bar.
- **WHY THIS TASK TOUCHES THE RULE LAYER (unlike EXP-0010/0014/0015):** those were
  diagnostics or additive-only outside the core detector. EXP-0016 deliberately adds a
  rule to `ml/rules.py`. The addition is strictly additive — `DeterministicRuleLayer` and
  its MFCI/Recon/func-code checks, all thresholds, and the Isolation Forest are unchanged,
  with a regression test proving it. The operational `run_detector` is **not** modified in
  EXP-0016; the effect of adding the rule to the frozen EXP-0004 TEST confusion is
  measured and reported so that wiring it in — which would update EXP-0004's baseline — is
  a separate, explicit decision.
- **IMPACT:** first concrete detection improvement in the project since EXP-0004. Bounds
  derived from TRAIN-normal only, per the corrected manifest. Known caveat: the rule reads
  the ARFF `pressure measurement` value via row alignment (as EXP-0009/0011a did); a real
  PCAP-replay deployment would decode it from the `0x03` response bytes, and that register
  map / scaling is undocumented — a separate open item.

---

### 2026-09-10 · DECISION — diagnose the NMRI / CMRI detection gap (EXP-0015); response-side, so no diode caveat

- **DECISION:** run a diagnostic-only experiment (EXP-0015) on the remaining two weak
  per-category rows in EXP-0004's combined detector — NMRI (`109/1,131` flagged,
  `9.6 %`) and CMRI (`232/1,812`, `12.8 %`) — completing the per-category gap review
  that EXP-0014 began with MSCI/MPCI. Same rigor: reproduce the frozen detector, read its
  scores, classify the root cause, build nothing.
- **OPTIONS CONSIDERED:** (a) assume NMRI/CMRI share DoS/MSCI/MPCI's structural limit and
  deprioritise; (b) assume they are a pure feature gap because the name says
  "response injection"; (c) confirm the direction from the dataset documentation and the
  raw frames, then measure feature separation and the already-trained IF's per-window
  scores.
- **WHY (c):** the direction is the decisive fact and must be verified, not assumed. It
  was: every NMRI and CMRI frame is `destination == 1`, `function 0x03` read response —
  the forged pressure telemetry the slave sends back. Zero inbound frames. So unlike
  DoS (inbound flood blocked by the diode) and MSCI/MPCI (malicious command payload
  never crosses the diode), **the NMRI/CMRI malicious content is the egress traffic
  itself**. A low-recall finding here is a feature/model gap, not a structural
  observation limit — which changes whether it is worth fixing.
- **WHY DIAGNOSTIC-ONLY:** EXP-0004's model stays frozen while its gaps are characterised;
  a fix is a separate pre-registered change with its own TEST-blind evaluation. EXP-0015
  reproduces the EXP-0004 model exactly and only reads from it.
- **IMPACT:** EXP-0015 produces a per-category root-cause classification and names the
  category of fix each indicates, with no fix built, and states plainly that the diode
  caveat does not apply here. Corrected manifest for all block assignment. New files
  only; EXP-0004 / DoS files / EXP-0014 / Layer A / `app.py` untouched.

---

### 2026-09-09 · DECISION — diagnose the MSCI / MPCI detection gap before proposing any fix (EXP-0014)

- **DECISION:** run a diagnostic-only experiment (EXP-0014) on the two worst non-DoS
  per-category gaps in EXP-0004's combined detector — MSCI (`2/324` flagged) and MPCI
  (`8/741`) — to establish *why* they are missed, before any feature or model work.
  MSCI and MPCI first (most severe); NMRI (`109/1,131`) and CMRI (`232/1,812`) are a
  later separate diagnostic.
- **OPTIONS CONSIDERED:** (a) assume it is the same "under-investment" story as elsewhere
  and jump straight to building features / a supervised model; (b) assume a structural
  ceiling like the diode explains it and deprioritise; (c) diagnose first — measure
  feature separation and the already-trained Isolation Forest's actual per-window scores,
  and classify the root cause per category.
- **WHY (c):** unlike Type 1 DoS, there is no known physics/architecture reason these
  categories should be near-zero — no dedicated feature engineering or diagnostic has
  ever been done on them. But "under-investment" is a hypothesis, not a finding.
  Committing feature/model effort without knowing whether the signal is (a) absent from
  egress, (b) present but under-threshold, or (c) starved of examples risks building the
  wrong fix. A cheap measurement settles it.
- **WHY DIAGNOSTIC-ONLY:** EXP-0004's model is frozen and must not move while its gaps
  are being characterised; a fix is a separate pre-registered change with its own
  TEST-blind evaluation. EXP-0014 reproduces the EXP-0004 model exactly (EXP-0010
  identity-check discipline), reads scores, and writes findings — it trains nothing.
- **IMPACT:** EXP-0014 produces a per-category root-cause classification (feature
  blindness / calibration / class imbalance / other) and names the *category* of fix
  each would indicate, with no fix built. It uses the corrected
  `verified-egress-5s-exp0008-pretest-v1` manifest for all block assignment. New files
  only; EXP-0004 / DoS files / Layer A / `app.py` untouched.

---

### 2026-09-09 · PROPOSED (NOT IMPLEMENTED) — add a `packets_per_sec` rate rule to the deterministic rule layer for Type 2 DoS

- **STATUS:** proposed follow-up only. **Nothing is built.** EXP-0010 is a diagnostic
  capability test; this entry records the recommended fix it motivates so a later task
  can pick it up without re-deriving it. "Diagnosed" is not "fixed".
- **PROPOSAL:** add one deterministic rule to `ml/rules.py`'s `DeterministicRuleLayer` —
  flag a five-second egress window whose `packets_per_sec` exceeds the TRAIN-normal
  maximum (`0.8` on the current verified capture), frozen from TRAIN-normal exactly like
  the existing function-code / address profile. OR-ed into the combined verdict alongside
  the existing rule and the Isolation Forest, unchanged.
- **EVIDENCE (EXP-0010, SYNTHETIC INJECTION TEST):** cohort = 4,807 real Normal TEST
  windows (negative) vs. the same 4,807 flood-injected (positive); `FP = 36`, `TN = 4,771`
  constant (= EXP-0004's real-Normal split). The existing rule-layer-OR-IF detector
  catches duplicate-frame floods (Profile B) fully — recall `1.0000`, precision `0.9926`
  at every severity ≥ 2× — but distinct-frame volumetric floods (Profile A) only at
  recall `0.2376` (precision `0.9694`), and raising severity 2× → 20× does not help
  because the IF anomaly score saturates just below the operating threshold. Every
  synthetic flood at ≥ 2× has `packets_per_sec ≥ 1.2` against a TRAIN-normal maximum of
  `0.8` and a real Normal-TEST maximum of `0.8`. A `packets_per_sec > 0.8` rule would
  flag **100%** of both profiles at all severities ≥ 2× with **0** new false positives on
  the 4,807 real Normal TEST windows.
- **OPTIONS CONSIDERED:** (a) retrain / re-threshold the Isolation Forest to catch
  volumetric floods — rejected: the IF's far-out-of-distribution score saturation is
  structural, and re-thresholding trades Normal FPR for it; (b) add a learned rate model
  — rejected as over-engineered for an unambiguous, cleanly separated signal; (c) one
  frozen rate-threshold rule in the layer that already handles constant-on-normal
  membership signals — chosen.
- **WHY LOW-RISK:** the rule layer already exists and is already OR-ed into the verdict;
  the threshold is a frozen TRAIN-normal statistic, not tuned on TEST; the signal is
  volumetric and unsubtle; EXP-0010 measured 0 new false positives on real Normal TEST.
  It does not touch the Isolation Forest, `app.py`, or Layer A.
- **IMPACT IF ADOPTED:** closes the Type 2 (egress-channel flood) detection gap for both
  flood shapes. Would be its own pre-registered experiment / change with its own frozen
  TEST-blind evaluation and full-suite run; **not** folded into EXP-0010.

---

### 2026-09-09 · DECISION — EXP-0010 tests Type 2 (egress-channel) DoS by synthetic injection because no labelled example exists

- **DECISION:** treat "DoS" as two distinct problems and test them separately.
  **Type 1** (external-flood DoS) is what the Turnipseed dataset's `DoS` label represents:
  a Bad-CRC flood on the *inbound command* path. It never crosses the diode; the slave's
  egress replies during it are byte-identical to normal traffic. It is structurally hard
  from a one-directional view and was closed at EXP-0013 (recall `0.269430`, precision
  `0.981132`, TEST-blind). **Type 2** (egress-channel / diode-termination flood) is an
  insider or compromised device flooding the *outbound* channel itself — excessive
  telemetry, high-frequency sensor spam, log flooding. This traffic **does** cross the
  diode by definition, because it *is* the egress stream. EXP-0010 tests whether the
  existing EXP-0004 detector already catches Type 2, using synthetic injection.
- **OPTIONS CONSIDERED:** (a) find a labelled Type 2 example in an available dataset;
  (b) capture one in a lab; (c) synthetically inject a volume/rate anomaly into real
  Normal egress windows and score the existing detector.
- **WHY (c):** no dataset in this project — Turnipseed included — contains a labelled
  egress-side volumetric flood; every `DoS`-labelled frame is inbound Bad-CRC. No lab
  capture rig is in scope before the deadline. Synthetic injection is therefore the only
  available method. It is legitimate here and **not** the earlier fabricated-dataset
  failure mode: the frames are real verified capture, only the rate/volume anomaly is
  synthetic, it is a capability probe of an already-frozen detector (no model is trained
  or tuned on it), and every result is labelled `SYNTHETIC INJECTION TEST` throughout —
  never presented as a real captured attack.
- **WHY TEST-portion windows are acceptable here:** EXP-0010 trains nothing and changes
  no detector code, threshold, or feature. The detector is immutable during the
  experiment, so nothing it "sees" can bias it toward the held-out set. Using the real
  Normal TEST windows as injection substrate and as an untouched false-positive control
  is categorically different from training-time TEST access.
- **IMPACT:** if the existing rule-layer-OR-Isolation-Forest detector already flags the
  synthetic floods, Type 2 DoS is effectively covered by the existing pipeline — a
  genuine, reportable positive result. If it does not, EXP-0010 will note (not build) a
  minimal fix: a fixed rate-threshold rule in the existing deterministic rule layer,
  which is low-risk because the rule layer already exists and a volumetric flood is not a
  subtle signal. No detector change is made in EXP-0010 itself. All boundary construction
  uses the corrected `verified-egress-5s-exp0008-pretest-v1` manifest; the existing
  detector's split is asserted byte-identical to it before scoring.

---

### 2026-09-09 · DECISION — EXP-0013 Configuration X selected for the one trustworthy Type 1 DoS frozen TEST

- **DECISION:** run exactly one genuinely TEST-blind frozen evaluation for Type 1 DoS
  using **Configuration X** — EXP-0011b's model recipe (Borderline-SMOTE
  `sampling_strategy="auto", k_neighbors=5, m_neighbors=10, kind="borderline-1",
  random_state=0` + `RandomForestClassifier(300, class_weight=None, random_state=0,
  max_depth=None, min_samples_leaf=1)`, threshold `0.50`) on the original 33 cadence
  features, retrained fresh on the corrected manifest's TRAIN population and scored once
  against the manifest-derived guarded TEST population.
- **OPTIONS CONSIDERED:** (a) Configuration X — 33 cadence features, no lag features;
  (b) Configuration Y — X plus the 16 EXP-0012 lag/trend features; (c) run no frozen
  TEST and leave EXP-0011b's invalidated number as the last word.
- **WHY X, NOT Y:** under the corrected manifest, EXP-0012b 5-fold block CV gave X mean
  recall `0.438±0.197` and Y mean recall `0.404±0.188` — Y **does not improve recall**
  despite winning the mechanical precision-floor selection rule (its gain is precision
  and false-positive suppression, i.e. F1). The frozen evaluation is for detection
  capability, so recall is the criterion of record. X is also simpler and adds no
  unproven feature engineering; the 16 lag features have no validated benefit. Both
  configurations show large fold-to-fold instability, which argues against spending the
  single frozen-TEST shot on the more complex option.
- **WHY NOT (c):** EXP-0011b's `26.9% / 91%` frozen TEST result is invalidated by the
  boundary-construction flaw and must not be cited as final. Type 1 DoS deserves one
  constructionally clean closing number.
- **FINGERPRINT NOTE:** EXP-0013 does **not** gate on EXP-0011b's pre-correction semantic
  fingerprint `bb89557b…`. The corrected manifest and the rewritten cadence-feature
  pipeline produce a fresh forest (fingerprint `d55a802e…`) from identical TRAIN/VALIDATION
  window counts (`28,040 / 9,345`). EXP-0013 asserts the exact sampler and RF knobs match
  EXP-0011b and records its own fingerprint; a knob mismatch stops before any TEST row is
  read.
- **IMPACT:** EXP-0013 is the only validated, trustworthy Type 1 DoS number going forward.
  Frozen TEST (threshold `0.50`, cohort `4,807` Normal / `193` DoS, `4,347` other-attack
  excluded): precision `0.981132`, recall `0.269430`, F1 `0.422764`, FPR `0.000208`,
  TN/FP/FN/TP `4,806/1/141/52`. The corrected boundary did not change the substantive
  finding — `52/193` DoS windows detected, `141` missed — versus the invalidated
  EXP-0011b `52/193`; it tightened precision (`0.912281 → 0.981132`, FP `5 → 1`).
  EXP-0008/0009/0011 TEST-adjacent numbers remain invalidated audit evidence only.
  No further Type 1 DoS variants or optimizations are authorized in this phase.

---

### 2026-09-09 · INVALIDATED — EXP-0012 boundary construction depended on TEST-tail eligibility

- **INVALIDATED — decision:** withdraw all original EXP-0012 X/Y folds, aggregates, and
  its recommendation. Retain them below only as an audit trail; do not cite them or use
  them to authorize TEST.
- **INVALIDATED — evidence:** `partition_pretest_inputs()` first enumerated every eligible
  egress window in the full capture and calculated 60/20/20 cut positions from that total.
  Mutating only nominal TEST-tail records so their destination/window eligibility changed
  altered both returned TRAIN and VALIDATION bucket sets. Thus TEST was not scored, but
  TEST-tail values were materialized and could change the pre-TEST population.
- **INVALIDATED — shared impact:** EXP-0008, EXP-0009, and EXP-0011 all used this shared
  pre-TEST constructor. EXP-0009's payload alignment called it a second time; EXP-0008 and
  EXP-0011b's guarded TEST paths also refit through it. Their historical validation claims
  are not constructionally TEST-blind, and already-consumed TEST results cannot be
  rehabilitated or rerun. Preserve all results as invalid/qualified audit evidence.
- **CORRECTION PRE-REGISTERED:** freeze the exact prior TRAIN 28,040 and VALIDATION 9,345
  bucket memberships in versioned manifest `verified-egress-5s-exp0008-pretest-v1`, digest
  `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`. Future pre-TEST
  construction selects only those IDs and stops reading after the final VALIDATION bucket.
  This prospective freeze prevents future tail dependence but does not retroactively
  validate the source split.
- **VALIDATED — EXP-0012b:** the eligibility-changing tail-mutation and stop-before-tail
  proofs passed, as did the full 92-test suite before fitting. The corrected run reproduced
  the same folds because the manifest intentionally freezes the prior memberships. X mean
  precision/recall/F1/FPR ± population SD was `0.676868±0.332675 /
  0.438335±0.196592 / 0.424670±0.209644 / 0.050778±0.093277`; Y was
  `0.821935±0.356129 / 0.404244±0.187667 / 0.474687±0.234629 /
  0.016547±0.033094`. Y mechanically wins the precision-floor rule again but lowers mean
  recall, and both remain highly regime-sensitive. Treat Y only as a provisional pre-TEST
  winner. **TEST NOT READ OR RUN; TEST count remains unknown/null.**

---

### 2026-09-09 · INVALIDATED — original EXP-0012 causal-feature block CV (audit trail)

- **PLANNED — decision:** compare two tabular Random Forest configurations on only the
  existing egress-only TRAIN+VALIDATION timeline: X is EXP-0011b's original 33 cadence
  features, and Y adds strictly prior-window lag/trend features. Use five deterministic
  contiguous forward-chaining folds, not shuffled individual-window folds. Frozen TEST
  remains unopened, and neither configuration receives a TEST path in this experiment.
- **PLANNED — LSTM/GRU ruled out:** the available DoS-containing window pool is only
  roughly 600–900 before splitting, at or below the user-supplied literature-informed
  floor of roughly 320–800 positive examples for rare-event deep sequence learning.
  Given that borderline sample size and the observed single-split overfitting, a full
  LSTM/GRU adds unjustified capacity and is out of scope. Test causal lag/trend summaries
  in the established tabular RF instead.
- **PLANNED — temporal CV choice:** ordinary stratified k-fold would randomly intermix
  adjacent five-second windows whose cadence states and traffic regimes are temporally
  correlated. Use past-only expanding training and one globally excluded window on each
  side of every contiguous segment boundary. Choose segment cut points from sixths of
  chronologically ordered DoS-window positions to improve positive balance without
  shuffling or breaking chronology; report actual per-fold DoS counts and any sparsity.
- **PLANNED — causal features and edge rule:** for each of `0x03` and `0x10`, add the
  prior five emitted windows' `deviation_mean`, least-squares slope, slope direction, and
  population variance. Never use the current/future window. Reset history at each
  independently built fold block and exclude its first five windows instead of padding
  or adding an availability flag.
- **PLANNED — frozen evaluation:** both X and Y use fold-local TRAIN-only response-type
  discovery, cadence baselines and CUSUM calibration; fold-TRAIN-only Borderline-SMOTE
  (`auto`, k=5, seed 0, installed `borderline-1`/m=10 defaults); the EXP-0011b 300-tree RF
  (`class_weight=None`, seed 0, `n_jobs=-1`, depth None, leaf 1); and threshold `0.50`.
  Report per-fold and mean/population-variance/std precision, recall, F1, and FPR.
- **PLANNED — selection/impact:** feasible means mean CV precision ≥`0.80`; among feasible
  configurations maximize mean recall, then mean F1, mean precision, lower mean FPR, and
  lower recall variance. Exact ties retain X. If neither is feasible, maximize mean F1
  with the same later tie-breakers and disclose failure of the precision floor. Y may be
  recommended for one later authorized TEST score only if it strictly wins. If X wins or
  ties, retain the already-tested EXP-0011b without rerunning TEST. New EXP-0012 files
  only; no integration, commit, or push before review.
- **IMPLEMENTED/TESTED — outcome:** isolated EXP-0012 code constructs five causal
  forward folds with fold-local preprocessing and TRAIN-only resampling; nine dedicated
  tests pass and the complete suite increased from 81 to 90 passing tests. No TEST path
  exists. One initial synthetic-test stub failure was corrected and disclosed.
- **VALIDATED — decision:** X mean precision/recall/F1/FPR was
  `0.676868/0.438335/0.424670/0.050778`; Y was
  `0.821935/0.404244/0.474687/0.016547`. Only Y meets the frozen mean-precision floor, so
  Y formally wins and may be considered for one later explicitly authorized frozen TEST.
  This is a precision/F1/FPR improvement, not a recall improvement: Y mean recall is
  `0.034091` lower, with unchanged recall in folds 2–5 except fold 1 where it trades 15 TP
  for 515 fewer FP. Both show large fold variance; Y recall ranges `0.218391–0.735632` and
  X `0.218391–0.735632`, while fold-1 precision is only `0.109677` for Y and `0.058333`
  for X. The re-baselined X mean recall below the old single-split `0.522167`, plus this
  spread, confirms that a single validation block was unstable. **TEST NOT RUN.** Retain
  this as a pre-TEST recommendation only; no integration, commit, or push.

---

### 2026-09-09 · PLANNED — test EXP-0011 protocol, sampler, RF-grid, and ensemble follow-ups on VALIDATION only

- **PLANNED — decision:** keep EXP-0009b as the incumbent and independently evaluate
  four preregistered follow-ups without opening TEST: diagnose and conditionally use
  `0x03` response pressure (0011a), compare Borderline-SMOTE and ADASYN (0011b), run a
  nine-point RF grid after frozen standard SMOTE (0011c), and average frozen-recipe RF/
  XGBoost probabilities equally (0011d). Report every candidate and retain EXP-0009b if
  no new configuration strictly wins the common rule.
- **PLANNED — protocol/payload choice:** Modbus `0x03` Read Holding Registers responses
  return register values, while `0x10` Write Multiple Registers responses acknowledge
  only starting address and quantity. Confirm this against canonical shapes and measured
  TRAIN/VALIDATION pressure counts. If pre-TEST `0x10` pressure is universally absent,
  treat it as structural and expose only seven `0x03` summaries plus an explicit
  availability flag; missing numeric values use declared zero placeholders and there is
  no `0x10` pressure field. If `0x10` pressure exists outside TRAIN, classify split
  sparsity and stop 0011a rather than widening TRAIN or inventing values.
- **PLANNED — frozen comparisons:** 0011b uses library Borderline-SMOTE and ADASYN with
  fixed default variant choices/k=5/seed 0; 0011c evaluates exactly depth None/10/20 ×
  leaf 1/2/5; 0011d uses equal probability weights only. All retain original cadence
  features and frozen model/resampling settings except the single dimension named by
  the sub-experiment. Resampling and fitting are TRAIN-only.
- **PLANNED — selection and impact:** each successful candidate receives the same
  0.10–0.90 by 0.05 VALIDATION sweep and EXP-0009 precision≥0.50/max-recall/F1 rule.
  Rank selected points by recall, F1, precision with incumbent-first exact ties. This
  prevents novelty bias. Code is isolated in new EXP-0011 modules/tests; EXP-0008/0009,
  prior experiments, Layer A, `app.py`, and dashboard remain untouched. No EXP-0011
  TEST materializer or scorer is allowed. Stop with `TEST NOT RUN`, show results/full
  diff, and wait before commit or push.
- **VALIDATED — protocol decision:** official Modbus V1.1b3 §6.3/§6.12 and the observed
  shapes agree that `0x03` returns register values while `0x10` acknowledges address and
  quantity only. All `0x03` TRAIN/VALIDATION frames had pressure and all `0x10` frames
  had none, including every class, so the earlier gate failure is structural rather than
  split sparsity. Permit the preregistered `0x03`-only features with explicit
  availability; continue to forbid any invented `0x10` pressure.
- **VALIDATED — outcome and choice:** the common VALIDATION rule formally selects 0011a
  at threshold `0.20` (precision `0.568528`, recall `0.551724`, F1 `0.560000`, FPR
  `0.017519`, TN/FP/FN/TP `4,767/85/91/112`) over incumbent 0009b at `0.60`
  (`0.929825/0.522167/0.668770`, FPR `0.001649`, `4,844/8/97/106`). This is a narrow
  recall gain of six true positives at the cost of 77 extra false positives and a large
  precision/F1 regression, not broad improvement. Borderline-SMOTE and the equal-weight
  ensemble each selected `0.963636/0.522167/0.677316`; ADASYN tied the incumbent; no RF
  grid point improved recall, and depth None/leaf 5 won that grid by frozen tie order.
  The ensemble improves precision only, not recall, at its selected point; neither full
  curve globally Pareto-dominates the other. Recommend 0011a only because the written
  rule prioritizes feasible recall—not because it is newer or uniformly better.
- **VALIDATED — impact/stop:** retain the recommendation as VALIDATION-selected and
  unconfirmed. Multiple comparisons reused one VALIDATION block, pressure remains
  ARFF-aligned rather than independently TXT-decoded, and the availability flag may
  encode schedule/presence. **TEST NOT RUN.** No integration, commit, or push is implied;
  one frozen TEST score still requires explicit authorization.
- **AUTHORIZED OVERRIDE — recorded before TEST:** retain 0011a as the mechanical
  recall-first result but do **not** advance it: +6 TP required +77 FP, worsened three of
  four reported rates, and its availability flag has an unresolved schedule/presence
  leakage question. Advance 0011b Borderline-SMOTE + RF at threshold `0.50` instead,
  with the original 33 cadence features and fingerprint
  `bb89557b34a1ff3850ae06a3e8151d70dad9f215837f5c0d5216e1a5b0f9cc40`. This explicit
  human deployment-suitability decision does not rewrite the preregistered mechanical
  rule. **TEST had not been run when this override was recorded.**
- **VALIDATED — one-shot outcome:** the guarded EXP-0011b fingerprint matched before
  TEST access. Its single threshold-0.50 TEST score was precision `0.912281`, recall
  `0.269430`, F1 `0.416000`, FPR `0.001040`, TN/FP/FN/TP `4,802/5/141/52` on 4,807
  Normal plus 193 DoS windows. Against EXP-0008 Detector B on the identical cohort, it
  preserves the same 52 TP/141 FN while reducing FP from 30 to 5; however, the
  VALIDATION recall did not generalize and 73.1% of DoS windows remain missed. Retain
  this exact result without tuning or rerun. **NO TEST RERUN.**

---

### 2026-09-09 · PLANNED — evaluate isolated EXP-0009 recall improvements on VALIDATION only

- **PLANNED — decision:** preserve EXP-0008's exact egress-only cohort, guarded split,
  TRAIN-only response-shape discovery, canonical mapper, baselines, and cadence features;
  independently test response pressure features (0009a), TRAIN-only standard SMOTE
  (0009b), XGBoost (0009c), and separate per-response-type RFs (0009d) at threshold 0.5.
  Then select one eligible variant and its threshold by the predeclared VALIDATION-only
  0009e rules. Report every result, including regressions and stopped variants.
- **PLANNED — options considered:** (a) tune or combine several changes at once; (b) use
  bidirectional command-side fields; (c) isolate four single changes, select one by frozen
  VALIDATION rules, and leave any later combination to a new experiment. Choose (c).
  XGBoost is chosen over LightGBM because it is already declared; standard SMOTE over
  Borderline-SMOTE avoids an additional border definition.
- **PLANNED — why:** EXP-0008 Detector B's frozen TEST recall was `0.269430`, so missed
  DoS windows warrant investigation, but that TEST result supplies motivation only—not
  a tuning target. Independent VALIDATION ablations distinguish whether additional
  response-visible semantics, class balancing, model family, or cadence-type
  specialization helps without hiding regressions or spending the held-out TEST again.
- **PLANNED — payload boundary:** exact TXT↔ARFF alignment and repository provenance
  support treating ARFF `pressure measurement` on `command response == 0` rows as a
  response-side value, and the user explicitly authorized that interpretation. 0009a
  may use only that field on rows aligned to TXT `destination == 1`; all command fields
  remain forbidden. A TRAIN-only provenance/leakage gate must reject a perfect or
  suspicious label proxy. Missing windows use frozen TRAIN-normal per-type baseline
  imputation without a missingness indicator. The raw TXT parser's inability to
  independently decode pressure is retained as a limitation.
- **PLANNED — selection/impact:** rank eligible 0009a–d at 0.5 by VALIDATION F1, then
  recall, precision, and fixed a→d order. For that single winner sweep 0.10–0.90 by 0.05;
  maximize recall subject to precision ≥0.50, with ties by F1, precision, and higher
  threshold; if infeasible, maximize F1 then recall, precision, and higher threshold.
  Freeze only that variant-plus-threshold as the proposed final configuration. Stop with
  `TEST NOT RUN` for explicit sign-off before one guarded TEST score. No post-hoc fusion,
  TEST tuning/rerun, main-pipeline integration, or modification of Layer A, dashboard,
  EXP-0004/0005/0005b/0007/0008 implementation files is authorized.
- **VALIDATED — VALIDATION-only outcome:** 0009a stopped at its payload gate because
  canonical `0x10` had no TRAIN-normal pressure value for its required per-type
  baseline/imputer; no substitute was used. At threshold 0.5, 0009b SMOTE+RF achieved
  precision `0.785185`, recall `0.522167`, F1 `0.627219`, FPR `0.005977`; 0009c
  XGBoost achieved `0.368056` / `0.522167` / `0.431772` / `0.037510`; and 0009d's
  per-type max/OR model achieved precision/recall/F1 `0` with FPR `0.029678`.
  Therefore 0009b won the frozen F1 ranking. Its 17-point sweep selected threshold
  **0.60** by maximum feasible recall then F1, yielding precision `0.929825`, recall
  `0.522167`, F1 `0.668770`, FPR `0.001649`, TN/FP/FN/TP `4,844/8/97/106` on
  VALIDATION. The proposed frozen TEST configuration is only 0009b TRAIN-only standard
  SMOTE plus RF at 0.60. **TEST NOT RUN**; explicit sign-off remains required.

---

### 2026-09-09 · PLANNED — rerun corrected egress cadence method under fresh EXP-0008

- **PLANNED — decision:** implement a fresh egress-only EXP-0008 rather than repairing
  or rerunning invalidated EXP-0007. Discover exact response shapes from TRAIN
  pure-Normal rows only, count exactly canonically mapped TRAIN-normal support, route
  audit/baseline/calibration/scoring through one mapper object, and route calibration
  and inference through one label-independent CUSUM replay implementation.
- **PLANNED — options considered:** (a) abandon cadence after invalidation; (b) patch and
  rerun EXP-0007; (c) preserve EXP-0007 as an invalid audit trail and pre-register a
  constructionally TEST-blind EXP-0008. Choose (c). Patching the old ID after viewing
  TEST would erase the experimental boundary; abandoning the hypothesis would confuse
  implementation defects with evidence against egress cadence.
- **PLANNED — why:** EXP-0007's shape discovery touched TEST, its support gate counted
  all TRAIN labels, its fitted and scored populations used different type assignment,
  and its calibration state process differed from inference. EXP-0008 makes these
  controls API and identity-test properties rather than prose assumptions. EXP-0007
  outputs—including its discarded detector metrics—are forbidden as inputs, tuning
  targets, or comparative evidence.
- **PLANNED — impact/controls:** EXP-0008 remains strictly `destination == 1`, uses the
  established chronological guarded split and fixed CUSUM/RF settings, and has no
  performance pass/fail gate. Synthetic tests must prove arbitrary TEST-value mutation
  cannot alter any pre-TEST artifact. After TRAIN/VALIDATION preparation, work stops for
  explicit sign-off before one frozen TEST score; no post-TEST tuning or rerun is
  authorized. Code is isolated in new EXP-0008 modules/tests. Existing EXP-0006,
  EXP-0007, Layer A, EXP-0004/0005/0005b, and dashboard files remain unchanged.
- **VALIDATED — outcome after explicit TEST sign-off:** the TRAIN/VALIDATION audit and
  all construction proofs passed before one guarded TEST execution. Detector A CUSUM
  detected 0/193 DoS-containing windows with 0/4,807 Normal false positives
  (precision/recall/F1/FPR all `0`). Detector B RF detected 52/193 with 30/4,807 Normal
  false positives (precision `0.634146`, recall `0.269430`, F1 `0.378182`, FPR
  `0.006241`). No post-TEST tuning or second frozen pass was performed. Detector A is
  not supported as an effective detector under this design; Detector B shows limited
  held-out egress-only signal on this one testbed but misses 141/193 DoS windows and is
  not evidence of general capability. EXP-0004 remains different-cohort context and
  EXP-0005b remains explicitly bidirectional/out of scope.

---

### 2026-09-09 · PLANNED — split egress cadence by response-visible type and compare CUSUM with supervised learning (EXP-0007)

- **PLANNED — decision:** make EXP-0007 an isolated, primary in-scope attempt at the
  unidirectional DoS requirement using only `destination == 1` egress traffic. Partition
  cadence streams by `(source, response-visible type)` while keeping raw source identity,
  direction, labels, and time identifiers outside the model feature matrix. First audit
  whether function code, confirmed by response shape, unambiguously separates source 3's
  two apparent Normal cadences; stop before modeling if the frozen support/tightening gate
  fails.
- **PLANNED — options considered:** (a) continue pooling all source-3 egress responses;
  (b) use Layer A/bidirectional features; (c) split the egress baseline by a field visible
  in the response and test both a statistical and supervised detector. Choose (c).
- **PLANNED — why:** Step 0 found that the pooled source-3 IAT tail largely bridges
  labelled episodes and that the remaining Normal distribution contains apparent
  1.5–1.9 s and 3.3–3.7 s modes. Pooling distinct schedules can hide missed cycles.
  Layer A is out of scope because it observes the command side. A one-sided per-type
  CUSUM tests an explicit sequential-delay hypothesis, while a fixed Random Forest tests
  whether the same egress-only cadence features carry supervised DoS signal that a
  threshold rule misses. Trying both distinguishes statistical-rule limitations from
  feature observability without changing the observation boundary.
- **PLANNED — impact/controls:** EXP-0004's measured pooled-timing null result remains
  valid; EXP-0007 tests a narrower pre-registered hypothesis rather than rewriting it.
  Type selection, baselines, CUSUM constants/threshold calibration, Random Forest
  settings, cohort, and split are frozen before TEST. There is no performance pass/fail
  gate and no post-TEST tuning. EXP-0005b is reported only as explicitly out-of-scope
  bidirectional context. New code is confined to `ml/cadence_features.py`,
  `ml/exp0007_cadence.py`, and dedicated tests; protected detector/dashboard files remain
  unchanged.

---

### 2026-09-09 · INVALIDATED — EXP-0007 TEST result withdrawn for audit leakage and method mismatch

- **INVALIDATED — decision:** withdraw every EXP-0007 detector metric before acceptance.
  Retain the generated numbers only as a clearly marked audit trail; do not cite them as
  held-out performance and do not repair or rerun EXP-0007 under the same ID.
- **INVALIDATED — evidence:** post-run review found that response-shape certainty was
  evaluated over full-capture Normal-labelled rows, including TEST, despite the frozen
  TRAIN/VALIDATION-only selection rule. The 1,000-frame support gate also counted all
  labels rather than TRAIN-normal frames. Baseline gap construction keyed raw function
  code while scoring required exact parser-certain shapes, and CUSUM calibration reset
  on labelled attack windows while scoring replay followed a different state process.
- **INVALIDATED — why it matters/impact:** these are held-out integrity and population
  consistency defects, so neither the CUSUM nor Random Forest number supports a claim.
  The defects were found through review, not hidden or tuned around. Any corrected
  attempt requires a new pre-registration and experiment ID, with canonical type
  assignment and explicit tests proving TEST mutations cannot affect pre-TEST outputs.
  EXP-0004 and the out-of-scope EXP-0005b historical results remain unchanged.

---

### 2026-09-08 · RETRACTION — `gas_pipeline_raw.txt` (sha256 45de4266…fbbd) was AI-generated, not a capture; EXP-0001/0002/0003 retracted

- **Decision:** the raw hex-frame file used by EXP-0001, EXP-0002 and EXP-0003
  (`data/raw/gas_pipeline_raw.txt`, sha256
  `45de4266d75553c8e658113ec4d43967c1de3ddaf38bb7022ad0a135b635fbbd`, 14,234,301
  bytes, 209,668 rows) is **confirmed AI-generated / fabricated content**, not a
  genuine testbed capture. It was pasted into an earlier AI chat session that was
  asked to "proceed" with it, and its hash was then recorded in
  `00-dataset-provenance.md` as if it had been provenance-verified. It never was.
  The file is **retracted**. If a verified copy is recovered, it will be named
  `data/raw/RETRACTED_gas_pipeline_raw.txt` (not deleted — kept for the audit
  trail) and must never again be an input to any pipeline stage. No verified copy
  is currently available locally; its absence is documented by hash and no
  placeholder was synthesized.
- **What was re-checked (2026-09-08):** 0% of the file's frames' trailing two bytes
  validate as a Modbus CRC-16 in either byte order. **This CRC check is not
  conclusive on its own** — the new genuine file (§below) shows the *same* 0% CRC
  signature, so a failed CRC does not by itself prove fabrication. The deciding
  evidence is the **confirmed origin** (pasted AI output, no capture provenance),
  not the CRC result.
- **Consequence:** EXP-0001, EXP-0002 and EXP-0003 in `EXPERIMENT_LOG.md` are
  marked **RETRACTED** (banner prepended, entries kept for audit). Every
  performance number they produced — the EXP-0002 "headline" IF recall 0.136 /
  combined 0.141, the EXP-0003 DoS effect sizes, DIAG-0001's XGBoost ceiling — is
  withdrawn and must not appear on any slide, README, or spec as a result. The
  exact-reproduction constants in `tests/test_detector.py` are now baselined
  against a retracted file and are invalid until EXP-0004 rebaselines them.
- **What is NOT affected:** `IanArffDataset.arff` (sha256 `970a7bcd…f459`) was
  always the authoritative file and is untouched. BLOCKER 1 (label codebook) and
  BLOCKER 2 (direction semantics) were resolved from the Turnipseed 2015 thesis and
  the ARFF, not from the retracted TXT — they still stand.
- **Options considered:** (a) silently replace the file and keep the experiment
  numbers; (b) delete the file and the experiment entries; (c) retract openly,
  keep the entries with a banner, re-run as EXP-0004. **Chosen (c)** — silent
  replacement would repeat the exact integrity failure being corrected, and
  deleting the entries destroys the audit trail of how the error entered.
- **Impact:** `00-dataset-provenance.md` (file inventory + CORRECTION section +
  BLOCKER 3), `EXPERIMENT_LOG.md` (retraction banners on EXP-0001/0002/0003 +
  DIAG-0001 + new EXP-0004), `tests/test_detector.py` (constants invalid pending
  EXP-0004), `README.md` / any doc quoting EXP-0002 numbers.

---

### 2026-09-08 · PLANNED — separate Layer A pre-diode DoS proof of concept (EXP-0005)

- **PLANNED — decision:** add an isolated OT-side Layer A proof of concept that observes
  the verified Turnipseed stream before direction filtering and emits only a sanitized
  DoS alert verdict outward. Keep EXP-0004 Layer B unchanged as the egress-only detector
  after the diode.
- **PLANNED — options considered:** (a) merge bidirectional features into Layer B;
  (b) leave DoS entirely out of software detection because Layer B cannot observe it;
  (c) add a separate pre-diode Layer A detector. Choose (c).
- **PLANNED — why:** merging would invalidate Layer B's unidirectional observer contract
  and disguise the observation-point difference. Omitting Layer A would fail to show
  that conventional detection remains possible inside OT where both directions are
  legitimately visible. Layer A does not send raw traffic across the diode, so it does
  not weaken the one-way boundary. Its potential capability comes precisely from
  visibility that Layer B is architecturally denied; this is complementary, not a
  contradiction or a reversal of EXP-0004.
- **PLANNED — scope/impact:** implement only `ml/layer_a_detector.py`, isolated tests,
  and a machine-readable result for EXP-0005. Dashboard/API/SQLite integration is
  deferred because the solo-developer deadline is 2026-09-15. Do not modify the Layer B
  detector, explainability, rules, or dashboard. Actual performance remains unmeasured
  until EXP-0005 runs; no claim that Layer A solves DoS detection is authorized.
- **VALIDATED — outcome (EXP-0005):** the isolated proof of concept ran once under its
  pre-registration and found 0/193 DoS-containing TEST windows (recall 0.000, precision
  0.000, F1 0.000) with 78/4,931 pure-Normal windows flagged (FPR 0.015818). Therefore
  Layer A is retained only as an architectural proof of placement, not as a validated
  working DoS detector. No post-TEST tuning is authorized under EXP-0005. The decision
  to keep it separate from Layer B still stands because their observation boundaries
  differ; the null result does not alter EXP-0004 and does not justify dashboard work.

---

### 2026-09-04 · DoS "CANNOT (egress)" verdict verified by measurement (EXP-0003)
- **Decision:** the DoS (Bad-CRC, specific 18) detection verdict, previously
  **CANNOT (egress)** on threat-model *reasoning* (EXP-0001), is now **CANNOT
  (egress) — MEASURED**. No detector or feature change; the verdict's basis is
  upgraded from "assumed" to "measured".
- **Options considered:** (a) leave the verdict as reasoning-only; (b) run a scoped
  measurement of egress timing before treating it as final; (c) speculatively add a
  Tier 2 IAT feature for DoS.
- **Why chosen (b):** a "CANNOT" that gates scope decisions should be measured, not
  inferred. EXP-0003 compared egress inter-arrival timing for DoS vs Normal windows
  on the **TEST split only** against a pre-registered decision rule. Result: **NO
  SEPARATION** — Cohen's d = +0.135 / +0.120 / +0.009 / +0.146 on
  `iat_mean`/`iat_std`/`iat_min`/`iat_max` (all < the 0.2 "no separation" threshold);
  raw inter-frame-gap distributions identical (d = +0.036, Mann–Whitney p = 0.45,
  Kolmogorov–Smirnov p = 0.65); best IAT threshold buys 8.7 % DoS recall at +5 %
  Normal FPR (noise). The 203 Bad-CRC egress frames are byte-identical to a normal
  `0x10` echo response. Option (c) is rejected by the same evidence.
- **Impact:** `EXPERIMENT_LOG.md` gains **EXP-0003** and the pre-registered
  CAN/CANNOT table DoS row is updated with the effect sizes / KS p-value.
  `06_AI_MODEL_EVALUATION_PLAN.md` Realistic-Expectations notes that EXP-0003 also
  forecloses the Tier 2 IAT rationale for CMRI/NMRI (same no-timing-signal logic).
  `ml/exp0003_dos_timing.py` added (measurement script, reproducible). **Phase 4
  (Tier 2 IAT features) is not pursued** — payload-content recall would need a new
  signal type, not identified.

---

### 2026-09-04 · Payload entropy admitted to the headline model; `function_code_valid` moved to a deterministic rule
- **Decision (two linked amendments, basis EXP-0001):**
  1. **Lift the payload-entropy exclusion.** `payload_entropy_mean` / `payload_entropy_std`
     are now headline Isolation Forest inputs on the TXT egress path (and TS-5 counts
     in headline recall there).
  2. **Remove `function_code_valid` from the IF feature set.** It becomes a standalone
     deterministic rule (invalid function code / novel address → immediate flag),
     OR-ed with the IF verdict.
- **Options considered:**
  - Entropy: (a) keep excluded per the 2026-09-02 pre-registration; (b) lift it;
    (c) keep excluded for the headline but always report a paired +entropy number.
  - `function_code_valid`: (a) leave it as an IF input; (b) move to a rule;
    (c) synthesise a variance-bearing surrogate feature.
- **Why chosen:**
  - The pre-registration's stated basis for excluding entropy was *"no join key links
    the payload TXT to the labels (BLOCKER 3)"*. That premise is **factually void**:
    `data/raw/gas_pipeline_raw.txt` is confirmed self-labelled
    (`00-dataset-provenance.md` §"CORRECTION (2026-09-04)"), so payload bytes and
    ground-truth labels sit in the same file. EXP-0001 measured the effect directly:
    adding entropy lifts IF recall **0.027 → 0.132** and precision to **0.82** on the
    held-out TEST block. This is measured signal on real labels, **not leakage** — a
    diode observer genuinely sees payload byte entropy on the wire. Amending a
    pre-registration is only legitimate when its premise was wrong (not when results
    disappoint); that condition is met and is documented.
  - `function_code_valid` is *exactly* constant (1.0) on all normal training windows.
    An Isolation Forest never draws a split on a zero-variance feature, so it
    contributed **nothing** to the anomaly score while occupying an input slot — EXP-0001
    showed the headline IF was blind to the strongest MFCI/Recon signal. A deterministic
    membership test is the right tool: out-of-profile function code / address → flag,
    no statistics needed. Stage 0 already did this at 100 % precision, so nothing is
    lost by making it explicit and independent of the IF.
- **Impact:** `05_FEATURE_ENGINEERING_SPEC.md` (Tier 1 IF table, new deterministic
  rule-layer subsection, modelling notes), `EXPERIMENT_LOG.md` pre-registration §2
  (amended) + **EXP-0002**, `06_AI_MODEL_EVALUATION_PLAN.md` (MODEL 1 input set),
  `04_DATASET_PLAN.md` (blockers summary + pre-registered constraints),
  `ml/rules.py` (new), `ml/iforest_detector.py` (rule layer + entropy headline).
  DoS and the payload-value categories (MSCI/MPCI/CMRI/NMRI) are **unchanged** — those
  EXP-0001 findings stand.

---

### 2026-09-03 · BLOCKER 1 resolved, BLOCKER 2 upgraded to primary-source confirmed
- **Decision:** treat **BLOCKER 1 (label codebook) as RESOLVED** and **BLOCKER 2
  (`command response` direction) as RESOLVED — CONFIRMED BY PRIMARY SOURCE**, both
  from the Turnipseed (2015) MS thesis (`docs/references/turnipseed-2015-scada-dataset-thesis.pdf`).
  The 2026-09-02 entry's "BLOCKER 1 remains the sole hard gate" and "BLOCKER 2 =
  documented assumption" positions are **superseded**.
- **Basis:** thesis §3.4–3.5 / Tables 3.5–3.8 give the full `categorized result`
  {0..7} and `specific result` {0..35} codebook; cross-checked exactly against the
  local ARFF `categorized × specific` cross-tab (all 35 IDs match). `binary result`
  0=normal/1=attack recorded at very-high (not verbatim-quoted) confidence. Thesis
  §3.5.2 p.34 defines `command response`: *"'0' for response or '1' for command."*
- **Why:** these were the last semantic unknowns gating label-based metrics and the
  egress filter value. Both are now primary-sourced, not inferred.
- **Impact:** metric gate LIFTED (label metrics permitted once split + artifact audit
  run and recorded); egress filter fixed at `command response == 0`. Updated:
  `00-dataset-provenance.md`, `04_DATASET_PLAN.md`, `EXPERIMENT_LOG.md`,
  `00_PROJECT_CHARTER.md`, `README.md`, `02-feature-schema.md`,
  `03-data-split-protocol.md`, `05-evaluation-plan.md`, `02_REQUIREMENTS_SPEC.md`,
  `01_PROBLEM_DEFINITION.md`, `07_SYSTEM_ARCHITECTURE.md`, `10_DEMO_SUCCESS_CRITERIA.md`.
  Open: dataset-count +1 discrepancy (minor, documented), BLOCKER 4 (public-release
  licence check), process/control-field tiering (see scope note below — unchanged,
  stays Tier 2/excluded).

---

### 2026-09-01 · Prototype deadline and build window
- **Decision:** internal hackathon milestone fixed at **2026-09-15**; ~14-day build
  window from 2026-09-01.
- **Options considered:** longer runway (not available — SIH internal date).
- **Why chosen:** externally fixed.
- **Impact:** all scope is sized against 14 days; drives the Tier 1/2/3 split below.

---

### 2026-09-01 · Dataset selection
- **Decision:** use the **Mississippi State University / Turnipseed (2015) SCADA gas
  pipeline** dataset (`data/raw/IanArffDataset.arff`, 274,628 verified instances).
- **Options considered:** MSU water-tank and storage-tank testbeds; other ICS
  datasets (SWaT, WADI, Electra); synthesising our own.
- **Why chosen:** gas pipeline is the simplest of the three MSU testbeds; exposes
  Modbus-style function-code fields needed for Tier 1; already present and verified
  in the repo; synthesising our own would undermine credibility.
- **Impact:** feature spec is built around the ARFF's real fields; inherits
  BLOCKERs 1–3 and the licence gap.

---

### 2026-09-01 · Model choice — Isolation Forest for the MVP
- **Decision:** Isolation Forest as the primary MVP detector.
- **Options considered:** One-Class SVM, Local Outlier Factor, Autoencoder.
- **Why chosen:** unsupervised / normal-only training fits the threat model; handles
  mixed continuous features with little preprocessing; fast to iterate within 14
  days; path-length score pairs naturally with a feature-level explanation. OC-SVM
  and LOF add tuning/scoring cost; Autoencoder adds a training surface not justified
  by the timeline.
- **Impact:** `06_AI_MODEL_EVALUATION_PLAN.md`; Autoencoder becomes Tier 3.

---

### 2026-09-01 · Contiguous time-block split; random splits forbidden
- **Decision:** train/validation/test are contiguous, time-ordered, non-overlapping
  blocks over the direction-filtered stream, with a guard gap at each boundary.
- **Options considered:** random row split; k-fold; stratified split.
- **Why chosen:** polling-loop self-similarity, windowed features straddling
  boundaries, contiguous attack episodes, and the train-past/test-future deployment
  story all make random splitting leak.
- **Impact:** `04_DATASET_PLAN.md`, `docs/03-data-split-protocol.md`,
  `09_TEST_VALIDATION_PLAN.md` T-12.

---

### 2026-09-02 · Tier 1 / Tier 2 / Tier 3 scoping decision  ← (this is the key scoping entry)
- **Decision:** partition all candidate features and threat classes into three tiers.
  **Tier 1** (MVP, committed): egress direction filter, 5 s per-source windows,
  basic features (packet/byte rate, IAT mean/std/min/max, function-code validity +
  frequency distribution, payload entropy mean/std as *one signal among several*),
  Isolation Forest on normal-only data, a naive statistical threshold **baseline for
  comparison only**, and feature-level explainability. **Tier 2** (stretch, only if
  Tier 1 validated with days to spare): IAT histogram distance, per-source rolling
  profiles, frame-length anomaly, address/point distribution entropy, and a cheap
  unseen-source check. **Tier 3** (documented future work, **not implemented**):
  epsilon-similarity of adjacent IATs, IAT multimodality / covert-symbol estimate,
  approximate entropy of the IAT sequence, Kolmogorov/compressibility estimate,
  autoencoder / LSTM-AE, IF+AE ensemble, covert storage channel detection,
  malformed-structure / protocol-conformance checking, replay/repetition detection.
- **Options considered:** (a) attempt the full anomaly landscape; (b) implement only
  Isolation Forest on basic features with no tiering; (c) the three-tier split.
- **Why chosen:**
  - *Deadline:* 14 days cannot support correct implementations of the complex covert
    -channel features plus a second model plus API + dashboard.
  - *Implementation risk:* the Tier 3 timing features (ApEn, Kolmogorov proxy,
    multimodality, epsilon-similarity) are individually intricate and
    parameter-sensitive; a subtly-wrong implementation produces confident nonsense,
    which is worse for a security tool than an honest omission.
  - *Literature finding:* simple threshold rules on timing are known to be brittle
    and evadable by adaptive covert channels that mimic the normal timing
    distribution (e.g. IP time-replay channels) — so the naive rule cannot be the
    detector, only a baseline; and the richer methods that *would* resist such
    evasion are exactly the ones that are hard to get right quickly.
  - *Honesty:* documenting Tier 3 shows research depth without over-claiming.
- **Impact:** authoritative across `00`, `02`, `03`, `05`, `06`, `07`, `09`, `10`,
  and the README. Any promotion of a Tier 2/3 item into the MVP requires a new
  decision-log entry and explicit user approval.
- **Update (2026-09-04, EXP-0003):** the Tier 2 **IAT** items (histogram distance,
  per-source rolling profile) are no longer a candidate recall lever — EXP-0003
  measured no egress timing signal for DoS, and the same reasoning applies to
  CMRI/NMRI. They remain documented as stretch, but pursuing them for detection
  recall is foreclosed. See `06_AI_MODEL_EVALUATION_PLAN.md` and the 2026-09-04
  EXP-0003 entry above.

---

### 2026-09-02 · Reinstate a minimal backend API + SOC dashboard for the demo
- **Decision:** the MVP includes a **minimal** backend REST API, an alert-history
  store (SQLite), and a minimal SOC dashboard sufficient to run the
  `10_DEMO_SUCCESS_CRITERIA.md` script (green→red + baseline-vs-ML comparison).
- **Options considered:** CLI-only output + static plots (the earlier
  `docs/07-scope-and-cuts.md` position); full-featured dashboard.
- **Why chosen:** the NTRO problem statement and the demo narrative call for a SOC
  -style visual; a *minimal* dashboard is achievable in the window, a full one is
  not. This **supersedes** the CLI-only cut recorded in
  `docs/07-scope-and-cuts.md` for the API/dashboard specifically.
- **Impact:** `02_REQUIREMENTS_SPEC.md` FR-8/FR-9, `07_SYSTEM_ARCHITECTURE.md`,
  `08_API_DATA_SCHEMA.md`. `docs/07-scope-and-cuts.md` to be annotated as superseded
  on this point. Dashboard remains strictly Tier 1-minimal; historical
  filtering/drill-down stays Tier 2.

---

### 2026-09-02 · Payload entropy kept in Tier 1 despite BLOCKER 3
- **Decision:** keep payload-entropy mean/std as a Tier 1 feature, explicitly as a
  *demonstrable computation* that is *not evaluable against dataset labels* (the
  authoritative ARFF has no payload bytes; the payload-bearing text file has no join
  key to the labels).
- **Options considered:** drop entropy to Tier 2; fabricate a join key; use the
  unlabelled file's entropy as a pseudo-label.
- **Why chosen:** the problem statement explicitly lists entropy as an MVP signal;
  fabricating a linkage is disallowed (`SECURITY_AND_ETHICS_BOUNDARIES.md`).
  Demonstrating the mechanism on fixtures while being honest about non-evaluability
  is the correct middle path.
- **Impact:** `05_FEATURE_ENGINEERING_SPEC.md`, `06`, `09` T-06; entropy alerts with
  no other contributing feature are marked low-confidence.

---

### 2026-09-02 · Documentation naming — numbered spec set added alongside existing recon docs
- **Decision:** create the `00_PROJECT_CHARTER.md` … numbered specification set as
  requested. The pre-existing lowercase recon docs (`00-dataset-provenance.md`,
  `01-threat-model.md`, `02-feature-schema.md`, `03-data-split-protocol.md`,
  `04-model-and-threshold.md`, `05-evaluation-plan.md`, `06-alert-schema.md`,
  `07-scope-and-cuts.md`) are **retained as the verified-measurement source of
  truth** and are referenced by the numbered docs.
- **Options considered:** rename/replace the lowercase docs; keep only one set.
- **Why chosen:** the lowercase docs contain hash-verified dataset facts and the
  blocker analysis; discarding them loses provenance. The numbered set is the
  engineering specification layer on top.
- **Impact:** two doc layers. Where they overlap, the lowercase recon docs win on
  *measured dataset facts*; the numbered docs win on *scope, requirements, and
  design*. `07-scope-and-cuts.md` is superseded on the API/dashboard point only
  (see entry above).

---

### 2026-09-02 · Blocker resolutions folded into docs (BLOCKER 2, 3, 4)
- **Decision:** record the three tractable dataset blockers as resolved/decided:
  **BLOCKER 2** — adopt the documented assumption `command response == 0` = the
  response/telemetry (egress) direction, kept by the direction filter, on the basis
  of Modbus exception codes 128–142 (incl. 136) appearing exclusively under value 0
  and the mean-`length` split (30.901 vs 50.383); flagged as inferred, pending
  confirmation against Turnipseed (2015). **BLOCKER 3** — no reliable ARFF↔TXT join
  key exists; a fuzzy timestamp join is explicitly **not** attempted; payload
  entropy stays a Tier 1 mechanism but is excluded from headline label-based metrics
  and TS-5 is reported as "not evaluable against dataset labels". **BLOCKER 4** — no
  explicit dataset licence exists; mitigation: keep raw files out of public repos
  (ship a download script + checksums), mandate citation of Turnipseed 2015 +
  Morris/Thornton/Turnipseed 2015 on any public artifact, and require a team member
  to verify official terms before any public release (open action item, not blocking
  the internal demo).
- **Options considered:** (2) filter both directions and pick later / hardcode a
  guess; (3) attempt a fuzzy timestamp join / drop entropy entirely / fabricate a
  pseudo-label; (4) assume permissive use / block all work until licence found.
- **Why chosen:** each keeps the pipeline moving without overclaiming. The direction
  assumption is well-evidenced and parameterised; forcing a payload join would inject
  silent label error worse than an honest omission; the licence position is the
  conservative one that still permits the internal demo.
- **Impact:** `docs/00-dataset-provenance.md` (§blockers rewritten),
  `04_DATASET_PLAN.md` (blocker summary + pre-registered constraints),
  `EXPERIMENT_LOG.md` (pre-registration block). BLOCKER 1 remains the sole hard gate
  on the evaluation plan.

---

### 2026-09-02 · Tier 1 dashboard downgraded to Streamlit/Gradio
- **Decision:** the Tier 1 "minimal SOC dashboard" is built as a **Streamlit or
  Gradio single-page app** that reads from the backend API / SQLite store — **not**
  as a bespoke web app (React/Vue + custom charting + hand-built timeline). It must
  still satisfy every demo requirement in `10_DEMO_SUCCESS_CRITERIA.md`
  (S-1 … S-8), including the baseline-vs-ML comparison view.
- **Options considered:**
  - Bespoke web dashboard — ~2.5–3 dev-days; best polish; highest schedule risk.
  - **Streamlit / Gradio single-page app — ~1.5 dev-days; chosen.** Reads the API,
    renders stats panel, anomaly-score gauge (green/red), alert timeline, per-alert
    explanation table, baseline-vs-ML comparison table.
  - CLI + matplotlib static plots only — ~0.5 day; no live interactivity; retained
    as the fallback (see hard gate below).
- **Why chosen:** the solo-developer budget working back from 2026-09-15 shows the
  **core pipeline alone consumes ~8–9 of ~13 working days** — dataset adapter,
  direction filter, windowing, Tier 1 features, the **instrumentation-artifact
  audit** (this dataset has a documented history of artifacts that can force feature
  rework), Isolation Forest training + validation-set threshold calibration, the
  naive baseline, explainability, and the evaluation harness with per-attack-type
  reporting. A bespoke web dashboard would cannibalise the buffer that core
  validation work needs. Streamlit/Gradio delivers the same demo value at roughly
  half the build cost and near-zero charting boilerplate.
- **Impact:** `02_REQUIREMENTS_SPEC.md` FR-9, `07_SYSTEM_ARCHITECTURE.md` module 10
  and tech stack, `10_DEMO_SUCCESS_CRITERIA.md`, `README.md` tech stack all specify
  Streamlit/Gradio. Historical filtering / per-source drill-down stays Tier 2.

---

### 2026-09-02 · HARD GATE — dashboard work is gated on a validated core experiment (go/no-go 2026-09-11)
- **Decision:** no dashboard work (Streamlit/Gradio *or* otherwise) begins until the
  **core pipeline has produced a validated `EXPERIMENT_LOG.md` entry** — i.e. an
  `### EXP-` entry with the split + artifact audit passed and (BLOCKER 1 permitting)
  real per-attack-type metrics recorded. **Checkpoint date: 2026-09-11.**
- **If, on 2026-09-11, no validated experiment entry exists:** the dashboard **falls
  back to CLI output + matplotlib static plots** (`docs/07-scope-and-cuts.md`'s
  original position) for the 2026-09-15 demo. The demo is then driven from the CLI
  with pre-rendered plots.
- **This fallback is pre-agreed and must NOT be re-litigated under time pressure**
  later in the sprint. It is recorded here specifically so that on 2026-09-11 the
  decision is a lookup, not a debate.
- **Options considered:** no gate (risk: dashboard half-built while core unvalidated
  on demo day); gate at 2026-09-13 (too late to execute the fallback well);
  **gate at 2026-09-11 — chosen** (leaves ~4 days either for the Streamlit app or for
  clean CLI+plots demo prep).
- **Why chosen:** protects the intellectually load-bearing deliverable (a
  leakage-controlled, honestly-evaluated detection pipeline) from being crowded out
  by presentation-layer work, while still giving the demo a visual if the core lands
  on time.
- **Impact:** noted in `02_REQUIREMENTS_SPEC.md` FR-9, `07_SYSTEM_ARCHITECTURE.md`,
  `10_DEMO_SUCCESS_CRITERIA.md`, `00_PROJECT_CHARTER.md` (MVP delivery surface), and
  `README.md`.
# 2026-09-10 — EXP-0017 baseline supersession — PLANNED

Human-approved decision: permanently include PressureBoundsRule in the operational
detector and supersede EXP-0004 as the headline baseline. EXP-0004 is superseded by
EXP-0017, retained for historical comparison; do not delete or rewrite its results.
The EXP-0017 benchmark is PLANNED until the pre-registered single guarded evaluation
passes (method and exact decision criteria: EXPERIMENT_LOG.md, EXP-0017).

Pressure comes from ARFF row alignment to canonical TXT 0x03 responses, NOT live
packet-byte decoding. TRAIN-normal min/max is empirical, not a physical safety
specification. Preserve this limitation prominently in the dashboard and overview.
Use only the versioned, checksummed EXP-0008 pretest manifest for split boundaries.
User authorized saved historical-output regression in place of historical reruns
and one shared guarded EXP-0017 output for tests/dashboard. Missing historical
arrays mean explicitly skipped pre-change tests, not fabricated before counts.
No protected experiment or Layer A files are modified. Dashboard diff must be shown
before application. No commit, push, or repeat TEST scoring is authorized.

## 2026-09-10 - EXP-0017 supersession completed - VALIDATED

The single authorized operational evaluation passed all seven pre-registered
identity gates: TN=4767, FP=40, FN=2166, TP=2374; recall 52.2907%, precision
98.3430%, Normal FPR 0.8321%. EXP-0017 is the primary benchmark; EXP-0004 is
superseded by EXP-0017, retained for historical comparison without rewriting its
original results. Full actual category results: [EXP0017_RESULTS.md](EXP0017_RESULTS.md).

**TESTED:** adapted before suite 126 passed / 12 skipped; after suite 147 passed /
0 skipped. Four historical integration tests replay saved summaries; no historical
scoring was repeated. The initial before run's two filesystem setup errors and its
retry are disclosed in EXPERIMENT_LOG.md. The dashboard loads saved results and
displays pressure explanations and the prominent ARFF-row-alignment limitation.
Its exact proposed diff was shown before application. Pressure is NOT decoded from
live packet bytes. No protected experiment or Layer A files were modified.

The saved evaluation and consumed-attempt ledger remain local, currently ignored
under `data/`; include them explicitly when a future commit/package is approved.
No commit or push is authorized or performed by this decision record.

# 2026-09-10 — EXP-0018 residual-smoothness diagnostic for missed CMRI — PLANNED

- **Decision:** test the external-research hypothesis that smooth CMRI response
  forgeries which stay inside the EXP-0016 pressure bounds are still detectable as
  *unnaturally quiet* one-step prediction residuals. Build a standalone
  residual-energy detector, measure it, and — as with EXP-0016 before EXP-0017 —
  DO NOT wire it into `run_detector()`. Measurement only; new files only.
- **Options considered:**
  (a) within-window residual variance/autocorrelation — **rejected**: egress 0x03
  pressure cadence is 1–2 samples per 5 s window, no intra-window series exists;
  (b) per-window single standardised residual at exact window granularity — weaker,
  deferred;
  (c) **chosen** — AR(1) residuals over the global 0x03 sequence, per-window verdict
  from a causal K=15-sample rolling residual-energy statistic, two-sided calibration
  against the TRAIN-normal energy distribution.
- **Why chosen:** (c) is the only form of the hypothesis the data cadence supports,
  keeps the model simple/explainable (one AR coefficient, one σ, two empirical
  quantiles), and CMRI episodes are long enough (median ~16 windows) that a
  ~55 s rolling window sits inside them.
- **Evaluation cohort, stated up front:** success is judged ONLY on CMRI TEST
  windows that EXP-0017's combined detector currently MISSES (`comb_pred == 0`).
  Already-caught CMRI windows earn no credit; only genuinely new detections count.
- **Decision rule:** STRONG = new-missed-CMRI recall ≥ 25% and new pure-Normal FP
  rate ≤ 0.30% and combined precision ≥ 97.0%; ACCEPTABLE = ≥ 10% / same bars;
  else HYPOTHESIS NOT SUPPORTED. Plus a threshold-independent Mann–Whitney U test
  (missed-CMRI vs Normal residual energy, α = 0.01, direction must match the
  hypothesis) — a null or wrong-direction result is reported as the idea not
  earning its place, exactly like every other experiment.
- **Constraints:** egress-only; checksummed EXP-0008 pretest manifest for all split
  boundaries; EXP-0017 saved output reproduced (all source sha256 + checksum +
  VALIDATED gate) before scoring; `run_detector` not called (attempt consumed);
  no change to protected EXP-0005..EXP-0013, Layer A, DoS/MSCI/MPCI files, or
  `app.py`. Full diff and real results shown before any commit; no push.
- **Impact:** method and exact criteria in `EXPERIMENT_LOG.md` (EXP-0018). If the
  verdict is STRONG/ACCEPTABLE, wiring it into `run_detector()` is a separate
  human decision (the EXP-0016 → EXP-0017 pattern).

## 2026-09-10 — EXP-0018 completed — HYPOTHESIS NOT SUPPORTED — negative result

The pre-registered evaluation ran once. Identity gates passed (EXP-0017 saved
output reproduced with no drift; `run_detector` not called). The residual-smoothness
hypothesis does not hold for CMRI in this testbed:

- Threshold-independent signal test is significant **in the opposite direction** —
  previously-missed pure-CMRI windows have *higher* AR(1) rolling residual energy
  than Normal (median 9.75 vs 0.008; Mann–Whitney p = 9.35e-69). The "over-smooth"
  (low-energy) variant catches only 14 / 544 = 2.57% of missed pure-CMRI.
- The two-sided rule at the pre-registered calibration flags 11.86% of pure-Normal
  TEST windows (bar ≤ 0.30%) and drops combined precision to 82.99% (bar ≥ 97.0%).
- Pre-registered decision rule → **WEAK / HYPOTHESIS NOT SUPPORTED**.

**Decision:** do NOT build on this signal; do NOT wire anything into
`run_detector()`. EXP-0018 is retained as a recorded negative result. No change to
`run_detector`, `app.py`, or any protected experiment / Layer A file. New files
only: `ml/exp0018_pressure_residual_smoothness.py`,
`tests/test_exp0018_pressure_residual_smoothness.py`,
`data/experiments/exp0018_pressure_residual_smoothness.json`, `docs/EXP0018_RESULTS.md`.
Full suite 147 → 156 passed. No commit or push performed by this record.

# 2026-09-10 — EXP-0019 physical rate-of-change plausibility diagnostic — PLANNED

- **Decision:** follow EXP-0018's negative result with a distinct test — whether a
  forged CMRI jump exceeds the physically plausible RATE of pressure change given
  the real elapsed time since the last `0x03` reading. Build a standalone rate rule,
  measure it, and — like EXP-0016 / EXP-0018 — do NOT wire it into `run_detector()`.
  Measurement only; new files only.
- **Distinct from EXP-0018:** EXP-0018 tested residual energy vs a fixed AR(1)
  variance and ignored Δt; its failure was that a fixed scale cannot tell a large
  legitimate pressure move from a large forged one. EXP-0019 divides by the true
  inter-sample time and calibrates against the empirical TRAIN-normal rate
  distribution, so a jump spread over a gap is correctly treated as more plausible.
- **Options considered:**
  (a) fixed round percentile with no justification — rejected;
  (b) engineering `dP/dt` limit from the register map — impossible, map/scale
  undocumented;
  (c) **chosen** — empirical TRAIN-normal 99.9th percentile of `|Δp|/Δt` as the
  plausibility bound (the fastest the real process was credibly seen to move over
  ~14,951 normal windows), with the TRAIN-normal max and 99.99th also reported and
  a stricter max-bound variant measured.
- **Why chosen:** (c) is the only defensible bound without a documented scale; it is
  robust to the ~20 most extreme normal steps and the 13 sub-cadence pairs while
  still representing real process dynamics. A k·σ bound is rejected on EXP-0018's
  evidence that this statistic is too heavy-tailed for a Gaussian scale.
- **Timing data confirmed clean:** TXT timestamps strictly monotonic (0 inversions);
  consecutive `0x03` Δt median 3.39 s, gaps characterised (~7 % at 3–4× cadence).
  Reuses EXP-0007/0008 timing understanding rather than re-deriving it.
- **Evaluation cohort:** CMRI TEST windows EXP-0017 already MISSES (`comb_pred == 0`);
  credit only for genuinely new detections. Same as EXP-0018.
- **Decision rule:** STRONG = new-missed-CMRI recall ≥ 25 % and new pure-Normal FP
  ≤ 0.30 % and combined precision ≥ 97.0 %; ACCEPTABLE = ≥ 10 % / same bars; else
  HYPOTHESIS NOT SUPPORTED. Bars re-justified against the 544-window cohort and the
  EXP-0017 headline, not blindly copied. Plus a threshold-independent Mann–Whitney U
  test (missed-CMRI rate vs Normal rate, α = 0.01, direction must be missed-CMRI
  higher). A null or wrong-direction result is reported as the idea not earning its
  place — a second honest negative result is still useful.
- **Constraints:** egress-only; checksummed EXP-0008 manifest for split boundaries;
  EXP-0017 saved output reproduced (all source sha256 + checksum + VALIDATED) before
  scoring; `run_detector` not called (attempt consumed); no change to protected
  EXP-0005..EXP-0018, Layer A, DoS/MSCI/MPCI files, `app.py`, or any EXP-0018 file.
  Full diff and real results shown before any commit; no push.
- **Impact:** method and exact criteria in `EXPERIMENT_LOG.md` (EXP-0019). If the
  verdict is STRONG/ACCEPTABLE, wiring it into `run_detector()` is a separate human
  decision (the EXP-0016 → EXP-0017 pattern).

## 2026-09-10 — EXP-0019 completed — HYPOTHESIS NOT SUPPORTED (pre-registered rule), but a near-miss

The pre-registered evaluation ran once. Identity gates passed (EXP-0017 reproduced,
no drift; `run_detector` not called). Result:

- **Signal confirmed, in the hypothesised direction** (unlike EXP-0018): missed
  pure-CMRI `|Δp|/Δt` per window is genuinely higher than Normal (median 0.0139 vs
  0.0067; Mann–Whitney p = 2.07e-19). ~26.65 % of the 544 previously-missed
  pure-CMRI windows are newly detected at the TRAIN-normal 99.9th-percentile cutoff.
- **But the pre-registered rule fails two bars:** pure-Normal FP 0.936 % (bar
  ≤ 0.30 %) and combined precision 96.945 % (floor 97.0 %). → **WEAK / HYPOTHESIS
  NOT SUPPORTED.**
- **The FP failure is mostly an artifact:** 35 of 45 pure-Normal FPs are the rule
  crediting a Normal window for pressure returning to normal after a preceding
  flagged/attack window. Residual FP excluding those: 10 / 4,807 = 0.208 % (would
  clear the bar).

**Decision:** EXP-0019 as specified is a recorded negative result — do NOT wire
anything into `run_detector()`, do NOT tweak-and-rescore against the same TEST.
Because the signal is real and the dominant FP mechanism is specific, authorise a
follow-up **EXP-0020** with a fresh pre-registration and a refined per-window rate
statistic (score a jump only against an in-bounds / unflagged predecessor, or only
the entry transition into an episode). No change to `run_detector`, `app.py`, or
any protected / EXP-0018 file. New files only:
`ml/exp0019_pressure_rate_plausibility.py`,
`tests/test_exp0019_pressure_rate_plausibility.py`,
`data/experiments/exp0019_pressure_rate_plausibility.json`, `docs/EXP0019_RESULTS.md`.
Full suite 156 → 164 passed. No commit or push performed by this record.

# 2026-09-10 — EXP-0020 refined rate rule with an in-bounds-predecessor gate — PLANNED

- **Decision:** run the refinement EXP-0019's logs recommended — score a pressure
  jump's rate only when its EARLIER sample is a plausible baseline — to test
  whether the identified 35/45 false-positive mechanism (crediting a Normal window
  for pressure returning to normal after an anomaly) was the real blocker.
  Build a standalone gated rate rule, measure it, do NOT wire it into
  `run_detector()`. Measurement only; new files only.
- **Exact predecessor-eligibility rule (fixed before scoring):** a consecutive
  `0x03` pair `(i-1, i)` is scored iff `Δt > 0` AND
  `0.482759 <= p_{i-1} <= 38.7471` — the earlier sample's pressure is within the
  EXP-0016 frozen TRAIN-normal bounds (from the checksum-verified EXP-0017
  artifact). The later sample is deliberately unconstrained (the hypothesis is that
  a forgery lands inside the bounds but moves there too fast).
- **Options considered:**
  (a) constrain both samples in-bounds — not chosen; "jump to out-of-bounds" cases
  are already caught by PressureBoundsRule, so constraining the later sample buys
  nothing and only adds risk of dropping a genuine in-bounds target case; kept the
  gate minimal (earlier sample only);
  (b) "earlier window `comb_pred == 0`" gate — rejected, couples a standalone rule
  to the operational detector's verdict;
  (c) "episode-entry transitions only" — rejected, needs an episode definition that
  requires labels or the same coupling;
  (d) **chosen** — earlier-sample-in-EXP-0016-bounds, a self-contained frozen value
  test that directly targets the identified mechanism.
- **Everything else unchanged from EXP-0019:** same feature, same
  TRAIN-normal-percentile calibration approach (re-fit on the gated feature), same
  evaluation cohort (CMRI TEST windows EXP-0017 misses), same decision rule and
  bars (STRONG ≥ 25 % new recall / FP ≤ 0.30 % / precision ≥ 97.0 %), same identity
  gates, same Mann–Whitney direction test. `run_detector` not called.
- **Honest disclosure:** EXP-0018/0019/0020 have each now scored the frozen TEST set
  once against a pressure hypothesis about the missed CMRI. Each is independently
  pre-registered, but iterative refinement across experiments is a
  garden-of-forking-paths risk; a truly held-out confirmation of any positive
  EXP-0020 result needs data not used here. Stated before scoring.
- **Constraints:** egress-only; checksummed EXP-0008 manifest; EXP-0017 reproduced
  before scoring; no change to protected EXP-0005..EXP-0019, Layer A,
  DoS/MSCI/MPCI, `app.py`, or any EXP-0018 / EXP-0019 file. Full diff and real
  results shown before any commit; no push.
- **Impact:** method and exact criteria in `EXPERIMENT_LOG.md` (EXP-0020). If the
  verdict is STRONG/ACCEPTABLE, wiring it into `run_detector()` is a separate human
  decision (the EXP-0016 → EXP-0017 pattern).

## 2026-09-10 — EXP-0020 completed — pre-registered rule NOT SUPPORTED; gate validated the EXP-0019 diagnosis

The pre-registered evaluation ran once. Identity gates passed (EXP-0017 reproduced,
no drift; `run_detector` not called).

- **The in-bounds-predecessor gate worked as designed:** pure-Normal FP 45 → 18,
  boundary-artifact FP 35 → 8, combined precision 96.945 % → 97.773 % (clears the
  floor). This confirms EXP-0019's root-cause diagnosis was correct.
- **But it also removed most of the detections:** new missed-pure-CMRI detections
  145 → 64; 84 missed-CMRI windows lost every eligible pair; new recall
  26.65 % → 13.91 % at the pre-registered p99.9 cutoff.
- **Pre-registered primary verdict → WEAK / HYPOTHESIS NOT SUPPORTED**: new
  pure-Normal FP 0.3745 % still exceeds the 0.30 % bar (by ~4 windows), though
  recall clears the 10 % ACCEPTABLE threshold and precision clears the floor.
- **Secondary:** the same gated rule at the TRAIN-normal-max cutoff reaches
  **ACCEPTABLE** — recall 12.17 %, FP 0.083 % (4 windows), precision 98.24 %.
- Signal still present in the hypothesised direction but far weaker
  (p = 1.8e-4 vs 2e-19 ungated) — most of EXP-0019's signal strength was the
  boundary jumps.

**Decision:** EXP-0020 as pre-registered is a recorded negative result — do NOT
wire anything into `run_detector()`, do NOT tweak-and-rescore. The physical-rate
hypothesis has a real but small effect (~12–14 % of the missed CMRI recoverable
within the FP budget). Whether to pursue it is a user judgement call: (a) an
EXP-0021 pre-registering the gated rule with the TRAIN-normal-max cutoff as primary
(and weighing a modest CMRI gain if it holds), or (b) closing the pressure-rate
line. No change to `run_detector`, `app.py`, or any protected / EXP-0018 /
EXP-0019 file. New files only: `ml/exp0020_pressure_rate_gated.py`,
`tests/test_exp0020_pressure_rate_gated.py`,
`data/experiments/exp0020_pressure_rate_gated.json`, `docs/EXP0020_RESULTS.md`.
Full suite 164 → 170 passed. No commit or push performed by this record.

## 2026-09-10 — Pressure-rate detection line CLOSED at EXP-0020 (option b)

- **Decision:** stop pursuing a pressure-derived rule for the CMRI that EXP-0017
  misses. No EXP-0021. Close the line opened at EXP-0018.
- **Reasoning:** three experiments (EXP-0018 / EXP-0019 / EXP-0020) have now scored
  the same 544-window frozen missed-CMRI cohort. As the diagnostics improved, the
  measured effect shrank from an artifact-inflated 26.65 % new recall (EXP-0019)
  down to a genuine ~12–14 % (EXP-0020), with weakening statistical significance
  (Mann–Whitney p: 2e-19 → 1.8e-4). The one remaining ACCEPTABLE variant (gated
  rule, TRAIN-normal-max cutoff) rests on **only 4 pure-Normal false-positive
  windows** — far too thin a sample to trust for generalisation. Continued
  iteration on this one cohort risks the exact validation-overfitting pattern this
  project already caught once (EXP-0009 → EXP-0011, the boundary/leakage
  invalidation). The hypothesis was not wrong — the honestly-measured effect is
  simply too small, and the cohort too thinly re-tested, to justify a fourth
  attempt.
- **Status of CMRI:** combined recall stays at **60.1 %** from EXP-0017 (its
  headline). No regression; nothing changed in `run_detector()`.
- **Next:** MSCI / MPCI — the largest remaining detection gap (EXP-0017: MSCI 4.63 %,
  MPCI 1.08 % dominant recall), and a different cohort entirely, so untouched by the
  forking-paths risk above. EXP-0014 was the diagnostic; the next experiment builds
  on that. Task framing pending.

## 2026-09-11 — EXP-0023 pre-registered: investigate 14 undecoded `0x03` bytes

**Status: PLANNED — investigative/descriptive only.** Characterize register-data
offsets 0–13 in canonical 23-byte `0x03` egress responses; use the candidate
big-endian float at offsets 14–17 and ARFF `pressure measurement` only to verify the
layout/alignment. Constant and candidate field structure are learned from pure-Normal
TRAIN windows in the corrected EXP-0008 manifest. Non-constant, non-random candidates
are compared with nearest-index matched pure-Normal windows using the EXP-0014/0015
Cohen's-d convention, with MSCI and MPCI first, followed by every other category for
which the candidate is observable. No detector, rule, model, threshold or TEST score
is authorized. `destination == 1`
is the only direction filter; the F-02 `source` artifact must not be parsed, bound,
filtered on, reported, or used in feature/decision logic. Process semantics remain
unknown unless primary documentation or a clean attack-event coincidence supports
them. Full results and diff must be shown before any commit; no push without explicit
approval.

## 2026-09-11 — EXP-0023 completed — no promising byte; MSCI/MPCI unobservable in this field

Identity gates passed (EXP-0017 reproduced; TEST never read). Pressure-offset sanity
check passed on all 48,060 Normal-category egress `0x03` rows (0 mismatches),
confirming the frame layout: 14 undecoded bytes = `frame[3:17]`, exactly 7 big-endian
16-bit registers, followed by the known pressure float at `frame[17:21]`.

- 8/14 bytes hard-constant in TRAIN-normal. Byte 5 is noise-like. Bytes 1/3/7/13 vary
  as small discrete sets consistent with packed status bits (bytes 1 and 3 identical
  in all 21,384 samples checked). Byte 4 correlates with decoded pressure at
  Pearson r=0.995 — the strongest finding, consistent with a raw analog channel on
  the same sensor, **not confirmed** as any specific process quantity.
- Thesis Appendix A's documented READS register map (7 registers: Digital
  Outputs/Inputs, Analog Input 0-4, then a 2-register float "Scaled Gas Pressure")
  structurally matches what's on the wire — named explicitly as an unconfirmed
  structural coincidence, since (unlike pressure) there is no ARFF column to
  independently verify it against.
- **0 pure MSCI/MPCI/MFCI/DoS/Recon windows contain any `0x03` traffic at all** — the
  motivating question can't be answered from this field, not merely answered
  negatively. CMRI/NMRI do have `0x03` traffic; every candidate byte/register/float
  compared there shows `|d| < 0.2` (negligible) everywhere, including the
  pressure-correlated byte.
- **Decision: no feature candidate identified. No detector, rule or model built or
  proposed from this field.** This reinforces EXP-0022's conclusion (`0x03` traffic
  structurally under-represents MSCI/MPCI) rather than opening a new lead.
- Full suite 198 → 215 passed. New files only:
  `ml/exp0023_0x03_register_bytes_diag.py`,
  `tests/test_exp0023_0x03_register_bytes_diag.py`,
  `data/experiments/exp0023_register_bytes.json`, `docs/EXP0023_RESULTS.md`.
  `source` never parsed/used (asserted by a static-analysis test). No commit or push
  performed by this record.

## 2026-09-11 — ACK-001 pre-registered: ack-anchored consequence detector, feasibility/coverage check only

**Status: PLANNED — feasibility/coverage check only.** No classifier, detector, rule
or threshold is built or scored. Population: every observable `0x10` echo-response
ack (`destination==1`, `function_code==0x10`, `frame_len_bytes==8`) in TRAIN+VAL only
(corrected manifest); TEST untouched. `source` is not parsed, bound, filtered on, or
used anywhere. Per-ack ground-truth label (Normal/MSCI/MPCI) is for reporting only,
never a runtime feature. Uses the proposed design's own numbers exactly: 30s/≥5
pre-ack baseline; post-ack horizons 10/30/60/120s with minimum scorable counts
2/5/10/20; 10s cluster gap; censoring compares each horizon to the gap to the next ack.
Pre-registered stopping rule: if the majority of MSCI or MPCI acks have no scorable
post-ack pressure data within 120s, that category is flagged likely infeasible and
reported as such, not built past. Full results and diff must be shown before any
commit; no push without explicit approval.

## 2026-09-11 — ACK-001 completed — INFEASIBLE once the design's own censoring rule is applied

Identity gates passed (EXP-0017 reproduced; TEST never read). Population: 51,229
egress `0x10` acks / 53,261 egress `0x03` pressure responses in TRAIN+VAL.

- Root cause: `0x03` and `0x10` traffic share a ~3.4s median inter-arrival cadence
  (the master's polling/control cycle), so 100% of acks are "clustered" under the
  design's own 10s definition.
- Raw (nominal-horizon) scorability looks fine (94.7–99.8%) and the pre-registered
  stopping rule, read literally, does not flag MSCI/MPCI — but that raw number
  ignores the design's own censoring/truncation rule. Applying it honestly:
  **censoring-aware scorability is exactly 0.00% at every horizon (10/30/60/120s),
  for Normal, MSCI, and MPCI alike**, confirmed by direct per-ack inspection (not
  just the aggregate), not a rounding artifact.
- **Corrected verdict: LIKELY INFEASIBLE for both MSCI and MPCI.** This is a
  population-wide data-density problem, not category-specific — Normal collapses
  identically. MSCI/MPCI acks are also 0% "pure" (always co-occur with another
  category in their 5s bucket).
- **Decision: do not build the fuller ack-anchored design (matched-reference
  detector, trajectory templates, supervised heads).** This is the same wall
  EXP-0023 hit for the payload bytes — the data doesn't support the question.
  Flagged explicitly that the literal pre-registered stopping rule (raw metric)
  would have given a false GO signal; the censoring-aware correction was necessary
  and is fully justified by the pre-registration's own step 6 honesty mandate.
- Full suite 215 → 237 passed. New files only:
  `ml/ack001_ack_anchored_coverage.py`,
  `tests/test_ack001_ack_anchored_coverage.py`,
  `data/experiments/ack001_coverage.json`, `docs/ACK0001_RESULTS.md`. `source`
  never parsed/used (asserted by a static-analysis test). No commit or push
  performed by this record.

## 2026-09-12 — PRE-REGISTRATION — ACK-002 (burst-level ack-anchored feasibility)

Feasibility check only, no model/classifier. One remaining cheap check before
treating the ack-anchored MSCI/MPCI line as fully closed (following ACK-001's
0.00% censoring-aware scorability). Question: does a clean pressure-sample window
exist after a whole BURST of writes ends, rather than after a single write.

- Burst-merging gap threshold derived **label-blind**: 3x the median inter-ack gap
  across all acks (Normal+attack, unlabeled), computed and fixed before any
  label-based outcome is examined. Not a value search for best separation.
- Labels (MSCI-containing / MPCI-containing / Normal-only burst) applied only at
  reporting time.
- Stopping rule (fixed in advance): >50% of MSCI- or MPCI-containing bursts with
  <2 uncontaminated post-burst pressure samples closes the line definitively — same
  standard as ACK-001. Expected to be negative (~5% chance of resolving it);
  honest reporting either way, no detector built regardless of outcome.
- New files only: `ml/ack002_burst_anchored_coverage.py`,
  `tests/test_ack002_burst_anchored_coverage.py`,
  `data/experiments/ack002_coverage.json`, `docs/ACK0002_RESULTS.md`.
  `run_detector`, `app.py`, DoS files, Layer A, closed CMRI files untouched.
  `source` never parsed/used. Full diff and go-ahead required before any commit;
  separate go-ahead before push.

## 2026-09-12 — ACK-002 completed — literal rule not triggered, but line closed anyway

Label-blind threshold (3× median inter-ack gap = 10.147s) merged 51,229 acks into
only 167 bursts — the tight ~3.4s cadence means splits only occur at rare tail
gaps, so bursts are mega-chunks (median 218 acks, ~13 min each), not attacker-scale
clusters.

- Literal stopping rule NOT triggered: 98.77%/95.04% of MSCI-/MPCI-containing
  bursts have ≥2 post-burst clean pressure samples — read alone, a GO signal.
- **Not a real positive**: 100% of those bursts also contain Normal traffic and
  span multiple categories with hundreds of acks — no single write inside a
  300+-ack burst can be credited with the post-burst pressure signal. The
  coverage reflects pressure density during the capture's rare pauses (episode
  boundaries), the same territory EXP-0021/0022 already covered (negative for
  MPCI), not a new usable observation unit.
- **Decision: do not build on the burst construction either.** Combined with
  ACK-001 (0.00% per-write scorability) and EXP-0021/0022/0023, the ack-anchored/
  write-response line for MSCI/MPCI is now treated as fully, definitively
  investigated — no further pre-registrations planned on this line.
- Full suite 237 → 263 passed. New files only:
  `ml/ack002_burst_anchored_coverage.py`,
  `tests/test_ack002_burst_anchored_coverage.py`,
  `data/experiments/ack002_coverage.json`, `docs/ACK0002_RESULTS.md`. `source`
  never parsed/used (asserted by a static-analysis test). No commit or push
  performed by this record.

## 2026-09-12 — PRE-REGISTRATION — EXP-0025 (wire in the Type 2 DoS rate rule)

Wires a THIRD rule (`RateFloodRule`, packets_per_sec > TRAIN-normal max) into the
deterministic rule layer, additive alongside protocol and pressure rules.
Targets Type 2 (egress-channel flood) DoS only — **explicitly does NOT address
Type 1 (external-flood) DoS**, which stays at 0% recall and is structurally
invisible on the egress side (diode blocks it). Must not be reported as "DoS
solved."

- Step 1: re-verify EXP-0010's 100%/0-FP finding under the CURRENT EXP-0017
  state (not re-cite the old number) using EXP-0010's exact synthetic-injection
  methodology, reused not reimplemented.
- Threshold re-derived fresh from current TRAIN-normal `packets_per_sec` max
  (expected ~0.8, verified not assumed).
- TEST is scored only via a closed-form derivation from the already-frozen
  EXP-0017 arrays (`rate_pred` is a deterministic function of the TRAIN-normal
  threshold and each TEST window's already-saved `packets_per_sec` feature) — no
  new TEST scoring event, since TEST must only ever be scored once (already
  consumed by EXP-0017). This is disclosed explicitly, not left implicit.
- New files: `ml/exp0025_dos_rate_rule.py`,
  `tests/test_exp0025_dos_rate_rule.py`,
  `data/experiments/exp0025_dos_rate_rule.json`, `docs/EXP0025_RESULTS.md`.
  Additive-only modifications: `ml/rules.py`, `ml/iforest_detector.py`,
  `tests/test_detector.py`, `tests/conftest.py` (if needed), `app.py`/docs.
  DoS Type 1 invalidated files, MSCI/MPCI closed files, Layer A, CMRI closed
  files untouched. Full diff and results required before any commit; separate
  go-ahead before push.

## 2026-09-12 — EXP-0025 completed — rate rule wired in; zero effect on real TEST data

Wired `rules.RateFloodRule` (Type 2 egress-flood DoS) into `run_detector()` as a
third additive OR term. New combined TEST confusion `(4767, 40, 2166, 2374)` is
**numerically identical to EXP-0017's** — verified directly that `rate_pred` is
0 for all 9,347 TEST windows, every category, DoS included. **Type 1 DoS
remains at 0% recall, unaffected — this is not "DoS solved."** No real Type 2
flood example exists in this dataset; the rule's 100%-at-≥5x/0-FP performance
(re-verified fresh, correcting an imprecise EXP-0010 note about 2x) is against
synthetic injections only.

- **Identity-gate collision, resolved with explicit user approval**: editing
  `ml/rules.py`/`ml/iforest_detector.py` (both required by the task) changed
  hashes pinned inside `exp0017_detector.json`'s own checksum, breaking
  `load_result()` for ACK-001/002 and EXP-0021/22/23. User chose: refresh only
  the `identity.source_sha256` ledger entries for those two files inside the
  existing frozen artifact (envelope checksum recomputed); the scored `result`
  payload was not touched. Verified: `load_result()` succeeds again and the
  full suite (all closed lines included) passes unchanged.
- TEST was not rescored a second time — the new confusion is a checked,
  closed-form derivation from the already-frozen EXP-0017 arrays.
- Full suite 263 → 275 passed. New files:
  `ml/exp0025_dos_rate_rule.py`, `tests/test_exp0025_dos_rate_rule.py`,
  `data/experiments/exp0025_detector.json`, `docs/EXP0025_RESULTS.md`.
  Additive-only modifications: `ml/rules.py`, `ml/iforest_detector.py`,
  `tests/test_detector.py`, `tests/conftest.py`, `app.py`. Identity-ledger-only
  modification (user-approved): `data/experiments/exp0017_detector.json`. DoS
  Type 1 invalidated files, MSCI/MPCI closed files, Layer A, CMRI closed files
  unchanged. No commit or push performed by this record.

## 2026-09-12 — PRE-REGISTRATION — EXP-0026 (native window-size exploration for MSCI/MPCI)

New, separate pipeline variant only — does not touch `ml/features_windowed.py`
or `run_detector()`. Tests whether redefining the observation unit natively
longer (5s baseline, 15s, 30s, 60s) reveals separation that the current
window-then-aggregate approach dilutes, independent of ACK-001/002's
already-closed per-write/per-burst attribution problem.

- Feature scope: EXP-0021's 5 pressure features only (`p_std`, `p_range`,
  `p_max_abs_step`, `p_trend_abs`, `p_mean_shift`), computed natively per
  window — not EXP-0014's 16 protocol/rate/entropy features, since those are
  structurally invariant to window size (MSCI/MPCI writes are byte-identical
  to Normal writes, already established).
- Split-boundary rule: a native window is discarded entirely (never truncated)
  unless every one of its constituent 5-second buckets belongs to the same
  manifest block — this also correctly discards windows crossing the
  manifest's existing internal TRAIN/VALIDATION gaps.
- Decision bar: `|d| >= 0.5` (EXP-0021's own gate) AND >= 30 pure-attack
  native windows for that (size, category, feature) — both required to
  proceed to building a detector. Cohen's d formula reused directly from
  `exp0021_msci_mpci.cohens_d` to enable an exact 5s-baseline reproduction
  check against EXP-0021's saved numbers before trusting new sizes.
- New files: `ml/exp0026_window_size.py`, `tests/test_exp0026_window_size.py`,
  `data/experiments/exp0026_window_size.json`, `docs/EXP0026_RESULTS.md`.
  `run_detector`, the 5s production pipeline, DoS Type 1 invalidated files,
  CMRI closed files, Layer A, `app.py` untouched. Full diff and results
  required before any commit; separate go-ahead before push.

## 2026-09-12 — EXP-0026 completed — gate not passed; a real bug caught by its own consistency check

The pre-registered 5s-baseline reproduction check caught a genuine
implementation bug on the first run (wrong cohort — `_pure` instead of
EXP-0021's `_containing`); fixed and reproduced EXP-0021's saved numbers
exactly before trusting any new window size.

- Primary cohort (matches EXP-0021): effect grows monotonically with window
  size (MPCI p_std 0.242→0.317→0.384→0.421 at 5/15/30/60s) but plateaus below
  the pre-registered `|d| >= 0.5` bar at every size tested.
- **Decision: no detector built at any native window size** — gate not
  passed, per pre-registration. Comparable to, not better than, EXP-0021's
  episode-level 0.446 (also sub-bar); fixed-grid windows don't recover what
  true episode-alignment provided.
- Disclosed secondary (non-gate) finding: the "pure" cohort shows a much
  larger, sharply growing MSCI effect (0.643→1.426) with shrinking n
  (606→117) while MPCI's pure-cohort effect stays negligible — genuinely
  surprising, explicitly NOT treated as gate-passing since it was never the
  pre-registered metric; would need its own pre-registration to pursue.
- Full suite 275 → 293 passed. New files only: `ml/exp0026_window_size.py`,
  `tests/test_exp0026_window_size.py`, `data/experiments/exp0026_window_size.json`,
  `docs/EXP0026_RESULTS.md`. `ml/features_windowed.py`, `run_detector`, DoS
  Type 1 invalidated files, CMRI closed files, Layer A, `app.py` unchanged.
  No commit or push performed by this record.

## 2026-09-12 — ERRATUM — EXP-0026's `p_mean_shift` contaminated by neighbouring CMRI injections

Found while diagnosing (user-requested, not a new experiment) whether the
MSCI 60s pure-cohort `p_std` effect (d=1.426) was small-n noise. A handful of
`p_mean_shift` values hit ~3.36e38 because it reads the PRECEDING native
window's pressure regardless of category, and a few neighbours are
CMRI-labelled with a genuinely huge forged pressure value (real attack data —
CMRI is naive out-of-bounds response injection — not a parsing bug). Only
`p_mean_shift` is affected (the other four features use only the window's own
samples); EXP-0026's reported conclusions do not rest on `p_mean_shift` and
are unaffected. `ml/exp0026_window_size.py` is not modified — documentation-
only flag so this feature is not reused uncritically later.

## 2026-09-12 — Diagnostic (not a new experiment): MSCI pure-cohort 60s `p_std` effect is NOT small-n noise

User requested a diagnostic (no new files, no commit) on the 117-example
pure-MSCI vs 1028 pure-Normal `p_std` comparison from EXP-0026's disclosed
secondary finding. Findings: the shift is broad (53.8%/45.3%/34.2% of MSCI
windows exceed Normal mean+0.5/1.0/2.0 std), not outlier-driven (removing the
top 10/117 most extreme values only drops d from 1.426 to 1.088), stable under
resampling (bootstrap 95% CI on d: (1.12, 1.75), comfortably clear of the 0.5
gate), and spread across 74 distinct contiguous episodes (not 2-3 clusters).
**Approved: worth a genuine pre-registered follow-up — see EXP-0027.**

## 2026-09-12 — PRE-REGISTRATION — EXP-0027 (MSCI 60s p_std vs the realistic population)

Tests whether EXP-0026's MSCI 60s `p_std` pure-cohort effect (d=1.426,
already verified not small-n noise) survives against ALL MSCI-containing 60s
windows (pure + mixed), not just the pure/isolated subset — closer to what a
deployed detector would actually see.

- Same bar as EXP-0021/0026: `|d| >= 0.5` AND `n >= 30`, now applied to the
  realistic (containing) population. Not weakened for this harder test.
- Reuses `ml/exp0026_window_size.py`'s functions read-only; 60s window size
  only, no re-exploration of other sizes.
- If it passes: build and measure a standalone detector, VALIDATION-first,
  TEST untouched without separate explicit approval. If it fails: report
  honestly as a selection-effect artifact, still a valuable, well-verified
  negative result.
- New files only: `ml/exp0027_msci_realistic_population.py`,
  `tests/test_exp0027_msci_realistic_population.py`,
  `data/experiments/exp0027_msci_realistic_population.json`,
  `docs/EXP0027_RESULTS.md`. `ml/features_windowed.py`, `run_detector`, the 5s
  production pipeline, `ml/exp0026_window_size.py`, DoS Type 1 invalidated
  files, CMRI closed files, Layer A, `app.py` untouched. Full diff and
  results required before any commit; separate go-ahead before push.

## 2026-09-12 — EXP-0027 completed — gate not passed; pure-cohort effect is a real but non-deployable selection artifact

Identity check reproduced EXP-0026's pure-cohort d exactly (1.4263). Realistic
population (all MSCI-containing, pure+mixed, n=310) gives d=+0.448 — below
the 0.5 gate. **Decision: no detector built.**

- Explained the mechanism: pure (d=1.426) and mixed (d=0.697) sub-populations
  each show a real effect, but pooling a heterogeneous mixture into one
  "MSCI-containing" class inflates variance more than it moves the mean,
  which is what Cohen's d penalizes — this is why the combined number is
  LOWER than either sub-population's own d, not a paradox or a bug.
- Ruled out CMRI contamination as the cause (informational cross-check):
  excluding all CMRI-co-occurring windows drops d further, to 0.178 — the
  pooling mechanism dominates, not the ~1e36-scale forged pressure values
  that happen to co-occur in some mixed windows (real CMRI attack data, same
  phenomenon as the p_mean_shift erratum below).
- **Verdict: the pure-cohort effect is real (already verified not small-n
  noise) but a selection artifact, not a deployable signal** — a detector
  cannot select for "pure" windows before scoring them. This closes the
  MSCI-60s-p_std standalone-detector lead; does not reopen ACK-001/002 or
  invalidate EXP-0026's primary findings.
- Full suite 293 → 303 passed. New files only:
  `ml/exp0027_msci_realistic_population.py`,
  `tests/test_exp0027_msci_realistic_population.py`,
  `data/experiments/exp0027_msci_realistic_population.json`,
  `docs/EXP0027_RESULTS.md`. No commit or push performed by this record.
