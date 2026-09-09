# Decision Log

Format: **DATE · DECISION · OPTIONS CONSIDERED · WHY CHOSEN · IMPACT**

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
