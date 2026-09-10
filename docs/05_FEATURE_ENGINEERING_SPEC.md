# 05 — Feature Engineering Specification

**VALIDATED current baseline: EXP-0017.** EXP-0004 is superseded by EXP-0017,
retained for historical comparison. The IF feature set is unchanged. A permanent
PressureBoundsRule now joins the protocol rules outside the IF: flag a window's
finite canonical 0x03 pressure minimum below 0.482759 or maximum above 38.7471.
These are observed TRAIN-normal extrema, not physical process limits.
**Pressure is ARFF-row-aligned to TXT responses, NOT live packet-byte decoding;
the register map/scale remains undocumented.** This additional data requirement is
mandatory for the current offline evaluation. See [EXP0017_RESULTS.md](EXP0017_RESULTS.md).

Scope tiers match `00_PROJECT_CHARTER.md` / `02_REQUIREMENTS_SPEC.md`:
**Tier 1** implement (MVP), **Tier 2** stretch (only if Tier 1 validated early),
**Tier 3** document only — **do not implement in the MVP**.

All features are computed **per 5-second window, per source**, over the
**egress-only** filtered stream, **within a single train/validation/test block**
(`04_DATASET_PLAN.md`). Windows with incomplete history at a block edge are dropped
or flagged, never zero-filled.

Data-source note: two artifacts are in play. `data/raw/IanArffDataset.arff` is the
authoritative *ARFF* path (`docs/02-feature-schema.md`) and has **no raw payload
bytes**. `data/raw/gas_pipeline_raw.txt` is the *TXT egress* path used by
`ml/features_windowed.py` — it **does** carry payload bytes and is verified row-aligned
to the ARFF across all 274,628 rows (`00-dataset-provenance.md` §NEW AUTHORITATIVE RAW
FILE), so payload entropy is computable and evaluable against authoritative labels.
Entropy is a Tier 1 headline IF feature on the TXT path; on the ARFF-only path it is
unavailable.

---

## Tier 1 — IMPLEMENT (MVP feature set)

| Feature | Meaning | Data type | Unit | Window | Normalization | Cybersecurity relevance | Tier |
|---|---|---|---|---|---|---|---|
| `packet_count` | number of egress packets in the window | integer | packets | 5 s | standardized (z-score) vs train-normal mean/std, per source | Bulk/staged exfiltration inflates packet count (TS-3). | T1 |
| `packets_per_sec` | `packet_count` / window length | float | packets/s | 5 s | z-score vs train-normal | Rate spikes / drops signal volume anomalies or paced channels (TS-3, TS-4). | T1 |
| `bytes_per_sec` | total egress payload+header bytes / window length | float | bytes/s | 5 s | z-score vs train-normal | Throughput deviation is the most direct exfiltration indicator (TS-3). | T1 |
| `iat_mean` | mean inter-arrival time between consecutive egress packets in the window | float | seconds | 5 s | z-score vs train-normal | A steady polling loop has a tight IAT mean; shifts indicate paced signalling or added traffic (TS-4). | T1 |
| `iat_std` | standard deviation of IAT in the window | float | seconds | 5 s | z-score vs train-normal | Covert timing channels change IAT dispersion even when the mean is held constant (TS-4). | T1 |
| `iat_min` | minimum IAT in the window | float | seconds | 5 s | z-score vs train-normal | Back-to-back bursts (near-zero min IAT) indicate injected traffic. | T1 |
| `iat_max` | maximum IAT in the window | float | seconds | 5 s | z-score vs train-normal | Long gaps can indicate gating / on-off keying of a covert channel. | T1 |
| `function_code_dist_*` | per-source frequency distribution of `function` codes in the window (one normalized count per code in the learned code set, or a divergence scalar vs the train-normal distribution) | float vector / float | ratio / divergence | 5 s | distribution normalized to sum 1; divergence (e.g. L1 or Jensen–Shannon) vs train-normal profile | A shift in the *mix* of operations (e.g. sudden writes where only reads are normal) flags misuse of the channel (TS-1). | T1 |
| `payload_entropy_mean` | mean Shannon entropy (bits/byte) of packet payloads in the window | float | bits/byte | 5 s | z-score vs train-normal | Compressed/encrypted exfil raises entropy above low-entropy telemetry (TS-5). **ONE SIGNAL AMONG SEVERAL — NEVER SUFFICIENT ALONE.** Evadable by padding/fragmenting to mimic normal entropy. Headline IF input (amended 2026-09-04); evaluable vs labels on the self-labelled TXT egress path. | T1 |
| `payload_entropy_std` | standard deviation of per-packet payload entropy in the window | float | bits/byte | 5 s | z-score vs train-normal | Mixed plaintext + encrypted content inflates entropy variance; same caveats as `payload_entropy_mean`. Headline IF input (amended 2026-09-04). | T1 |

## Tier 1 — deterministic rule layer (runs ALONGSIDE the Isolation Forest, not inside it)

Confirmed on the verified dataset by EXP-0004. Features that are **exactly constant
on normal traffic** carry the strongest signal for protocol-violation attacks (MFCI,
Recon) but an Isolation Forest **cannot use them** —
it never draws a split on a zero-variance feature, so they contribute nothing to the
anomaly score. They are moved out of the IF input vector into a small deterministic
rule that fires independently and is OR-ed with the IF verdict.

| Rule | Fires when | Cybersecurity relevance |
|---|---|---|
| `invalid_function_code` | any frame in the window carries a `function` code not in the train-normal set (on this dataset: not in `{0x03, 0x10}`) | An already-compromised device issuing out-of-profile Modbus function codes — MFCI, function-code-scan Recon (TS-1). |
| `novel_address` | any frame carries a slave `address` not seen in train-normal | Device-scan Recon / addressing a unit that never speaks on this link. |

- The learned "valid function code set" and "valid address set" are frozen from the
  **TRAIN-normal block only**, same discipline as the IF standardiser.
- Rule hits are surfaced in the alert explanation as `NOVEL VALUE` contributions
  (`06_AI_MODEL_EVALUATION_PLAN.md` FR-6), not as z-scores.
- Rationale and measured effect: `EXPERIMENT_LOG.md` EXP-0004. On the verified
  dataset the rule catches MFCI and Recon at 100 % with 0 % added Normal FPR, while
  keeping zero-variance fields out of the IF input.

### Tier 1 modelling notes

- **The IF model input vector is the scalar Tier 1 features above**, MINUS the
  deterministic-rule fields (`function_code_valid`, address novelty), PLUS the two
  entropy features (see amendment). The function-code *distribution* / divergence
  scalar stays an IF input — it has variance on normal traffic; the *validity
  fraction* does not.
- **Entropy is IN the headline model.** The earlier exclusion of
  `payload_entropy_mean` / `payload_entropy_std` was predicated on BLOCKER 3 ("payload
  bytes cannot be joined to labels"). Exact alignment of the current TXT with the ARFF
  resolves that blocker. In EXP-0004's paired comparison, entropy increased IF recall
  from 0.0084 to 0.1093 and PR-AUC from 0.5565 to 0.6493. The "one signal among
  several / never sufficient alone" and low-confidence-if-only-entropy disciplines
  below still stand.
- **Normalization / standardization** parameters (per-feature, per-source mean and
  std, and the learned "valid function code" set, and the train-normal function-code
  distribution) are **fitted on the TRAIN-normal block only** and frozen. They are
  reused unchanged on validation and test. This is itself a leakage control.
- **Explainability** (`06_AI_MODEL_EVALUATION_PLAN.md`, FR-6): for each alert, report
  the top-k features by absolute standardized deviation, with observed value and
  baseline (train-normal) value.
- **Entropy discipline:** any alert whose *only* contributing feature is an entropy
  feature must be labelled low-confidence in the explanation, reflecting the
  documented weakness.

---

## Tier 2 — STRETCH (implement only if Tier 1 is fully working and validated with days to spare)

| Feature | Meaning | Data type | Unit | Window | Normalization | Cybersecurity relevance | Tier |
|---|---|---|---|---|---|---|---|
| `iat_hist_distance` | distance between the window's IAT histogram and a learned "normal" IAT histogram | float | chi-square / KS statistic | 5 s (histogram over the window's IATs) | statistic is scale-free; compare to train-normal distribution of the same statistic | Detects timing-distribution changes that mean/std miss — a covert channel can hold mean/std and still reshape the histogram (TS-4). | T2 |
| `src_profile_deviation` | deviation score of the window against a per-source rolling behavioural profile (typical IAT distribution, packet rate, function-code mix, payload entropy) | float | composite z / divergence | 5 s vs rolling profile | each component standardized against its own rolling estimate | Per-source baselining catches "this device, specifically, is behaving unlike itself" even if it looks normal globally (TS-1, TS-4, TS-6). | T2 |
| `frame_length_anomaly` | degree to which window frame lengths deviate from the learned fixed-length templates | float | ratio / count of off-template frames | 5 s | fraction off-template; compare to train-normal ≈ 0 | SCADA/Modbus frames are often fixed-length; off-template lengths suggest tampering or an embedded channel (TS-1, precursor to TS-7/TS-8). | T2 |
| `addr_point_entropy` | Shannon entropy of the distribution of unique addresses/points (`address`) accessed in the window | float | bits | 5 s | z-score vs train-normal | A compromised device sweeping many registers/points (scan-like behaviour on the egress side) raises address-distribution entropy. Limited on this dataset (`address` near-constant). | T2 |
| `unseen_source_flag` | 1 if the window's source identifier was never seen in the TRAIN-normal data | boolean | 0/1 | 5 s | none | Unauthorised device emitting on the channel (TS-6). Cheap bolt-on — may be promoted into Tier 1 only if Tier 1 finishes early. | T2 (else T3) |

---

## Tier 3 — DOCUMENT ONLY. DO NOT IMPLEMENT IN THE MVP.

Listed to show research depth. Each is individually hard to implement correctly, and
a subtly-wrong implementation is worse than an honest omission given the timeline.

| Feature (not implemented) | Meaning | Why deferred |
|---|---|---|
| `iat_epsilon_similarity` | fraction of adjacent IAT pairs within ε of each other | Choice of ε is dataset-specific and unprincipled without study; easy to produce a meaningless number. |
| `iat_multimodality` | number of peaks in the IAT distribution; estimated covert-symbol count | Peak-counting is sensitive to binning/smoothing; "symbol count" is an inference that needs its own validation. |
| `iat_approx_entropy` | approximate entropy (ApEn) of the IAT sequence | Parameter-sensitive (m, r); expensive; correctness hard to verify under time pressure. |
| `iat_kolmogorov_ratio` | compressibility of the IAT sequence (e.g. zlib ratio) as a Kolmogorov-complexity proxy | Proxy quality depends heavily on serialization/quantization choices; misleading if done casually. |

Also documented-only at the feature level (detection side in `03_THREAT_MODEL.md`):
covert **storage** channel fields, malformed/non-standard structure conformance,
replay/repetition signatures.

---

## Identifier-as-Feature Policy (required reasoning)

- **Raw source/destination IP addresses are NOT used as model features.** Reasons:
  (a) they are identifiers, not behaviour — a model can memorise them and appear
  accurate while learning nothing generalisable; (b) they leak the train/test split
  when attack episodes come from fixed hosts; (c) on the project dataset `address` is
  near-constant so it carries almost no information anyway.
- **Source identity is used only** for (i) grouping windows per source and (ii) the
  Tier 2 `unseen_source_flag` check — both are membership tests, not learned
  embeddings.
- **`command response` is used only as the direction filter**, then becomes constant
  post-filter and is dropped as a feature by construction.
- **`crc rate` is excluded** pending the artifact audit; it is not added back on the
  grounds that it is "free".
- Any decision to admit an identifier or excluded attribute as a feature requires a
  recorded audit result in `EXPERIMENT_LOG.md`, not a judgement call.

### Process / control fields — evaluated for Tier 1 promotion (2026-09-03), recommendation: KEEP EXCLUDED

Prompted by the thesis Table 3.4 confirming `setpoint`, `gain`, `reset rate`,
`deadband`, `cycle time`, `rate`, `system mode`, `control scheme`, `pump`, `solenoid`
(Command Payload) and `pressure measurement` (Response Payload) are **named ARFF
columns**, and that MSCI (specific 13–17) + MPCI (specific 1–12) attacks — ~47% of
labelled attack rows — manipulate exactly these fields. Assessed for promotion to
Tier 1. **Recommendation: do not promote; they stay excluded (`02-feature-schema.md`).**
Reasons:
1. **Filtered-out direction.** The 10 command-payload fields are populated on
   *command* frames (`command response == 1`); the egress/diode filter keeps
   `command response == 0` (responses). Post-filter they are ~empty. Only
   `pressure measurement` survives (still 74.9% missing overall).
2. **Destroys the stated novelty.** `04_DATASET_PLAN.md` §Novelty commits to *dropping*
   the process-variable columns and detecting compromise "from behavioural egress
   features alone". Feeding `pump`/`system_mode`/`pressure` back in makes this
   another process-variable IDS on this dataset — the exact prior-work framing the
   project differentiates from.
3. **Breaks the diode-observer abstraction.** A low-side diode observer sees a
   byte/packet stream, not pre-decoded PID setpoints and actuator states.
4. **Trivial separability / artifact risk.** "Randomly changes the pump state"
   detected by reading the pump state is circular; limitation 6 + artifact-audit
   check 4 exist to reject exactly this. Near-perfect separation here would be a bug,
   not a result.
5. The pre-registered attack table already scores MPCI/MSCI as **PARTIAL** for Tier 1
   — the honest position; promotion would inflate it via a disallowed mechanism.

`pressure measurement` *could* be revisited as a **Tier 3 documented-only** item if
the diode-observer abstraction were deliberately relaxed. Not for the MVP.
