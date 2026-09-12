# EXP-0025 — Wire the Type 2 (egress-channel flood) DoS rate rule into the operational detector

**Status: VALIDATED.** Wires a THIRD deterministic rule (`rules.RateFloodRule`)
into the operational detector, additive alongside the existing protocol and
pressure rules. `DeterministicRuleLayer` and `PressureBoundsRule` are unchanged.

## Scope statement — read this first

**This targets Type 2 (egress-channel/diode-termination) DoS only: an insider or
compromised device flooding the OUTBOUND channel itself.** It does **not**
address Type 1 (external inbound-flood) DoS, which remains at **0% recall** and
is a separate, structurally different problem — the flood lives entirely in the
inbound command direction and a diode already blocks it from the egress view
(`ml/features_windowed.py` module docstring; EXP-0003/0013). **This must not be
reported or cited as "DoS solved."**

## Step 1 — re-verifying EXP-0010's finding under the current state

EXP-0010 (2026-09-09) measured 100% detection of synthetic egress-flood
injections at severities 2x-20x against the (then-current) combined detector,
and separately *noted but never built or scored* a standalone
`packets_per_sec > TRAIN-normal max` rule as a "minimal fix" idea. This
experiment re-derives that threshold fresh from the CURRENT TRAIN-normal data
and measures the rate rule's OWN standalone performance (not previously
measured) against EXP-0010's exact synthetic-injection methodology, reused
directly from `ml/exp0010_egress_flood.py`.

- **Threshold**: 0.8 packets/sec (TRAIN-normal max over 14,951 windows) — matches
  EXP-0010's cited value exactly; the split/window construction has not changed.
- **Standalone rate-rule dose-response** (profiles A_distinct / B_duplicate
  identical; both reused unmodified from EXP-0010):

| severity | flagged / 4,807 | recall | FP (real Normal TEST) |
|---|---|---|---|
| 1x (no injection, sanity anchor) | 0 | 0.00% | 0 |
| 2x | 4,563 | 94.92% | 0 |
| 5x | 4,807 | 100.00% | 0 |
| 10x | 4,807 | 100.00% | 0 |
| 20x | 4,807 | 100.00% | 0 |

**Honest correction to EXP-0010's informal note:** EXP-0010's "fix note" implied
every ≥2x flood clears the TRAIN-normal max; measured directly, that is not
quite true — 244/4,807 windows (5.08%) at exactly 2x fall at or just below the
threshold due to integer frame-count rounding on already-low-rate windows (a
2-frame window doubled is exactly 4 frames/5s = 0.8 pps, tied with, not above,
the threshold). This was never actually measured in EXP-0010 (only asserted
informally); recall reaches 100% at ≥5x and there are zero false positives at
every severity. This nuance is disclosed here rather than silently re-citing the
old "100% at all severities 2x-20x" framing.

## Step 2 — building `RateFloodRule`

`ml/rules.py`: new additive class `RateFloodRule` (`fit`/`evaluate`/`predict`,
`RuleHit` reasons), same style as `PressureBoundsRule` — single upper-bound
membership test, threshold frozen from TRAIN-normal only.

## Step 3/4 — wiring and the new combined TEST result

`ml/iforest_detector.run_detector()` is edited to fit and evaluate
`RateFloodRule` alongside the protocol and pressure rules permanently, for any
future fresh run (`rule_pred = protocol OR pressure OR rate`; `comb_pred = rule
OR IF`). `DetectorResult` gains `rate_pred`/`rate_threshold` fields.

**TEST is not scored a second time.** EXP-0017 already consumed the one guarded
TEST-scoring event; its `if_pred`/`if_scores`/`mu`/`sd`/`threshold` are frozen and
were not recomputed. The new combined TEST confusion is derived analytically:
`rate_pred` is a closed-form function of (a) the TRAIN-normal `packets_per_sec`
threshold (TRAIN-only, unlimited reads) and (b) each TEST window's already-
recorded `packets_per_sec` feature (already saved in EXP-0017's `test_windows`,
not a new read of raw TEST data). This is checked, not merely asserted: the
derivation script verifies the current manifest split matches EXP-0017's frozen
split identity before proceeding.

### Identity-gate note on a frozen artifact

Editing `ml/rules.py` and `ml/iforest_detector.py` changed their SHA-256, which
`exp0017_detector.json`'s own checksummed identity gate pins — and ACK-001,
ACK-002, and EXP-0021/0022/0023 all depend on `exp0017_operational.load_result()`
succeeding. **With the user's explicit approval**, the `identity.source_sha256`
entries for those two files inside the existing `exp0017_detector.json` envelope
were refreshed to their new hashes (envelope checksum recomputed); the frozen
`result` payload (every prediction array, `mu`/`sd`/`threshold`, etc.) was **not**
touched — only the "what source currently produces this" ledger. This was
verified by reloading `exp0017_operational.load_result()` successfully
afterward and confirming the full test suite (ACK-001/002, EXP-0021/22/23)
still passes unchanged.

### New overall confusion matrix

| | value |
|---|---|
| TN | 4,767 |
| FP | 40 |
| FN | 2,166 |
| TP | 2,374 |
| Precision | 98.34% |
| Recall | 52.29% |
| F1 | 68.28% |
| FPR | 0.83% |

**Numerically identical to EXP-0017's frozen confusion.** This is the honest,
verified result of step 6 below — not an oversight.

### Per-category table

| category | n | flagged | rate | protocol | pressure | **rate** | IF |
|---|---|---|---|---|---|---|---|
| Normal | 4,807 | 40 | 0.83% | 0 | 4 | **0** | 36 |
| NMRI | 1,131 | 866 | 76.57% | 93 | 853 | **0** | 85 |
| CMRI | 1,812 | 1,089 | 60.10% | 201 | 968 | **0** | 137 |
| MSCI | 324 | 15 | 4.63% | 0 | 13 | **0** | 2 |
| MPCI | 741 | 8 | 1.08% | 1 | 0 | **0** | 7 |
| MFCI | 227 | 227 | 100.00% | 227 | 0 | **0** | 156 |
| DoS | 136 | 0 | **0.00%** | 0 | 0 | **0** | 0 |
| Recon | 169 | 169 | 100.00% | 169 | 0 | **0** | 109 |

## Step 6 — honest reporting (verified, not assumed)

- **`rate_flags` is exactly 0 for every one of the 4,807+4,540 = 9,347 real TEST
  windows, in every category, DoS included.** Confirmed by direct computation,
  not assumed from the "should be" expectation in the pre-registration.
- **Type 1 DoS is completely unaffected**: 136 DoS-labeled TEST windows, 0 rate
  flags, 0% combined recall — identical to EXP-0017. This is the pre-registered
  expectation, verified true.
- **No other category's flag rate changed** — every category's flagged count is
  byte-identical before/after (see per-category table; all deltas are 0).
- **Normal FPR does not regress**: 40/4,807 = 0.832%, unchanged. Zero new false
  positives from the rate rule.
- **Why zero effect on real data**: this dataset contains no real captured Type 2
  (egress-channel) flood example — the rate rule's 100%-at-≥5x/0-FP result (step
  1) is entirely against *synthetic* injections. On real captured TEST data, no
  window of any category — attack or Normal — ever exceeds the TRAIN-normal
  `packets_per_sec` maximum. The rule is correctly built and wired in for a
  threat type this dataset does not contain, not silently broken.

## Dashboard / documentation update (step 7)

`app.py`: now loads `exp0025_dos_rate_rule.load_detector_result()`, title/caption
updated to EXP-0025, `CAVEAT` mentions `RateFloodRule`, and a new
`DOS_SCOPE_NOTE` states explicitly what the rule does and does not cover (Type 2
only; Type 1 unaffected; no real Type 2 example in this dataset). The naive-
baseline-vs-combined table label is updated to "Protocol OR pressure OR rate OR
IF" and its caption explains the identical-to-EXP-0017 numbers.

## Tests

`tests/test_exp0025_dos_rate_rule.py`: 10 fast synthetic units (`RateFloodRule`
fit/evaluate/guards/predict, existing-rule regression, three-rule OR
composition, static-analysis scope checks) + 2 `@pytest.mark.slow` saved-result
replay tests (zero rate flags on real TEST, identical frozen confusion, Type 1
DoS unaffected, dose-response sanity). `tests/test_detector.py`: fixture now
loads the EXP-0025 result; added `test_rate_rule_fires_zero_times_on_real_test_data`
and `test_rate_rule_leaves_every_category_unaffected`; updated the
reasons-format check and roundtrip test to include `rate_pred`.
`tests/test_exp0017_operational.py::test_dashboard_uses_saved_result_with_pressure_limitation`
updated to expect "EXP-0025" in the dashboard title (app.py step 7 change), with
a note explaining the numbers stay identical to EXP-0017's. All EXP-0017-era
regression constants are unchanged (numerically identical result). Full suite:
**263 → 275 passed** (12 new: 10 in test_exp0025 + 2 in test_detector; 1
existing test updated for the title change).

## Files

New: `ml/exp0025_dos_rate_rule.py`, `tests/test_exp0025_dos_rate_rule.py`,
`data/experiments/exp0025_detector.json`, this file. Modified (additive only):
`ml/rules.py` (+`RateFloodRule`), `ml/iforest_detector.py` (`run_detector`/
`DetectorResult`, docstring), `tests/test_detector.py`, `tests/conftest.py`
(fixture source), `tests/test_exp0017_operational.py` (dashboard title
assertion), `app.py`. Also modified: `data/experiments/exp0017_detector.json`
— only its `identity.source_sha256` ledger entries for `ml/rules.py` and
`ml/iforest_detector.py` (see identity-gate note above); the frozen `result`
payload is byte-for-byte unchanged, confirmed by successful reload and full
suite pass. DoS Type 1's invalidated files, MSCI/MPCI's closed files, Layer A,
and CMRI's closed files are unchanged.

## Limitations / honest disclosure

- `RateFloodRule`'s 100%-at-≥5x / 0-FP result is against *synthetic* injections
  only (EXP-0010's methodology, reused unmodified) — this dataset contains no
  real captured Type 2 flood example, so its real-world performance against an
  actual Type 2 attack is unverified, only plausible by construction (any
  volumetric flood pushes `packets_per_sec` far above any legitimate polling
  rate observed in TRAIN).
- The 2x-severity standalone recall (94.92%, not 100%) is a genuine, previously
  unmeasured boundary effect from integer frame-count rounding on already-low-
  rate windows, disclosed above rather than silently matched to EXP-0010's
  informal (and, it turns out, imprecise) note.
- The EXP-0017 frozen artifact's identity ledger was edited (with explicit user
  approval) to reflect the legitimate additive source change; this is disclosed
  prominently rather than left as a silent workaround, and was verified to leave
  the underlying scored arrays and every dependent closed experiment's tests
  unchanged.
- This experiment does not attempt to detect Type 1 DoS by any means; that
  remains a separate, unsolved, structurally invisible problem on egress-only
  data.
