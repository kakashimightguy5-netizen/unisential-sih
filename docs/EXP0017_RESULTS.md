# EXP-0017 operational baseline - VALIDATED

One guarded evaluation of `ml/iforest_detector.run_detector`, with PressureBoundsRule permanently included. EXP-0004 is superseded by EXP-0017, retained for historical comparison. Original EXP-0004 log entries and saved historical artifacts are unchanged.

**Pressure uses ARFF 'pressure measurement' row-aligned to TXT canonical 0x03 responses, NOT live packet-byte decoding. Register map/scale is undocumented; bounds are empirical TRAIN-normal extrema. Offline simulated data-diode view; one testbed.**

## Actual production output

| Metric | EXP-0017 |
|---|---:|
| TN | 4767 |
| FP | 40 |
| FN | 2166 |
| TP | 2374 |
| Precision | 0.9834299917149959 |
| Recall | 0.5229074889867842 |
| F1 | 0.6827725050330745 |
| Normal FPR | 0.008321198252548368 |

Threshold: `0.6745465823488428`. TRAIN-normal pressure extrema: `[0.482759, 38.7471]`.
Windows: 46736; TRAIN / VALIDATION / TEST: 28040 / 9345 / 9347; TRAIN-normal: 14951.

## Actual per-category output - VALIDATED

Dominant category follows the existing minimum nonzero category-code convention. Pure permits Normal frames plus only the named attack. Containing includes mixed-attack windows; these rows overlap and do not establish detection of the named attack itself. Normal is the false-positive rate.

| Category | Cohort | Windows | Combined flags | Rate | Protocol flags | IF flags | Pressure flags |
|---|---|---:|---:|---:|---:|---:|---:|
| Normal | dominant | 4807 | 40 | 0.832120% | 0 | 36 | 4 |
| NMRI | dominant | 1131 | 866 | 76.569408% | 93 | 85 | 853 |
| NMRI | pure | 715 | 565 | 79.020979% | 0 | 8 | 565 |
| NMRI | containing | 1131 | 866 | 76.569408% | 93 | 85 | 853 |
| CMRI | dominant | 1812 | 1089 | 60.099338% | 201 | 137 | 968 |
| CMRI | pure | 1198 | 654 | 54.590985% | 0 | 28 | 643 |
| CMRI | containing | 1826 | 1099 | 60.186199% | 201 | 137 | 978 |
| MSCI | dominant | 324 | 15 | 4.629630% | 0 | 2 | 13 |
| MSCI | pure | 322 | 15 | 4.658385% | 0 | 2 | 13 |
| MSCI | containing | 462 | 81 | 17.532468% | 0 | 2 | 79 |
| MPCI | dominant | 741 | 8 | 1.079622% | 1 | 7 | 0 |
| MPCI | pure | 739 | 7 | 0.947226% | 0 | 7 | 0 |
| MPCI | containing | 1280 | 345 | 26.953125% | 2 | 18 | 330 |
| MFCI | dominant | 227 | 227 | 100.000000% | 227 | 156 | 0 |
| MFCI | pure | 227 | 227 | 100.000000% | 227 | 156 | 0 |
| MFCI | containing | 446 | 446 | 100.000000% | 446 | 289 | 141 |
| DoS | dominant | 136 | 0 | 0.000000% | 0 | 0 | 0 |
| DoS | pure | 136 | 0 | 0.000000% | 0 | 0 | 0 |
| DoS | containing | 193 | 36 | 18.652850% | 0 | 0 | 36 |
| Recon | dominant | 169 | 169 | 100.000000% | 169 | 109 | 0 |
| Recon | pure | 169 | 169 | 100.000000% | 169 | 109 | 0 |
| Recon | containing | 245 | 245 | 100.000000% | 245 | 151 | 36 |

## Identity and reproduction

All seven pre-registered gates passed: exact threshold, exact bounds, historical component confusion, operational confusion, element-wise OR composition, pressure explanations, and identity with every saved EXP-0016 comparison cohort.

Historical confusion is computed from protocol and IF component predictions of this same evaluation, not a second model run. No saved historical IF score vector exists for an independent element-wise old/new score comparison; none is claimed.

Split: `verified-egress-5s-exp0008-pretest-v1`; membership SHA256 `0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6`. Membership comes from the checksummed manifest, never capture-length fractions. TEST follows the final manifest VALIDATION bucket, excluding the next two eligible guard buckets.

Python 3.12.10; packages: `{'numpy': '2.5.3', 'scipy': '1.18.1', 'scikit-learn': '1.9.0'}`.

Full measured summary and source/raw identity hashes: [exp0017_results.json](exp0017_results.json). All predictions, window features, rule reasons and baseline statistics: [saved evaluation](../data/experiments/exp0017_detector.json). Single-attempt ledger: [ledger](../data/experiments/exp0017_test_attempt.json). The JSON envelope includes a SHA256 integrity checksum. It contains no executable pickle, model weights, or raw packet bytes.

The saved evaluation is local and currently ignored by the repository data rule. It must be included explicitly in any later approved commit/package for dashboard and regression replay; no commit or staging was performed.

## Usage - IMPLEMENTED

`python ml/exp0017_operational.py` prints the saved summary; `python ml/iforest_detector.py` does the same. `streamlit run app.py` reads the saved evaluation. Missing, altered, failed, or source-mismatched artifacts fail closed. The dashboard does not train or score TEST.

The one authorized command was `python ml/exp0017_operational.py --score-frozen-test --confirm SCORE-EXP-0017-FROZEN-TEST-ONCE`. Do not repeat it: the exclusive attempt ledger prevents another attempt, including after a failed run. Default `run_detector()` now refuses unconfirmed scoring. Historical experiment entry points are retained as historical code; the test harness replays their artifacts rather than calling them.

## Scope and limitations

Only the operational detector, replay/guard module, dependent tests/dashboard and baseline documentation changed. Protected EXP-0005 through EXP-0013 and Layer A files remain untouched. Their synthetic unit tests still execute; four historical integration tests replay saved JSON summaries and are not fresh experimental validation.

Pressure-only in-range forgeries can be missed. The dominant/pure DoS cohort still has zero flags; mixed containing-cohort flags are not evidence of DoS detection. No physical deployment, PCAP pressure decoder, broad ICS generalization, or retraining/model-choice improvement is claimed.

## Test execution - TESTED

| Execution record | Passed | Skipped | Failures | Setup errors |
|---|---:|---:|---:|---:|
| [exp0017_before_tests.xml](exp0017_before_tests.xml) | 124 | 12 | 0 | 2 |
| [exp0017_before_tests_retry.xml](exp0017_before_tests_retry.xml) | 126 | 12 | 0 | 0 |
| [exp0017_pretest_checks.xml](exp0017_pretest_checks.xml) | 5 | 3 | 0 | 0 |
| [exp0017_pretest_checks_final.xml](exp0017_pretest_checks_final.xml) | 6 | 3 | 0 | 0 |
| [exp0017_after_tests.xml](exp0017_after_tests.xml) | 147 | 0 | 0 | 0 |

The initial before run encountered two pytest temporary-directory permission errors;
the authorized environment retry passed. The exact safe before/after counts are
126 passed / 12 skipped and 147 passed / 0 skipped. The 12 missing-array tests
became saved-output regressions; 9 EXP-0017 tests were added. Four historical
integration tests replay saved JSON summaries in both suites. All 2,414 saved alerts
have tested explanations, and the Streamlit app passed with raw capture reads blocked.
No real TEST scoring was performed by pytest. Later edits were documentation and
one stale test comment only; the evaluated detector source bytes remain unchanged.

## Review artifacts

[Full diff, including saved output and execution records](exp0017_full.diff).
[Code and documentation diff](exp0017_code.diff) excludes the large saved JSON and
XML execution records for easier reading. Neither diff contains itself or the other
review diff. The saved evaluation currently lives under the ignored data directory;
include it and the consumed-attempt ledger explicitly in a later approved commit or
package. Strict source-byte identity includes line endings: preserve the recorded
source bytes together with the saved result. No staging, commit, or push performed.
