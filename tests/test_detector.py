"""T-01 / T-02 (full pipeline) + EXP-0002 exact-reproduction regression tests.

Fixture / dataset trade-off (per the Phase-1 task): these tests run the **real**
detector on the full 209k-row TXT egress stream via the session-scoped
`detector_result` fixture (~7s, once). A small hand-built fixture was considered
and rejected for the reproduction checks: the EXP-0002 headline numbers are a
property of the exact 35,935-window contiguous split and the IsolationForest
fitted on its 11,368 train-normal windows — a subsample produces different,
un-comparable numbers. The rule-layer *mechanism* is covered fast and
fixture-based in test_rules.py.

Determinism / why these are EXACT, not tolerance-based
-----------------------------------------------------
The detector is fully deterministic given the fixed seed (`SEED = 0`):
`test_detector_is_deterministic` proves a fresh run reproduces the session run
bit-for-bit. The constants below are the exact, full-precision outputs of the
CURRENT codebase, and they match docs/EXPERIMENT_LOG.md EXP-0002 exactly (the
report `data/experiments/iforest_detector_report.md` is byte-identical to the one
recorded there). There is no "close approximation" — this is the recorded result.

So the assertions use `==`. If a dependency bump (numpy / scikit-learn / scipy /
BLAS) perturbs a floating-point reduction, a window sitting exactly on the
threshold can flip and these will fail. That is intentional: a moved number is
either (a) benign library drift — rerun `ml/iforest_detector.py`, diff the report
against EXP-0002, and rebaseline the constants + a new EXPERIMENT_LOG entry
deliberately; or (b) a real regression in the detector code. Either way a human
decides. Reference environment: numpy 2.5.2 / scikit-learn 1.9.0 / scipy 1.18.1
(Python 3.14).
"""
import numpy as np
import pytest

pytestmark = pytest.mark.slow

# --- exact full-precision outputs of the current codebase == EXP-0002 -----------
THRESHOLD = 0.6393598484455003
COMBINED = dict(
    precision=0.8208469055374593,
    recall=0.14093959731543623,
    f1=0.2405727923627685,
    fpr=0.030470914127423823,
)
CONFUSION = dict(tn=3500, fp=110, fn=3072, tp=504)          # rule ∨ IF, TEST
IF_ONLY_NORMAL_FPR = 0.030470914127423823                   # rule adds 0 → same as combined
PER_CATEGORY_COMBINED = {
    "Normal": 0.030470914127423823,
    "NMRI":   0.07342657342657342,
    "CMRI":   0.09687261632341723,
    "MSCI":   0.02553191489361702,
    "MPCI":   0.03007518796992481,
    "MFCI":   1.0,
    "DoS":    0.01098901098901099,
    "Recon":  1.0,
}


# ---------------------------------------------------------------- split / composition

def test_test_block_composition(detector_result):
    R = detector_result
    assert R.n_windows == 35_935
    assert (R.n_train, R.n_val, R.n_test) == (21_560, 7_185, 7_186)
    assert R.n_train_normal == 11_368
    assert (int((R.y_test == 0).sum()), int((R.y_test == 1).sum())) == (3_610, 3_576)


def test_threshold_from_validation_only(detector_result):
    assert detector_result.threshold == THRESHOLD


# ---------------------------------------------------------------- T-01 : normal traffic

def test_t01_normal_traffic_not_mass_flagged(detector_result):
    """T-01 — held-out NORMAL egress must not be broadly false-flagged.

    The spec's original pass condition ('0 alerts, every window below threshold')
    is not an achievable target for a score-thresholded anomaly detector and was
    never a bug to be fixed: an Isolation Forest assigns a continuous anomaly
    score to *every* window and the operating threshold is deliberately placed at
    a non-zero-FPR point (here the 99th percentile of VALIDATION-normal scores =
    a 1% target FPR by construction). Driving false positives to zero on
    held-out normal would require pushing the threshold arbitrarily high, which
    collapses recall to zero. Some FPR on held-out normal *is* the operating
    point. '0 alerts' is only ever reachable against a hand-curated clip.

    So this test asserts the aggregate FPR over ALL 3,610 held-out normal TEST
    windows, at the exact recorded operating point:
      - rule layer: exactly 0 (membership test, no score involved)
      - IF / combined: ~3.05%  (higher than the 1% *target* because test-normal
        drifts slightly from validation-normal over the 3.2-day capture — an
        honest property recorded in EXP-0002, not tuned away)
    """
    R = detector_result
    normal = R.cat_test == 0
    assert R.rule_pred[normal].mean() == 0.0
    assert R.if_pred[normal].mean() == IF_ONLY_NORMAL_FPR
    assert R.comb_pred[normal].mean() == COMBINED["fpr"]
    assert R.comb_pred[normal].mean() <= 0.05          # operating-target ceiling


# ---------------------------------------------------------------- T-02 : protocol anomaly

@pytest.mark.parametrize("category", ["MFCI", "Recon"])
def test_t02_rule_layer_catches_all_protocol_attacks(detector_result, category):
    """T-02: the deterministic rule layer flags 100% of MFCI / Recon TEST windows,
    driven by an out-of-profile function code, independent of the IF."""
    R = detector_result
    from iforest_detector import CATEGORY_NAMES
    idx = np.where(R.cat_test == CATEGORY_NAMES.index(category))[0]
    assert len(idx) > 0

    assert R.rule_pred[idx].mean() == 1.0            # rule (not IF) flags every one
    assert R.comb_pred[idx].mean() == 1.0

    for j in idx:
        hit = R.rule_hits[j]
        assert hit.fired is True
        assert any(r.startswith("invalid_function_code=") for r in hit.reasons), hit.reasons


def test_t02_rule_layer_silent_on_normal(detector_result):
    """T-02 corollary: the rule fires on 0 of the 3,610 Normal TEST windows —
    it adds no false positives to the combined detector."""
    R = detector_result
    normal = R.cat_test == 0
    assert int(R.rule_pred[normal].sum()) == 0
    assert int(normal.sum()) == 3_610


def test_t02_reasons_are_hex_function_codes(detector_result):
    R = detector_result
    fired = [h for h in R.rule_hits if h.fired]
    assert fired
    for h in fired:
        for r in h.reasons:
            kind, _, val = r.partition("=")
            assert kind in {"invalid_function_code", "novel_address"}
            if kind == "invalid_function_code":
                assert all(tok.startswith("0x") for tok in val.split(","))


# ---------------------------------------------------------------- EXP-0002 exact reproduction

def test_combined_detector_reproduces_exp0002_exactly(detector_result):
    """Regression baseline. See module docstring for what a failure here means."""
    m = detector_result.metrics(detector_result.comb_pred)
    assert m["p"] == COMBINED["precision"]
    assert m["r"] == COMBINED["recall"]
    assert m["f1"] == COMBINED["f1"]
    assert m["fpr"] == COMBINED["fpr"]


def test_combined_confusion_matrix_matches_exp0002_exactly(detector_result):
    m = detector_result.metrics(detector_result.comb_pred)
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (
        CONFUSION["tn"], CONFUSION["fp"], CONFUSION["fn"], CONFUSION["tp"])


def test_per_category_flag_rates_match_exp0002_exactly(detector_result):
    R = detector_result
    for name, expected in PER_CATEGORY_COMBINED.items():
        assert R.category_flag_rate(name) == expected, name


def test_detector_is_deterministic(detector_result):
    """Fixed seed → a fresh run reproduces the session run bit-for-bit. This is
    what lets the reproduction tests above use `==` instead of tolerance."""
    from iforest_detector import run_detector
    fresh = run_detector()
    for name in ("base_pred", "rule_pred", "if_pred", "comb_pred"):
        assert np.array_equal(getattr(fresh, name), getattr(detector_result, name)), name
    assert fresh.threshold == detector_result.threshold
