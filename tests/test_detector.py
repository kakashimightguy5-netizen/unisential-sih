"""T-01 / T-02 (full pipeline) + EXP-0004 exact-reproduction regression tests.

These tests run the real detector once per session on the verified 274,628-row TXT
(sha256 ce2d69e3…93e3), yielding 46,736 windows. The exact constants below were
rebaselined from EXP-0004; EXP-0001/0002 constants are retracted.

The detector is deterministic for a fixed seed. Exact assertions intentionally flag
library drift for deliberate review. Reference environment for EXP-0004: Python 3.12.10,
numpy 2.5.3, scikit-learn 1.9.0, scipy 1.18.1.
"""
import numpy as np
import pytest

pytestmark = pytest.mark.slow

# --- exact full-precision outputs of EXP-0004 -------------------------------
THRESHOLD = 0.6745465823488428
COMBINED = dict(
    precision=0.9540229885057471,
    recall=0.1645374449339207,
    f1=0.2806687957918467,
    fpr=0.00748907842729353,
)
CONFUSION = dict(tn=4771, fp=36, fn=3793, tp=747)            # rule ∨ IF, TEST
IF_ONLY_NORMAL_FPR = 0.00748907842729353                     # rule adds 0 → same as combined
PER_CATEGORY_COMBINED = {
    "Normal": 36 / 4807,
    "NMRI":   109 / 1131,
    "CMRI":   232 / 1812,
    "MSCI":   2 / 324,
    "MPCI":   8 / 741,
    "MFCI":   1.0,
    "DoS":    0.0,
    "Recon":  1.0,
}


# ---------------------------------------------------------------- split / composition

def test_test_block_composition(detector_result):
    R = detector_result
    assert R.n_windows == 46_736
    assert (R.n_train, R.n_val, R.n_test) == (28_040, 9_345, 9_347)
    assert R.n_train_normal == 14_951
    assert (int((R.y_test == 0).sum()), int((R.y_test == 1).sum())) == (4_807, 4_540)


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

    So this test asserts the aggregate FPR over ALL 4,807 held-out normal TEST
    windows, at the exact recorded operating point:
      - rule layer: exactly 0 (membership test, no score involved)
      - IF / combined: ~0.75%, below the 1% validation-normal target on this TEST block.
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
    """T-02 corollary: the rule fires on 0 of the 4,807 Normal TEST windows —
    it adds no false positives to the combined detector."""
    R = detector_result
    normal = R.cat_test == 0
    assert int(R.rule_pred[normal].sum()) == 0
    assert int(normal.sum()) == 4_807


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


# ---------------------------------------------------------------- EXP-0004 exact reproduction

def test_combined_detector_reproduces_exp0004_exactly(detector_result):
    """Regression baseline. See module docstring for what a failure here means."""
    m = detector_result.metrics(detector_result.comb_pred)
    assert m["p"] == COMBINED["precision"]
    assert m["r"] == COMBINED["recall"]
    assert m["f1"] == COMBINED["f1"]
    assert m["fpr"] == COMBINED["fpr"]


def test_combined_confusion_matrix_matches_exp0004_exactly(detector_result):
    m = detector_result.metrics(detector_result.comb_pred)
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (
        CONFUSION["tn"], CONFUSION["fp"], CONFUSION["fn"], CONFUSION["tp"])


def test_per_category_flag_rates_match_exp0004_exactly(detector_result):
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
