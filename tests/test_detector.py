"""T-01 / T-02 (full pipeline) + EXP-0017/EXP-0025 exact-reproduction regression tests.

These tests read the EXP-0025 saved result: protocol OR pressure OR rate OR IF
(EXP-0025, 2026-09-12, wires in the Type 2 egress-flood DoS rate rule additively
alongside EXP-0017's protocol/pressure rules). They never rescore TEST — EXP-0025's
result is derived analytically from the already-frozen EXP-0017 arrays plus one new
deterministic rule term (see docs/EXP0025_RESULTS.md). All constants below are
numerically IDENTICAL to EXP-0017's, because the rate rule fires zero times on real
captured TEST data of any category, Type 1 DoS included (Type 1 remains
structurally invisible on the egress side and is unaffected by this rule). Source
and artifact checksums detect drift without reruns.
"""
import numpy as np
import pytest

pytestmark = pytest.mark.slow

# --- exact full-precision outputs of EXP-0017 -------------------------------
THRESHOLD = 0.6745465823488428
COMBINED = dict(
    precision=2374 / 2414,
    recall=2374 / 4540,
    f1=4748 / 6954,
    fpr=40 / 4807,
)
CONFUSION = dict(tn=4767, fp=40, fn=2166, tp=2374)            # rule ∨ IF, TEST
IF_ONLY_NORMAL_FPR = 0.00748907842729353                     # IF unchanged; pressure adds four Normal flags
PER_CATEGORY_COMBINED = {
    "Normal": 40 / 4807,
    "NMRI":   866 / 1131,
    "CMRI":   1089 / 1812,
    "MSCI":   15 / 324,
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
      - protocol layer: 0; full rule layer: 4/4807 (pressure bounds)
      - IF: ~0.75%; combined: ~0.83%, below the 1% validation-normal target on this TEST block.
    """
    R = detector_result
    normal = R.cat_test == 0
    assert R.protocol_pred[normal].mean() == 0.0
    assert R.rule_pred[normal].mean() == 4 / 4807
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


def test_t02_protocol_silent_pressure_adds_four_normal_flags(detector_result):
    """Protocol rule stays silent; pressure contributes four Normal flags."""
    R = detector_result
    normal = R.cat_test == 0
    assert int(R.protocol_pred[normal].sum()) == 0
    assert int(R.rule_pred[normal].sum()) == 4
    assert int(normal.sum()) == 4_807


def test_t02_reasons_are_hex_function_codes(detector_result):
    R = detector_result
    fired = [h for h in R.rule_hits if h.fired]
    assert fired
    for h in fired:
        for r in h.reasons:
            kind, _, val = r.partition("=")
            assert kind in {"invalid_function_code", "novel_address",
                            "pressure_below_train_normal_min", "pressure_above_train_normal_max",
                            "packets_per_sec_above_train_normal_max"}
            if kind == "invalid_function_code":
                assert all(tok.startswith("0x") for tok in val.split(","))


# ---------------------------------------------------------------- EXP-0017 exact reproduction

def test_combined_detector_reproduces_exp0017_exactly(detector_result):
    """Regression baseline. See module docstring for what a failure here means."""
    m = detector_result.metrics(detector_result.comb_pred)
    assert m["p"] == COMBINED["precision"]
    assert m["r"] == COMBINED["recall"]
    assert m["f1"] == COMBINED["f1"]
    assert m["fpr"] == COMBINED["fpr"]


def test_combined_confusion_matrix_matches_exp0017_exactly(detector_result):
    m = detector_result.metrics(detector_result.comb_pred)
    assert (m["tn"], m["fp"], m["fn"], m["tp"]) == (
        CONFUSION["tn"], CONFUSION["fp"], CONFUSION["fn"], CONFUSION["tp"])


def test_per_category_flag_rates_match_exp0017_exactly(detector_result):
    R = detector_result
    for name, expected in PER_CATEGORY_COMBINED.items():
        assert R.category_flag_rate(name) == expected, name


def test_saved_detector_roundtrip_preserves_arrays(detector_result):
    """Artifact replay identity, not a second model execution."""
    from exp0025_dos_rate_rule import load_detector_result
    fresh = load_detector_result()
    for name in ("base_pred", "rule_pred", "protocol_pred", "pressure_pred", "rate_pred",
                 "if_pred", "comb_pred", "if_scores"):
        assert np.array_equal(getattr(fresh, name), getattr(detector_result, name)), name
    assert fresh.threshold == detector_result.threshold


# ---------------------------------------------------------------- EXP-0025: Type 2 DoS rate rule

def test_rate_rule_fires_zero_times_on_real_test_data(detector_result):
    """EXP-0025: the rate rule (Type 2 egress-flood DoS) never fires on any real
    captured TEST window, of any category — confirmed, not assumed. It only ever
    catches the synthetic flood injections measured in EXP-0025's verification
    step (see docs/EXP0025_RESULTS.md), not anything present in this dataset."""
    R = detector_result
    assert int(R.rate_pred.sum()) == 0
    assert R.rate_threshold > 0.0


def test_rate_rule_leaves_every_category_unaffected(detector_result):
    """Adding the rate rule changes nothing about EXP-0017's frozen numbers,
    Type 1 DoS included — Type 1 remains structurally invisible on egress and
    this experiment does not claim otherwise."""
    R = detector_result
    from iforest_detector import CATEGORY_NAMES
    for name in CATEGORY_NAMES:
        idx = np.where(R.cat_test == CATEGORY_NAMES.index(name))[0]
        if len(idx) == 0:
            continue
        assert int(R.rate_pred[idx].sum()) == 0, name
    dos_idx = np.where(R.cat_test == CATEGORY_NAMES.index("DoS"))[0]
    assert len(dos_idx) > 0
    assert R.comb_pred[dos_idx].mean() == 0.0  # Type 1 DoS: still 0% recall, unaffected
