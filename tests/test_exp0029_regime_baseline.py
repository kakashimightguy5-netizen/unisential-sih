"""EXP-0029: synthetic units for the causal rolling median/MAD z-score, the
per-window max-|z| aggregation, the diagnostic effect-size calculation and the
artifact-gating logic, plus one slow saved-result replay (no raw-data read).

`ml/iforest_detector.run_detector` is measurement-only here: a source check
asserts this module never imports or calls it.
"""
import ast
import inspect
import json
from pathlib import Path

import numpy as np
import pytest

import exp0029_regime_baseline as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0029_regime_baseline.json"


# ------------------------------------------------------- causal_z_scores

def test_causal_z_scores_undefined_before_k_samples():
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    z = exp.causal_z_scores(values, k=3)
    assert np.all(np.isnan(z[:3]))
    assert np.all(np.isfinite(z[3:]))


def test_causal_z_scores_never_uses_current_or_future_sample():
    # A huge spike at index 5 must not perturb the (median, MAD) computed for
    # its own z_t (causal: window is values[t-k:t], strictly before t).
    values = [10.0, 10.0, 10.0, 10.0, 10.0, 1000.0, 10.0, 10.0]
    z = exp.causal_z_scores(values, k=3)
    # z at t=5 (the spike itself) should be huge relative to a stable window of 10s
    assert z[5] > 100
    # z at t=6 (right after the spike) reflects the spike now being IN the window
    # -- median of [10,10,1000] is 10, MAD is 0, so it's not degenerate/negative;
    # just confirm it's finite and doesn't crash on window mixing.
    assert np.isfinite(z[6])


def test_causal_z_scores_matches_hand_computed_value():
    values = [1.0, 2.0, 3.0, 100.0]
    z = exp.causal_z_scores(values, k=3, epsilon=1e-6)
    # window for t=3 is [1,2,3]; median=2, mad=median(|1-2|,|2-2|,|3-2|)=1
    expected = (100.0 - 2.0) / (1.0 + 1e-6)
    assert z[3] == pytest.approx(expected, rel=1e-6)


def test_causal_z_scores_handles_zero_mad_via_epsilon():
    values = [5.0, 5.0, 5.0, 9.0]
    z = exp.causal_z_scores(values, k=3, epsilon=1e-6)
    # window [5,5,5]: median=5, mad=0 -> denominator is just epsilon
    expected = (9.0 - 5.0) / (0.0 + 1e-6)
    assert z[3] == pytest.approx(expected, rel=1e-3)


# ------------------------------------------------------- window_max_abs_z

def test_window_max_abs_z_takes_max_magnitude_per_bucket():
    # bucket_of uses WINDOW_SECONDS=5.0 floor division
    z = np.array([1.0, -5.0, 2.0, np.nan])
    times = [0.0, 1.0, 6.0, 7.0]
    out = exp.window_max_abs_z(z, times)
    assert out[0] == pytest.approx(5.0)     # bucket 0 gets max(|1|, |-5|)
    assert out[1] == pytest.approx(2.0)     # bucket 1's only finite sample is 2.0


def test_window_max_abs_z_bucket_with_only_nan_is_absent():
    z = np.array([1.0, np.nan])
    times = [0.0, 6.0]
    out = exp.window_max_abs_z(z, times)
    assert 1 not in out                     # bucket 1's only sample is NaN -> undefined


def test_window_max_abs_z_skips_nan_entirely():
    z = np.array([np.nan, np.nan])
    times = [0.0, 1.0]
    out = exp.window_max_abs_z(z, times)
    assert out == {}


# ------------------------------------------------------- cohens_d

def test_cohens_d_zero_for_identical_groups():
    assert exp.cohens_d([1, 2, 3], [1, 2, 3]) == 0.0


def test_cohens_d_large_for_well_separated_groups():
    d = exp.cohens_d([10, 11, 12], [0, 1, 2])
    assert d > 3


def test_cohens_d_zero_with_too_few_samples():
    assert exp.cohens_d([1.0], [1.0, 2.0, 3.0]) == 0.0


# ------------------------------------------------------- fit_threshold

def test_fit_threshold_bounds_empirical_fpr():
    rng = np.random.default_rng(0)
    normal_scores = rng.normal(size=10000)
    threshold, achieved = exp.fit_threshold(normal_scores, max_fpr=0.003)
    assert achieved <= 0.003 + 1e-9
    fired = np.sum(normal_scores > threshold) / len(normal_scores)
    assert fired == pytest.approx(achieved)


def test_fit_threshold_zero_budget_fires_on_nothing():
    scores = np.array([1.0, 2.0, 3.0])
    threshold, achieved = exp.fit_threshold(scores, max_fpr=0.0)
    assert achieved == 0.0
    assert np.sum(scores > threshold) == 0


# ------------------------------------------------------- rule_recall

def test_rule_recall_arithmetic():
    mask = np.array([True, True, False, True])
    fired = np.array([1, 0, 1, 1])
    hits, n, recall = exp.rule_recall(mask, fired)
    assert (hits, n) == (2, 3)
    assert recall == pytest.approx(2 / 3)


def test_rule_recall_zero_denominator():
    mask = np.array([False, False])
    fired = np.array([1, 1])
    hits, n, recall = exp.rule_recall(mask, fired)
    assert (hits, n, recall) == (0, 0, 0.0)


# ------------------------------------------------------- confusion

def test_confusion_basic_arithmetic():
    c = exp.confusion(tp=8, n_pos=10, fp=2, n_neg=20)
    assert c == {"tp": 8, "fn": 2, "fp": 2, "tn": 18, "precision": 0.8, "recall": 0.8, "fpr": 0.1}


# ------------------------------------------------------- measurement-only guard

def test_module_is_measurement_only():
    src = inspect.getsource(exp)
    assert "from iforest_detector import" not in src
    assert "import iforest_detector" not in src
    calls = {
        node.func.id for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_detector" not in calls


def test_no_forbidden_fields_referenced():
    """No code (as opposed to prose in the module docstring, which explicitly
    disclaims these fields) accesses crc_rate or a 'source' field."""
    tree = ast.parse(inspect.getsource(exp))
    body_without_docstring = ast.Module(body=tree.body[1:], type_ignores=[])
    src_without_docstring = ast.unparse(body_without_docstring)
    for forbidden in ("crc_rate", "'source'", '"source"'):
        assert forbidden not in src_without_docstring


def test_no_rate_of_change_reintroduction():
    """This is a relative-deviation baseline, not EXP-0019/0020's |dp|/dt rate
    feature reintroduced under a new name: no division by an elapsed-time delta."""
    src = inspect.getsource(exp)
    assert "step_rates" not in src
    assert "/ dt" not in src.replace(" ", "")


# ------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0029 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0029"

    g = r["identity_gates"]
    assert g["comb_equals_protocol_or_pressure_or_if"] is True
    assert g["whole_test_confusion_matches_exp0017"] is True
    assert g["run_detector_modified"] is False
    assert g["exp0017_confusion"] == [4767, 40, 2166, 2374]

    assert r["known_false_negatives"]["n"] == 150
    assert r["known_false_negatives"]["matches_expected"] is True

    diag = r["diagnostic"]
    assert set(diag["per_k"]) == {"5", "10", "20"} or set(diag["per_k"]) == {5, 10, 20}
    supported = diag["diagnostic_supported"]
    assert supported == (diag["best_cohens_d"] >= diag["min_required_abs_d"])

    dr = r["decision_rule"]
    assert dr["verdict_nmri"] in {"GO", "NO-GO"}
    if not supported:
        assert dr["verdict_nmri"] == "NO-GO"
        assert "diagnostic failed" in dr["verdict_cmri_secondary"] or dr["verdict_cmri_secondary"] == "NO-GO"
    else:
        expected_go_nmri = bool(
            dr["passes_nmri_recall_bar"] and dr["passes_nmri_fpr_bar"]
            and dr["artifact_check_clean_or_gated"]
        )
        assert (dr["verdict_nmri"] == "GO") is expected_go_nmri
