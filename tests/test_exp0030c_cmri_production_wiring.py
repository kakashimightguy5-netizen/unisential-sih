"""EXP-0030c: unit tests for `rules.CmriFloatProvenanceRule` (fast, using a
fake model double — no XGBoost fit needed) plus a slow saved-result replay
of `ml/exp0030c_cmri_production_wiring.py`'s actual TEST-scored-once output.

CMRI ONLY. These tests must never exercise or assert an NMRI float rule.
`ml/iforest_detector.run_detector` is NOT called by this test file.
"""
import json
from pathlib import Path

import numpy as np
import pytest

from rules import CmriFloatProvenanceRule, RuleHit

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0030c_cmri_production_wiring.json"
MODEL_PATH = ROOT / "data" / "artifacts" / "exp0030c_cmri_float_provenance_model.json"
REFERENCE_PATH = ROOT / "data" / "experiments" / "exp0030c_train_normal_reference.json"


class _FakeModel:
    """Deterministic stand-in for a fitted XGBClassifier: fires whenever the
    first feature exceeds 0."""

    def predict_proba(self, x):
        x = np.asarray(x, dtype=float)
        p1 = (x[:, 0] > 0).astype(float)
        return np.stack([1 - p1, p1], axis=1)


# --------------------------------------------------------- CmriFloatProvenanceRule

def test_fit_from_trained_and_evaluate_fires_above_threshold():
    rule = CmriFloatProvenanceRule().fit_from_trained(_FakeModel(), 0.5, ["a", "b"])
    hit = rule.evaluate({"a": 1.0, "b": 0.0})
    assert hit.fired is True
    assert "cmri_float_provenance_score" in hit.reasons[0]


def test_evaluate_below_threshold_does_not_fire():
    rule = CmriFloatProvenanceRule().fit_from_trained(_FakeModel(), 0.5, ["a", "b"])
    hit = rule.evaluate({"a": -1.0, "b": 0.0})
    assert hit.fired is False
    assert hit.reasons == []


def test_evaluate_none_row_is_silent():
    rule = CmriFloatProvenanceRule().fit_from_trained(_FakeModel(), 0.5, ["a", "b"])
    hit = rule.evaluate(None)
    assert hit.fired is False


def test_evaluate_requires_fit_first():
    with pytest.raises(RuntimeError):
        CmriFloatProvenanceRule().evaluate({"a": 1.0})


def test_predict_batch():
    rule = CmriFloatProvenanceRule().fit_from_trained(_FakeModel(), 0.5, ["a"])
    rows = [{"a": 1.0}, {"a": -1.0}, None]
    assert rule.predict(rows) == [1, 0, 0]


def test_feature_order_respected_not_dict_iteration_order():
    # Feature "a" is the one the fake model keys off (column 0); passing a
    # dict with keys in a different insertion order must not change the
    # result, because the rule reorders by self.feature_names.
    rule = CmriFloatProvenanceRule().fit_from_trained(_FakeModel(), 0.5, ["a", "b"])
    hit = rule.evaluate({"b": 0.0, "a": 1.0})
    assert hit.fired is True


# --------------------------------------------------------- scope discipline

def test_module_docstring_declares_cmri_only():
    import rules
    src = Path(rules.__file__).read_text(encoding="utf-8")
    assert "CMRI ONLY" in src
    assert "NMRI" in src  # mentioned as explicitly out of scope, not silently omitted


# --------------------------------------------------------- slow: saved result replay

@pytest.mark.slow
@pytest.mark.skipif(not RESULT_PATH.exists(), reason="EXP-0030c has not been run yet")
def test_saved_result_identity_gates_pass():
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert data["experiment"] == "EXP-0030c"
    assert "CMRI ONLY" in data["scope"]

    gate = data["identity_gates"]["fix1_style_gate_vs_exp0025"]
    assert all(gate.values()), f"EXP-0030c reproduction of the wired baseline failed: {gate}"
    assert data["identity_gates"]["run_detector_called_this_session"] is False
    assert data["identity_gates"]["reference_reproducible_from_scratch"] is True
    round_trip = data["identity_gates"]["round_trip_checks_after_serialize_reload"]
    assert all(round_trip.values()), round_trip
    assert data["identity_gates"]["evaluate_path_matches_batch_scoring_sample"] is True


@pytest.mark.slow
@pytest.mark.skipif(not RESULT_PATH.exists(), reason="EXP-0030c has not been run yet")
def test_saved_result_decision_rule_consistent_with_reported_numbers():
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    marginal = data["test_scored_once"]["isolated_marginal"]
    decision = data["decision_rule"]
    assert decision["isolated_ratio"] == pytest.approx(marginal["isolated_ratio"])

    go_bar = 3.0
    should_go = marginal["isolated_ratio"] >= go_bar and data["generalizes"]
    assert should_go == decision["overall_verdict"].startswith("GO")

    baseline = data["test_scored_once"]["baseline_confusion_exp0025_wired"]
    new = data["test_scored_once"]["new_confusion_with_cmri_float_rule"]
    assert new["tp"] - baseline["tp"] == marginal["tp_gain"]
    assert new["fp"] - baseline["fp"] == marginal["fp_gain"]
    # a CMRI-only rule must never REDUCE recall or REDUCE FP relative to baseline
    assert marginal["tp_gain"] >= 0
    assert marginal["fp_gain"] >= 0


@pytest.mark.slow
@pytest.mark.skipif(not RESULT_PATH.exists(), reason="EXP-0030c has not been run yet")
def test_leave_one_run_out_reported_consistently():
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    loro = data["leave_one_run_out_fitted_model"]
    assert loro["cohort"] == "cmri_pure"
    assert loro["family"] == "F2"
    generalizes = bool(loro["n_runs_evaluated"] >= 2 and loro["run_dependent"] is False)
    assert generalizes == data["generalizes"]


@pytest.mark.slow
@pytest.mark.skipif(not (MODEL_PATH.exists() and REFERENCE_PATH.exists()),
                    reason="EXP-0030c production artifacts have not been built yet")
def test_production_artifacts_load_and_score_end_to_end():
    from float_provenance_features import f2_row, load_model, load_reference, SeriesIndex
    from exp0032_admissible_ceiling_audit import F2_NAMES

    clf, threshold, feature_names = load_model()
    assert feature_names == list(F2_NAMES)
    reference = load_reference()
    assert len(reference) > 0

    rule = CmriFloatProvenanceRule().fit_from_trained(clf, threshold, feature_names)
    # a synthetic single-sample window's feature row, far outside the
    # TRAIN-normal reference -- exercises the whole load -> feature -> score path
    row = {
        "exponent": 2000.0, "mantissa_low_bits": 255.0, "trailing_zero_bits": 0.0,
        "ulp_distance_to_train_normal": 1e6, "quantization_distance": 1e6,
        "adc_lattice_distance": 1e6, "mantissa_entropy_local": 8.0,
    }
    hit = rule.evaluate(row)
    assert isinstance(hit, RuleHit)
    assert isinstance(hit.fired, bool)
