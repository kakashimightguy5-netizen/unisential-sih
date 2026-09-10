"""EXP-0018: synthetic units for the AR(1) residual model, the causal rolling
energy statistic, two-sided calibration and the pre-registered decision rule,
plus one slow test that replays the saved result (no raw-data read).

`ml/iforest_detector.run_detector` is measurement-only here: a source check
asserts this module never imports or calls it.
"""
import inspect
import json
from pathlib import Path

import numpy as np
import pytest

import exp0018_pressure_residual_smoothness as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0018_pressure_residual_smoothness.json"


class _AllTrainNormal:
    def label(self, bucket):
        return "train_normal"


class _NormalThenTest:
    def __init__(self, split):
        self.split = split

    def label(self, bucket):
        return "train_normal" if bucket < self.split else "test"


def _ar1(n, phi, mu, sd, seed=0):
    rng = np.random.default_rng(seed)
    x = np.empty(n)
    x[0] = mu
    for i in range(1, n):
        x[i] = mu + phi * (x[i - 1] - mu) + rng.normal(0, sd)
    return x


# --------------------------------------------------------------- AR(1) fit

def test_ar1_recovers_known_coefficient_and_sigma():
    vals = _ar1(6000, phi=0.9, mu=10.0, sd=1.0)
    buckets = np.arange(6000)
    model = exp.ResidualModel(vals, buckets, _AllTrainNormal())
    assert abs(model.phi - 0.9) < 0.03
    assert abs(model.mu - 10.0) < 0.1
    assert abs(model.sigma - 1.0) < 0.1
    # standardised squared residuals average ~1 on the fitting distribution
    assert abs(np.nanmean(model.z2) - 1.0) < 0.15


def test_ar1_needs_enough_train_normal():
    with pytest.raises(RuntimeError):
        exp.ResidualModel(np.arange(10.0), np.arange(10), _AllTrainNormal())


# ------------------------------------------------ rolling energy is two-sided

def test_rolling_energy_low_for_oversmooth_high_for_noisy():
    normal = _ar1(5000, phi=0.85, mu=20.0, sd=1.5, seed=1)
    rng = np.random.default_rng(2)
    smooth = 20.0 + np.cumsum(rng.normal(0, 0.02, 400))          # near-constant forgery
    noisy = 20.0 + rng.normal(0, 8.0, 400)                       # unstable forgery
    vals = np.concatenate([normal, smooth, noisy])
    buckets = np.arange(len(vals))
    model = exp.ResidualModel(vals, buckets, _NormalThenTest(5000))
    energy = model.rolling_energy_by_bucket(model.z2)

    calib = model.calibration_energies(energy)
    smooth_e = np.array([energy[b] for b in range(5200, 5390) if b in energy])
    noisy_e = np.array([energy[b] for b in range(5600, 5390 + 400) if b in energy])

    assert np.median(smooth_e) < 0.3 * np.median(calib)          # over-smooth -> quiet
    assert np.median(noisy_e) > 3.0 * np.median(calib)           # noisy -> loud


def test_calibration_thresholds_are_separate_empirical_quantiles():
    vals = _ar1(8000, phi=0.8, mu=5.0, sd=1.0, seed=3)
    model = exp.ResidualModel(vals, np.arange(8000), _AllTrainNormal())
    energy = model.rolling_energy_by_bucket(model.z2)
    calib = model.calibration_energies(energy)
    low = float(np.quantile(calib, exp.CALIB_LOW_Q))
    high = float(np.quantile(calib, exp.CALIB_HIGH_Q))
    med = float(np.median(calib))
    assert 0.0 < low < med < high
    # mean-of-squares energy is right-skewed: the two sides are not symmetric
    assert (high - med) > (med - low)


# --------------------------------------------------------------- helpers

def test_build_global_samples_orders_by_bucket_then_drops_nonfinite():
    vals, buckets = exp.build_global_samples(
        {5: [1.0, 2.0], 3: [9.0], 7: [float("nan"), 4.0, float("inf")]}
    )
    assert list(vals) == [9.0, 1.0, 2.0, 4.0]
    assert list(buckets) == [3, 5, 5, 7]


def test_confusion_arithmetic():
    c = exp.confusion(tp=50, n_pos=200, fp=3, n_neg=4807)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (50, 150, 3, 4804)
    assert c["recall_pct"] == pytest.approx(25.0, abs=0.001)
    assert c["fpr_pct"] == pytest.approx(100 * 3 / 4807, abs=0.001)


def test_classify_verdict_matches_preregistered_rule():
    assert exp.classify_verdict(0.30, 0.001, 0.98) == "STRONG"
    assert exp.classify_verdict(0.25, 0.0030, 0.970) == "STRONG"       # bars are <=/>=
    assert exp.classify_verdict(0.15, 0.001, 0.98) == "ACCEPTABLE"
    assert exp.classify_verdict(0.30, 0.0031, 0.98).startswith("WEAK")  # FP bar
    assert exp.classify_verdict(0.30, 0.001, 0.969).startswith("WEAK")  # precision bar
    assert exp.classify_verdict(0.09, 0.0, 0.99).startswith("WEAK")     # recall bar


def test_module_is_measurement_only():
    """No import of the operational detector module and no run_detector call:
    EXP-0017 is reproduced only through the checksummed saved artifact."""
    src = inspect.getsource(exp)
    assert "from iforest_detector import" not in src
    assert "import iforest_detector" not in src
    tree = compile(src, "exp0018", "exec", flags=__import__("ast").PyCF_ONLY_AST)
    import ast
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_detector" not in calls
    assert exp.run_experiment.__module__ == exp.__name__


# --------------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0018 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0018"

    g = r["identity_gates"]
    assert g["comb_equals_protocol_or_pressure_or_if"] is True
    assert g["whole_test_confusion_matches_exp0017"] is True
    assert g["run_detector_modified"] is False
    assert g["exp0017_confusion"] == [4767, 40, 2166, 2374]

    dr = r["decision_rule"]
    assert dr["verdict"] in {"STRONG", "ACCEPTABLE", "WEAK / HYPOTHESIS NOT SUPPORTED"}
    assert exp.classify_verdict(
        dr["new_pure_cmri_recall"], dr["new_pure_normal_fp_rate"], dr["combined_precision"]
    ) == dr["verdict"]

    cal = r["calibration"]
    assert cal["low_thr"] < cal["median"] < cal["high_thr"]

    st = r["signal_test"]
    assert 0.0 <= st["p_value"] <= 1.0
    assert isinstance(st["signal_present_in_hypothesised_direction"], bool)

    wt = r["whole_test_block_binary_confusion"]
    d_tn, d_fp, d_fn, d_tp = wt["delta_tn_fp_fn_tp"]
    assert d_tp >= 0 and d_fn == -d_tp and d_tn == -d_fp     # OR only adds flags
    assert wt["exp0017_comb"] == {"tn": 4767, "fp": 40, "fn": 2166, "tp": 2374}
