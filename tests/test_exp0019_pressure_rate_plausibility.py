"""EXP-0019: synthetic units for the |Δp|/Δt rate feature, per-window max
aggregation, the TRAIN-normal plausibility cutoff and the pre-registered decision
rule, plus one slow test that replays the saved result (no raw-data read).

`ml/iforest_detector.run_detector` is measurement-only here: a source check
asserts this module never imports or calls it.
"""
import ast
import inspect
import json
from pathlib import Path

import numpy as np
import pytest

import exp0019_pressure_rate_plausibility as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0019_pressure_rate_plausibility.json"


class _Blocks:
    def __init__(self, train_normal_buckets):
        self.tn = set(train_normal_buckets)

    def label(self, bucket):
        return "train_normal" if bucket in self.tn else "test"


# --------------------------------------------------------------- rate feature

def test_step_rates_are_abs_delta_over_elapsed_time():
    # timestamps 0, 2, 5(->same value), 5 (dt=0 dropped), 9
    series = [(0.0, 10.0), (2.0, 16.0), (5.0, 16.0), (5.0, 99.0), (9.0, 8.0)]
    rates, buckets, later_ts = exp.step_rates(series)
    # pairs: (0->2): |6|/2=3 ; (2->5): 0/3=0 ; (5->5): dt=0 dropped ; (5->9): |8-99|/4=22.75
    assert list(np.round(rates, 4)) == [3.0, 0.0, 22.75]
    assert list(buckets) == [0, 1, 1]            # floor(2/5)=0, floor(5/5)=1, floor(9/5)=1
    assert list(later_ts) == [2.0, 5.0, 9.0]


def test_window_max_rate_takes_the_largest_step_in_each_window():
    rates = np.array([3.0, 0.0, 22.75, 1.0])
    buckets = np.array([0, 1, 1, 4])
    by_win = exp.window_max_rate(rates, buckets)
    assert by_win == {0: 3.0, 1: 22.75, 4: 1.0}


def test_train_normal_step_rates_requires_both_endpoints_train_normal():
    # buckets: 0,0,1,2  -> pairs (b0,b0),(b0,b1),(b1,b2)
    series = [(1.0, 0.0), (2.0, 3.0), (7.0, 3.0), (12.0, 9.0)]
    blocks = _Blocks(train_normal_buckets={0})          # only bucket 0 is train-normal
    tn = exp.train_normal_step_rates(series, blocks)
    assert list(np.round(tn, 4)) == [3.0]               # only the (b0,b0) pair, |3|/1
    blocks2 = _Blocks(train_normal_buckets={0, 1, 2})
    tn2 = exp.train_normal_step_rates(series, blocks2)
    assert len(tn2) == 3


def test_bucket_of():
    assert exp.bucket_of(0.0) == 0
    assert exp.bucket_of(4.999) == 0
    assert exp.bucket_of(5.0) == 1
    assert exp.bucket_of(283780169.0 * 5) == 283780169


# --------------------------------------------------------------- helpers

def test_confusion_arithmetic():
    c = exp.confusion(tp=60, n_pos=544, fp=2, n_neg=4807)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (60, 484, 2, 4805)
    assert c["recall_pct"] == pytest.approx(100 * 60 / 544, abs=0.001)
    assert c["fpr_pct"] == pytest.approx(100 * 2 / 4807, abs=0.001)


def test_classify_verdict_matches_preregistered_rule():
    assert exp.classify_verdict(0.30, 0.001, 0.98) == "STRONG"
    assert exp.classify_verdict(0.25, 0.0030, 0.970) == "STRONG"        # bars are <=/>=
    assert exp.classify_verdict(0.15, 0.001, 0.98) == "ACCEPTABLE"
    assert exp.classify_verdict(0.30, 0.0031, 0.98).startswith("WEAK")  # FP bar
    assert exp.classify_verdict(0.30, 0.001, 0.969).startswith("WEAK")  # precision bar
    assert exp.classify_verdict(0.09, 0.0, 0.99).startswith("WEAK")     # recall bar


def test_module_is_measurement_only():
    src = inspect.getsource(exp)
    assert "from iforest_detector import" not in src
    assert "import iforest_detector" not in src
    tree = ast.parse(src)
    calls = {
        node.func.id for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_detector" not in calls


# --------------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0019 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0019"

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

    m = r["method"]
    p = m["train_normal_rate_percentiles"]
    assert p["p50"] <= p["p99"] <= p["p99_9"] <= p["max"]
    assert m["cutoff_primary_p99_9"] == pytest.approx(p["p99_9"])
    assert m["cutoff_strict_train_normal_max"] == pytest.approx(p["max"])

    st = r["signal_test"]
    assert 0.0 <= st["p_value"] <= 1.0
    assert isinstance(st["signal_present_in_hypothesised_direction"], bool)

    wt = r["whole_test_block_binary_confusion"]
    d_tn, d_fp, d_fn, d_tp = wt["delta_tn_fp_fn_tp"]
    assert d_tp >= 0 and d_fn == -d_tp and d_tn == -d_fp     # OR only adds flags
    assert wt["exp0017_comb"] == {"tn": 4767, "fp": 40, "fn": 2166, "tp": 2374}
