"""ACK-001: synthetic units for ack identification, clustering/censoring arithmetic,
and horizon scorability, plus one slow saved-result replay (no raw-data read).
FEASIBILITY CHECK ONLY — there is no detector/classifier under test here.
"""
import json
from pathlib import Path

import pytest

import ack001_ack_anchored_coverage as ack

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "ack001_coverage.json"


# ------------------------------------------------------- shape identification

def test_is_ack_matches_0x10_8_byte_echo_response_only():
    assert ack.is_ack(function_code=0x10, frame_len_bytes=8, is_request=0) is True
    assert ack.is_ack(function_code=0x10, frame_len_bytes=8, is_request=1) is False  # a request, not ack
    assert ack.is_ack(function_code=0x10, frame_len_bytes=22, is_request=1) is False  # write request
    assert ack.is_ack(function_code=0x03, frame_len_bytes=8, is_request=0) is False  # wrong function


def test_is_pressure_response_matches_0x03_23_byte_canonical_response_only():
    assert ack.is_pressure_response(function_code=0x03, frame_len_bytes=23, is_request=0) is True
    assert ack.is_pressure_response(function_code=0x03, frame_len_bytes=8, is_request=1) is False
    assert ack.is_pressure_response(function_code=0x10, frame_len_bytes=23, is_request=0) is False


def test__is_request_reproduces_a_known_frame_shape():
    # real frozen 0x03 canonical response from EXP-0016/0023
    frame = bytes.fromhex("04031210000e000c7600000000000000003f308d3e3044")
    assert len(frame) == 23
    assert ack._is_request(frame) == 0
    # 8-byte 0x10 echo ack
    echo = bytes([0x04, 0x10, 0x0b, 0xe9, 0x00, 0x12, 0x45, 0x36])
    assert ack._is_request(echo) == 0
    assert len(echo) == 8


# ------------------------------------------------------- range counting

def test_count_in_range_respects_inclusivity_flags():
    ts = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert ack.count_in_range(ts, 1.0, 3.0, lo_inclusive=True, hi_inclusive=True) == 3
    assert ack.count_in_range(ts, 1.0, 3.0, lo_inclusive=False, hi_inclusive=True) == 2
    assert ack.count_in_range(ts, 1.0, 3.0, lo_inclusive=True, hi_inclusive=False) == 2
    assert ack.count_in_range(ts, 1.0, 3.0, lo_inclusive=False, hi_inclusive=False) == 1
    assert ack.count_in_range(ts, 10.0, 20.0, lo_inclusive=True, hi_inclusive=True) == 0


def test_pre_ack_baseline_count_is_strictly_before_ack_within_30s():
    ack_ts = 100.0
    pressure_ts = [69.9, 70.0, 85.0, 99.9, 100.0, 100.1]
    # 70.0, 85.0, 99.9 in [70,100); 69.9 excluded (outside 30s window); 100.0/100.1 excluded (not before)
    n = ack.pre_ack_baseline_count(ack_ts, sorted(pressure_ts))
    assert n == 3


def test_post_ack_horizon_count_is_strictly_after_ack_up_to_and_including_horizon():
    ack_ts = 100.0
    pressure_ts = [100.0, 100.1, 105.0, 110.0, 110.1]
    n = ack.post_ack_horizon_count(ack_ts, 10.0, sorted(pressure_ts))
    # excludes 100.0 (not after), includes 100.1, 105.0, 110.0; excludes 110.1 (> 110.0)
    assert n == 3


# ------------------------------------------------------- clustering / censoring

def test_nearest_ack_gap_seconds_finds_closest_other_ack_either_direction():
    all_ts = [0.0, 5.0, 100.0, 108.0, 200.0]
    assert ack.nearest_ack_gap_seconds(5.0, all_ts) == 5.0    # nearest is 0.0, dist 5
    assert ack.nearest_ack_gap_seconds(100.0, all_ts) == 8.0  # nearest is 108.0
    assert ack.nearest_ack_gap_seconds(200.0, all_ts) == 92.0  # only neighbour is 108.0


def test_nearest_ack_gap_seconds_none_when_only_ack():
    assert ack.nearest_ack_gap_seconds(50.0, [50.0]) is None


def test_next_ack_gap_seconds_looks_forward_only():
    all_ts = [0.0, 5.0, 100.0, 108.0]
    assert ack.next_ack_gap_seconds(5.0, all_ts) == 95.0
    assert ack.next_ack_gap_seconds(108.0, all_ts) is None  # last ack, no censor


# ------------------------------------------------------- category summary integration

def _acks(ts_cat_pairs, bucket=0):
    return [ack.Ack(ts=t, bucket=bucket, cat=c, spec=0) for t, c in ts_cat_pairs]


class _Scan:
    def __init__(self, acks, pressure_ts):
        self.acks = acks
        self.pressure_ts = sorted(pressure_ts)


def test_summarise_category_scorable_and_censored_end_to_end():
    # One MSCI ack at t=100 with a good baseline and full 120s of post-ack pressure,
    # but a second MSCI ack lands at t=140 (40s later) which should censor the 60s
    # and 120s horizons (gap 40 < 60, 40 < 120) but not the 10s/30s horizons.
    msci = 3
    a1 = ack.Ack(ts=100.0, bucket=20, cat=msci, spec=0)
    a2 = ack.Ack(ts=140.0, bucket=28, cat=msci, spec=0)
    pre = [70.0 + i for i in range(6)]          # 6 samples in [70,100)
    post = [100.0 + i * 5 for i in range(1, 25)]  # samples every 5s out to 220s
    scan = _Scan(acks=[a1, a2], pressure_ts=pre + post)
    bucket_cats = {20: frozenset({msci}), 28: frozenset({msci})}

    out = ack.summarise_category("MSCI", [a1, a2], scan, bucket_cats)
    assert out["n_acks"] == 2
    assert out["pct_valid_pre_ack_baseline"] == 100.0  # both have >=5 pre samples (a2's pre-window overlaps a1's post samples too)
    h = out["horizons"]
    assert h["10.0"]["pct_censored"] == 0.0     # neither ack has a next-ack within 10s
    assert h["30.0"]["pct_censored"] == 0.0     # gap for a1 is 40s > 30s; a2 has no next ack
    assert h["60.0"]["pct_censored"] == 50.0    # a1's gap (40s) < 60s: censored; a2 uncensored
    assert h["120.0"]["pct_censored"] == 50.0   # same logic


def test_summarise_category_censoring_truncates_scorable_count():
    # a1 at t=100, next ack (a2) at t=105 — only 5s away, far inside every horizon.
    # Only 2 post-ack pressure samples exist before a2 (t=101, t=103); the nominal
    # 30s horizon would see many more (fabricated dense trailing samples), so raw
    # "scorable" and "scorable_after_censoring" must diverge at 30/60/120s.
    msci = 3
    a1 = ack.Ack(ts=100.0, bucket=20, cat=msci, spec=0)
    a2 = ack.Ack(ts=105.0, bucket=21, cat=msci, spec=0)
    pre = [70.0 + i for i in range(6)]
    near_post = [101.0, 103.0]                       # only these are visible before a2
    far_post = [110.0 + i for i in range(40)]         # would satisfy horizons if uncensored
    scan = _Scan(acks=[a1, a2], pressure_ts=pre + near_post + far_post)
    bucket_cats = {20: frozenset({msci}), 21: frozenset({msci})}
    out = ack.summarise_category("MSCI", [a1, a2], scan, bucket_cats)
    h30 = out["horizons"]["30.0"]
    assert h30["n_scorable"] >= 1        # a1 counted scorable under the naive/raw view
    # under the design's own truncation rule, a1's post-ack window is cut to 5s
    # (next ack at t=105), leaving only 2 samples < HORIZON_MIN_SAMPLES[30]=5
    assert h30["n_scorable_after_censoring"] < h30["n_scorable"]


def test_summarise_category_pure_vs_mixed():
    msci = 3
    a_pure = ack.Ack(ts=100.0, bucket=20, cat=msci, spec=0)
    a_mixed = ack.Ack(ts=200.0, bucket=40, cat=msci, spec=0)
    scan = _Scan(acks=[a_pure, a_mixed], pressure_ts=[90.0] * 6 + [190.0] * 6)
    bucket_cats = {20: frozenset({msci}), 40: frozenset({msci, 0})}
    out = ack.summarise_category("MSCI", [a_pure, a_mixed], scan, bucket_cats)
    assert out["pct_pure"] == 50.0
    assert out["pct_mixed"] == 50.0


def test_summarise_category_empty_reports_zero_not_error():
    scan = _Scan(acks=[], pressure_ts=[])
    out = ack.summarise_category("MPCI", [], scan, {})
    assert out["n_acks"] == 0


# ------------------------------------------------------- cadence evidence

def test_inter_arrival_summary_basic():
    out = ack._inter_arrival_summary([10.0, 12.0, 15.0, 25.0])
    assert out["n_gaps"] == 3
    assert out["median"] == 3.0  # diffs are 2,3,10 -> median 3
    assert out["max"] == 10.0


def test_inter_arrival_summary_handles_too_few_points():
    assert ack._inter_arrival_summary([1.0]) == {"n_gaps": 0}
    assert ack._inter_arrival_summary([]) == {"n_gaps": 0}


# ------------------------------------------------------- stopping rule

def test_stopping_rule_flags_majority_unscorable_raw():
    summary = {
        "by_category": {
            "MSCI": {"n_acks": 10, "horizons": {"120.0": {"pct_scorable": 20.0, "pct_scorable_after_censoring": 20.0}}},
            "MPCI": {"n_acks": 10, "horizons": {"120.0": {"pct_scorable": 80.0, "pct_scorable_after_censoring": 80.0}}},
        }
    }
    out = ack.stopping_rule_verdict(summary)
    assert out["MSCI"]["verdict_literal_rule_raw_horizon"] == "LIKELY INFEASIBLE"
    assert out["MPCI"]["verdict_literal_rule_raw_horizon"] == "not flagged by this rule"


def test_stopping_rule_censoring_aware_can_diverge_from_raw():
    # raw scorability looks fine, but after applying the design's own truncation
    # rule almost nothing is actually observable -> the two verdicts diverge.
    summary = {
        "by_category": {
            "MSCI": {"n_acks": 10, "horizons": {"120.0": {"pct_scorable": 95.0, "pct_scorable_after_censoring": 10.0}}},
        }
    }
    out = ack.stopping_rule_verdict(summary)
    assert out["MSCI"]["verdict_literal_rule_raw_horizon"] == "not flagged by this rule"
    assert out["MSCI"]["verdict_censoring_aware"] == "LIKELY INFEASIBLE"


def test_stopping_rule_handles_zero_acks():
    summary = {"by_category": {"MSCI": {"n_acks": 0}, "MPCI": {"n_acks": 5, "horizons": {"120.0": {"pct_scorable": 90.0, "pct_scorable_after_censoring": 90.0}}}}}
    out = ack.stopping_rule_verdict(summary)
    assert out["MSCI"]["verdict"] == "INFEASIBLE (no data)"


# ------------------------------------------------------- scope / source discipline

def test_module_never_parses_or_uses_source_field():
    import ast
    src = Path(ack.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "source":
            pytest.fail("ack001 must never read record.source")
        if isinstance(node, ast.Name) and node.id == "source":
            pytest.fail("ack001 must never bind/use a bare 'source' identifier")


def test_module_does_not_import_run_detector_or_protected_files():
    src = Path(ack.__file__).read_text(encoding="utf-8")
    for forbidden in ("iforest_detector", "rules", "app"):
        assert f"import {forbidden}" not in src
        assert f"from {forbidden} " not in src


def test_module_does_not_write_or_modify_features_windowed():
    src = Path(ack.__file__).read_text(encoding="utf-8")
    assert "from features_windowed import" not in src  # imported only via exp0021.Blocks


# ------------------------------------------------------- slow replay (no raw read)

@pytest.mark.slow
def test_saved_result_identity_gate_and_stopping_rule_present():
    if not RESULT_PATH.exists():
        pytest.skip("ACK-001 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["identity_gates"]["exp0017_reproduced"] is True
    assert tuple(r["identity_gates"]["exp0017_confusion"]) == ack.EXP0017_TEST_CONFUSION
    for cat in ("Normal", "MSCI", "MPCI"):
        assert cat in r["by_category"]
    assert "MSCI" in r["stopping_rule_verdict"]
    assert "MPCI" in r["stopping_rule_verdict"]
