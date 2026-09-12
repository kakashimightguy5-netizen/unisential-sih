"""ACK-002: synthetic units for burst-merging (label-blind gap threshold, merge
behavior, post-burst window counting), plus one slow saved-result replay (no raw
data read). FEASIBILITY CHECK ONLY — no detector/classifier under test here.
"""
import json
from pathlib import Path

import numpy as np
import pytest

import ack002_burst_anchored_coverage as ack2
from ack001_ack_anchored_coverage import Ack

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "ack002_coverage.json"


def make_acks(timestamps, cat=0):
    return [Ack(ts=t, bucket=0, cat=cat, spec=0) for t in timestamps]


# ------------------------------------------------------- gap distribution / threshold (label-blind)

def test_inter_ack_gaps_empty_for_fewer_than_two():
    assert ack2.inter_ack_gaps([]).size == 0
    assert ack2.inter_ack_gaps(make_acks([1.0])).size == 0


def test_inter_ack_gaps_basic():
    acks = make_acks([0.0, 1.0, 3.0, 3.5])
    gaps = ack2.inter_ack_gaps(acks)
    assert list(gaps) == [1.0, 2.0, 0.5]


def test_derive_gap_threshold_is_fixed_multiple_of_median():
    gaps = np.array([1.0, 1.0, 1.0, 1.0, 100.0])  # median = 1.0
    threshold = ack2.derive_gap_threshold(gaps, multiple=3.0)
    assert threshold == pytest.approx(3.0)


def test_derive_gap_threshold_raises_on_empty():
    with pytest.raises(ValueError):
        ack2.derive_gap_threshold(np.array([]))


def test_gap_distribution_summary_empty():
    assert ack2.gap_distribution_summary(np.array([])) == {"n_gaps": 0}


def test_gap_distribution_summary_basic():
    gaps = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
    out = ack2.gap_distribution_summary(gaps)
    assert out["n_gaps"] == 5
    assert out["median"] == pytest.approx(3.0)
    assert out["max"] == pytest.approx(5.0)
    assert out["min"] == pytest.approx(1.0)


# ------------------------------------------------------- burst merging

def test_merge_bursts_empty():
    assert ack2.merge_bursts([], threshold=1.0) == []


def test_merge_bursts_single_ack_is_one_burst():
    acks = make_acks([5.0])
    bursts = ack2.merge_bursts(acks, threshold=1.0)
    assert len(bursts) == 1
    assert bursts[0].n_acks == 1
    assert bursts[0].duration == 0.0


def test_merge_bursts_gap_exactly_at_threshold_merges():
    # gap == threshold must merge (<=, not <), per pre-registration step 2
    acks = make_acks([0.0, 2.0])
    bursts = ack2.merge_bursts(acks, threshold=2.0)
    assert len(bursts) == 1
    assert bursts[0].n_acks == 2


def test_merge_bursts_gap_just_over_threshold_splits():
    acks = make_acks([0.0, 2.01])
    bursts = ack2.merge_bursts(acks, threshold=2.0)
    assert len(bursts) == 2
    assert all(b.n_acks == 1 for b in bursts)


def test_merge_bursts_multiple_clusters():
    # cluster A: 0,1,2 (gaps 1,1 <= 2); gap to next is 10 (> 2) -> new cluster
    # cluster B: 12,13 (gap 1 <= 2)
    acks = make_acks([0.0, 1.0, 2.0, 12.0, 13.0])
    bursts = ack2.merge_bursts(acks, threshold=2.0)
    assert len(bursts) == 2
    assert bursts[0].n_acks == 3
    assert bursts[0].start == 0.0
    assert bursts[0].end == 2.0
    assert bursts[1].n_acks == 2
    assert bursts[1].start == 12.0
    assert bursts[1].end == 13.0


def test_merge_bursts_preserves_labels_for_cats_property():
    acks = [Ack(ts=0.0, bucket=0, cat=0, spec=0), Ack(ts=0.5, bucket=0, cat=3, spec=0)]
    bursts = ack2.merge_bursts(acks, threshold=1.0)
    assert len(bursts) == 1
    assert bursts[0].cats == {0, 3}


# ------------------------------------------------------- post-burst window

def test_post_burst_clean_count_strict_boundaries():
    pressure_ts = [5.0, 10.0, 10.0, 15.0, 20.0]
    # window (5.0, 15.0) exclusive both ends -> only 10.0, 10.0 qualify
    assert ack2.post_burst_clean_count(5.0, 15.0, pressure_ts) == 2


def test_post_burst_clean_count_no_samples_in_window():
    assert ack2.post_burst_clean_count(100.0, 110.0, [1.0, 2.0, 200.0]) == 0


def test_burst_windows_last_burst_uses_scope_end():
    acks = make_acks([0.0, 1.0, 20.0, 21.0])
    bursts = ack2.merge_bursts(acks, threshold=2.0)
    assert len(bursts) == 2
    windows = ack2.burst_windows(bursts, scope_end=100.0)
    assert windows[0][1] == 20.0  # bounded by next burst's start
    assert windows[1][1] == 100.0  # bounded by scope end


def test_burst_windows_single_burst_uses_scope_end():
    acks = make_acks([0.0, 1.0])
    bursts = ack2.merge_bursts(acks, threshold=2.0)
    windows = ack2.burst_windows(bursts, scope_end=50.0)
    assert len(windows) == 1
    assert windows[0][1] == 50.0


# ------------------------------------------------------- grouping / summarisation

def test_summarise_group_empty():
    out = ack2.summarise_group("MSCI_containing", [])
    assert out["n_bursts"] == 0


def test_summarise_group_basic_percentages():
    # 3 bursts with clean counts 0, 1, 3 -> ge1: 2/3, ge2: 1/3, ge3: 1/3
    entries = [(None, 0, 5.0), (None, 1, 5.0), (None, 3, 5.0)]
    out = ack2.summarise_group("X", entries)
    assert out["n_bursts"] == 3
    assert out["pct_with_ge1_clean_sample"] == pytest.approx(200.0 / 3.0)
    assert out["pct_with_ge2_clean_sample"] == pytest.approx(100.0 / 3.0)
    assert out["pct_with_ge3_clean_sample"] == pytest.approx(100.0 / 3.0)
    assert out["median_clean_sample_count"] == pytest.approx(1.0)


def test_composition_summary_empty():
    assert ack2.composition_summary([]) == {"n_bursts": 0}


def test_composition_summary_basic():
    b1 = ack2.Burst(make_acks([0.0, 1.0, 2.0], cat=0))  # pure Normal
    b2 = ack2.Burst([Ack(ts=0.0, bucket=0, cat=3, spec=0), Ack(ts=1.0, bucket=0, cat=0, spec=0)])  # MSCI + Normal
    entries = [(b1, 5, 1.0), (b2, 1, 1.0)]
    out = ack2.composition_summary(entries)
    assert out["n_bursts"] == 2
    assert out["median_acks_per_burst"] == pytest.approx(2.5)
    assert out["max_acks_per_burst"] == 3.0
    assert out["pct_bursts_spanning_multiple_categories"] == pytest.approx(50.0)
    assert out["pct_bursts_also_containing_normal"] == pytest.approx(100.0)


def test_stopping_rule_verdict_flags_majority_below_two():
    by_group = {
        "MSCI_containing": {"n_bursts": 10, "pct_with_ge2_clean_sample": 20.0},
        "MPCI_containing": {"n_bursts": 10, "pct_with_ge2_clean_sample": 80.0},
    }
    out = ack2.stopping_rule_verdict(by_group)
    assert out["MSCI_containing"]["verdict"] == "LIKELY INFEASIBLE"
    assert out["MPCI_containing"]["verdict"] == "not flagged by this rule"


def test_stopping_rule_verdict_handles_zero_bursts():
    by_group = {"MSCI_containing": {"n_bursts": 0}, "MPCI_containing": {"n_bursts": 5, "pct_with_ge2_clean_sample": 90.0}}
    out = ack2.stopping_rule_verdict(by_group)
    assert out["MSCI_containing"]["verdict"] == "INFEASIBLE (no data)"


# ------------------------------------------------------- scope / source discipline

def test_module_never_parses_or_uses_source_field():
    import ast
    src = Path(ack2.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "source":
            pytest.fail("ack002 must never read record.source")
        if isinstance(node, ast.Name) and node.id == "source":
            pytest.fail("ack002 must never bind/use a bare 'source' identifier")


def test_module_does_not_import_run_detector_or_protected_files():
    src = Path(ack2.__file__).read_text(encoding="utf-8")
    for forbidden in ("iforest_detector", "rules", "app"):
        assert f"import {forbidden}" not in src
        assert f"from {forbidden} " not in src


def test_module_does_not_touch_dos_or_cmri_closed_files():
    src = Path(ack2.__file__).read_text(encoding="utf-8")
    for forbidden in ("exp0018", "exp0019", "exp0020"):
        assert forbidden not in src


# ------------------------------------------------------- slow saved-result replay

@pytest.mark.slow
def test_saved_result_replay():
    if not RESULT_PATH.exists():
        pytest.skip("ack002_coverage.json not present; run ml/ack002_burst_anchored_coverage.py first")
    data = json.loads(RESULT_PATH.read_text())
    assert data["experiment"] == "ACK-002"
    assert data["status"] == "TESTED"
    assert data["identity_gates"]["exp0017_reproduced"] is True
    assert data["gap_threshold_derivation"]["method"] == "label_blind_fixed_multiple_of_median"
    assert data["gap_threshold_derivation"]["multiple"] == 3.0
    assert data["burst_construction"]["n_bursts_total"] > 0
