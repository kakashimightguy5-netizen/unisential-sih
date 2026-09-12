"""EXP-0026: native window-construction unit tests (split-boundary discipline,
no TRAIN/VALIDATION/TEST leakage), feature/statistics helpers, plus a slow
saved-result replay. Descriptive/diagnostic — no detector is trained here
unless the pre-registered gate passed (see docs/EXP0026_RESULTS.md)."""
import json
from pathlib import Path

import numpy as np
import pytest

import exp0026_window_size as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0026_window_size.json"


class FakeBlocks:
    """Minimal stand-in for exp0021_msci_mpci.Blocks — just the three bucket-id
    sets native_block_label/build_native_windows actually read."""
    def __init__(self, train, validation, test):
        self.train = set(train)
        self.validation = set(validation)
        self.test = set(test)


def make_scan(categories_by_5s, pressure_by_5s=None):
    scan = exp.Scan()
    for b5, cats in categories_by_5s.items():
        scan.categories_by_5s_bucket[b5] = set(cats)
    for b5, samples in (pressure_by_5s or {}).items():
        scan.pressure_by_5s_bucket[b5] = list(samples)
    return scan


# --------------------------------------------------------- native_block_label

def test_native_block_label_all_in_train():
    blocks = FakeBlocks(train=range(0, 10), validation=range(10, 20), test=range(20, 30))
    assert exp.native_block_label(0, n5=3, blocks=blocks) == "train"  # buckets 0,1,2


def test_native_block_label_discarded_when_spanning_boundary():
    blocks = FakeBlocks(train=range(0, 5), validation=range(5, 10), test=range(10, 20))
    # native window nb=1, n5=3 -> buckets 3,4,5 -- 3,4 train but 5 validation
    assert exp.native_block_label(1, n5=3, blocks=blocks) is None


def test_native_block_label_discarded_when_spanning_internal_gap():
    blocks = FakeBlocks(train={0, 1, 3, 4}, validation=set(), test=set())  # bucket 2 missing
    assert exp.native_block_label(0, n5=5, blocks=blocks) is None  # needs 0..4, 2 is absent
    assert exp.native_block_label(0, n5=2, blocks=blocks) == "train"  # buckets 0,1 only


def test_native_block_label_validation_and_test():
    blocks = FakeBlocks(train=range(0, 5), validation=range(5, 10), test=range(10, 20))
    assert exp.native_block_label(1, n5=5, blocks=blocks) == "validation"  # buckets 5..9
    assert exp.native_block_label(2, n5=5, blocks=blocks) == "test"        # buckets 10..14


# --------------------------------------------------------- build_native_windows / no leakage

def test_build_native_windows_respects_boundaries_and_discards_spanning():
    # 12 base 5s buckets: 0-4 train, 5-9 validation. n5=3 -> native buckets 0,1,2,3.
    # native 0 -> {0,1,2} all train (ok); native 1 -> {3,4,5} spans train/val (discard);
    # native 2 -> {6,7,8} all validation (ok); native 3 -> {9,10,11} 10,11 missing (discard).
    blocks = FakeBlocks(train=range(0, 5), validation=range(5, 10), test=set())
    cats = {b: {0} for b in range(0, 10)}
    scan = make_scan(cats)
    by_block, n_discarded = exp.build_native_windows(scan, blocks, window_seconds=15.0)
    assert [w.nb_index for w in by_block.get("train", [])] == [0]
    assert [w.nb_index for w in by_block.get("validation", [])] == [2]
    assert n_discarded == 2


def test_build_native_windows_no_leakage_across_blocks():
    """No native window straddling TRAIN/VALIDATION/TEST ever appears in any
    block's list -- the core anti-leakage guarantee this experiment must uphold."""
    blocks = FakeBlocks(train=range(0, 6), validation=range(6, 12), test=range(12, 24))
    cats = {b: {0} for b in range(0, 24)}
    scan = make_scan(cats)
    for w_seconds, n5 in ((15.0, 3), (30.0, 6), (60.0, 12)):
        by_block, _ = exp.build_native_windows(scan, blocks, window_seconds=w_seconds)
        for label, bucket_set in (("train", blocks.train), ("validation", blocks.validation),
                                   ("test", blocks.test)):
            for w in by_block.get(label, []):
                sub = range(w.nb_index * n5, w.nb_index * n5 + n5)
                assert all(b in bucket_set for b in sub), (w_seconds, label, w.nb_index)


def test_build_native_windows_rejects_non_multiple():
    blocks = FakeBlocks(train=set(), validation=set(), test=set())
    scan = make_scan({})
    with pytest.raises(ValueError):
        exp.build_native_windows(scan, blocks, window_seconds=7.0)


# Note: build_native_windows only ever generates a native id from a base bucket
# that actually has data (`native_ids` is derived from `all_5s_buckets`), so
# every native window's span contains at least one non-empty base bucket by
# construction -- the "not cats" discard branch is defensive-only and cannot
# be exercised through this public entry point; not separately unit-tested.


# --------------------------------------------------------- native_window_features

def test_native_window_features_none_below_two_samples():
    w = exp.NativeWindow(0, frozenset({0}), [(1.0, 5.0)])
    assert exp.native_window_features(w, {}) is None


def test_native_window_features_basic():
    w = exp.NativeWindow(5, frozenset({0}), [(0.0, 1.0), (1.0, 3.0), (2.0, 2.0)])
    f = exp.native_window_features(w, {})
    assert f["p_std"] == pytest.approx(np.std([1.0, 3.0, 2.0]))
    assert f["p_range"] == pytest.approx(2.0)
    assert f["p_max_abs_step"] == pytest.approx(2.0)  # |3-1| then |2-3|=1 -> max 2
    assert f["p_mean_shift"] == 0.0  # no preceding window supplied


def test_native_window_features_mean_shift_vs_preceding():
    prev = exp.NativeWindow(4, frozenset({0}), [(0.0, 10.0), (1.0, 10.0)])
    w = exp.NativeWindow(5, frozenset({0}), [(0.0, 12.0), (1.0, 14.0)])
    f = exp.native_window_features(w, {4: prev})
    assert f["p_mean_shift"] == pytest.approx(abs(13.0 - 10.0))


def test_native_window_features_mean_shift_zero_when_preceding_has_no_pressure():
    prev = exp.NativeWindow(4, frozenset({0}), [])
    w = exp.NativeWindow(5, frozenset({0}), [(0.0, 12.0), (1.0, 14.0)])
    f = exp.native_window_features(w, {4: prev})
    assert f["p_mean_shift"] == 0.0


# --------------------------------------------------------- pure selection

def test_pure_and_pure_normal_selection():
    windows = [
        exp.NativeWindow(0, frozenset({0}), []),
        exp.NativeWindow(1, frozenset({0, 3}), []),   # pure MSCI(+Normal)
        exp.NativeWindow(2, frozenset({0, 3, 4}), []),  # mixed MSCI+MPCI -> not pure either
        exp.NativeWindow(3, frozenset({4}), []),      # pure MPCI, no Normal co-occurrence
    ]
    assert [w.nb_index for w in exp._pure(windows, 3)] == [1]
    assert [w.nb_index for w in exp._pure(windows, 4)] == [3]
    assert [w.nb_index for w in exp._pure_normal(windows)] == [0]


def test_containing_selection_includes_mixed_windows():
    """`_containing` (EXP-0021's window-level cohort) must include a window
    even when another attack category also co-occurs -- unlike `_pure`."""
    windows = [
        exp.NativeWindow(0, frozenset({0}), []),
        exp.NativeWindow(1, frozenset({0, 3}), []),
        exp.NativeWindow(2, frozenset({0, 3, 4}), []),
        exp.NativeWindow(3, frozenset({4}), []),
    ]
    assert [w.nb_index for w in exp._containing(windows, 3)] == [1, 2]
    assert [w.nb_index for w in exp._containing(windows, 4)] == [2, 3]


# --------------------------------------------------------- decision gate

def test_decision_gate_ignores_baseline_and_requires_both_conditions():
    by_size = {
        5.0: {"per_category": {"MSCI": {"features": [
            {"feature": "p_std", "cohens_d": 0.9, "n_attack_containing": 100, "clears_gate": True},
        ]}}},
        15.0: {"per_category": {"MSCI": {"features": [
            {"feature": "p_std", "cohens_d": 0.6, "n_attack_containing": 40, "clears_gate": True},
            {"feature": "p_range", "cohens_d": 0.55, "n_attack_containing": 10, "clears_gate": False},
        ]}}},
    }
    gate = exp.decision_gate(by_size)
    assert gate["passed"] is True
    assert len(gate["passing_triples"]) == 1
    assert gate["passing_triples"][0]["window_seconds"] == 15.0


def test_decision_gate_not_passed_when_nothing_clears():
    by_size = {15.0: {"per_category": {"MSCI": {"features": [
        {"feature": "p_std", "cohens_d": 0.3, "n_attack_containing": 100, "clears_gate": False},
    ]}}}}
    gate = exp.decision_gate(by_size)
    assert gate["passed"] is False
    assert gate["consequence"].startswith("STOP")


# --------------------------------------------------------- scope discipline

def test_module_never_parses_or_uses_source_field():
    import ast
    src = Path(exp.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "source":
            pytest.fail("exp0026 must never read record.source")
        if isinstance(node, ast.Name) and node.id == "source":
            pytest.fail("exp0026 must never bind/use a bare 'source' identifier")


def test_module_does_not_import_production_pipeline_or_closed_files():
    src = Path(exp.__file__).read_text(encoding="utf-8")
    for forbidden in ("features_windowed", "run_detector", "iforest_detector",
                       "exp0011", "exp0018", "exp0019", "exp0020", "app"):
        assert f"import {forbidden}" not in src, forbidden
        assert f"from {forbidden} " not in src, forbidden


# --------------------------------------------------------- slow: saved result replay

@pytest.mark.slow
def test_saved_result_replay():
    if not RESULT_PATH.exists():
        pytest.skip("exp0026_window_size.json not present; run ml/exp0026_window_size.py first")
    data = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert data["experiment"] == "EXP-0026"
    assert data["window_sizes_seconds"] == [5.0, 15.0, 30.0, 60.0]
    check = data["five_second_baseline_consistency_check"]
    assert check["all_within_tolerance"] is True, check["checks"]
    gate = data["decision_gate"]
    assert gate["passed"] in (True, False)
