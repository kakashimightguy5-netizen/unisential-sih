"""EXP-0032: synthetic units for the IEEE-754 / distribution feature builders,
the event-grouped bootstrap resampler, the label-permutation shuffler and the
causality-audit table builder, plus one slow saved-result replay (no raw-data
read).

`ml/iforest_detector.run_detector` is measurement-only here: a source check
asserts this module never imports or calls it.
"""
import ast
import inspect
import json
import struct
from pathlib import Path

import numpy as np
import pytest

import exp0032_admissible_ceiling_audit as exp

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0032_admissible_ceiling_audit.json"


# ------------------------------------------------------- IEEE-754 bit features

def test_ieee754_bits_extracts_expected_exponent_for_powers_of_two():
    values = np.array([1.0, 2.0, 4.0])
    exponent, mantissa_low, trailing_zero = exp.ieee754_bits(values)
    # float64 bias is 1023; 1.0 -> exponent 1023, 2.0 -> 1024, 4.0 -> 1025
    assert list(exponent) == [1023, 1024, 1025]
    # exact powers of two have an all-zero mantissa -> low bits 0, trailing zero 52
    assert list(mantissa_low) == [0, 0, 0]
    assert list(trailing_zero) == [52, 52, 52]


def test_ieee754_bits_nonzero_mantissa_has_finite_trailing_zero_count():
    values = np.array([1.5])   # mantissa = 0.5 in binary -> top bit set, not all-zero
    exponent, mantissa_low, trailing_zero = exp.ieee754_bits(values)
    assert trailing_zero[0] < 52


def test_ieee754_bits_matches_struct_pack_bit_pattern():
    value = 3.14159
    bits = struct.unpack("<Q", struct.pack("<d", value))[0]
    expected_exponent = (bits >> 52) & 0x7FF
    exponent, _, _ = exp.ieee754_bits(np.array([value]))
    assert int(exponent[0]) == expected_exponent


# ------------------------------------------------------- nearest_reference_distance

def test_nearest_reference_distance_zero_for_exact_match():
    ref = np.array([1.0, 2.0, 3.0])
    d = exp.nearest_reference_distance(np.array([2.0]), ref)
    assert d[0] == pytest.approx(0.0)


def test_nearest_reference_distance_picks_closer_neighbor():
    ref = np.array([0.0, 10.0])
    d = exp.nearest_reference_distance(np.array([3.0, 8.0]), ref)
    assert d[0] == pytest.approx(3.0)
    assert d[1] == pytest.approx(2.0)


def test_nearest_reference_distance_empty_reference_is_nan():
    d = exp.nearest_reference_distance(np.array([1.0]), np.array([]))
    assert np.isnan(d[0])


# ------------------------------------------------------- quantization_grid_distance

def test_quantization_grid_distance_zero_on_grid_point():
    d = exp.quantization_grid_distance(np.array([1.0]), steps=[0.5])
    assert d[0] == pytest.approx(0.0, abs=1e-9)


def test_quantization_grid_distance_takes_min_over_steps():
    # 1.05 is 0.05 from the nearest multiple of 0.1, but exactly on a multiple of 1.05... use simpler case
    d = exp.quantization_grid_distance(np.array([1.05]), steps=[0.1, 1.0])
    # nearest multiple of 0.1 to 1.05 is 1.1 or 1.0, distance 0.05; nearest multiple of 1.0 is 1.0, distance 0.05
    assert d[0] == pytest.approx(0.05, abs=1e-9)


# ------------------------------------------------------- mantissa_low_bits_entropy

def test_mantissa_entropy_zero_for_constant_bits():
    assert exp.mantissa_low_bits_entropy(np.array([3, 3, 3, 3])) == pytest.approx(0.0)


def test_mantissa_entropy_max_for_uniform_two_symbols():
    bits = np.array([0, 1, 0, 1, 0, 1])
    e = exp.mantissa_low_bits_entropy(bits, n_bits=1)
    assert e == pytest.approx(1.0, abs=1e-6)


def test_mantissa_entropy_zero_for_too_few_samples():
    assert exp.mantissa_low_bits_entropy(np.array([5])) == 0.0


# ------------------------------------------------------- distribution_features

def test_distribution_features_empty_buffer_is_all_zero():
    out = exp.distribution_features(np.array([]), (0.0, 1.0), np.array([0.5]))
    assert out["unique_count"] == 0.0
    assert out["entropy"] == 0.0


def test_distribution_features_quantiles_of_uniform_ramp():
    buf = np.arange(0, 101, dtype=float)   # 0..100
    out = exp.distribution_features(buf, (0.0, 100.0), np.array([50.0]))
    assert out["q50"] == pytest.approx(50.0, abs=1.0)
    assert out["unique_count"] == 101.0
    assert out["repetition_rate"] == pytest.approx(0.0)


def test_distribution_features_repetition_rate_for_constant_buffer():
    buf = np.full(10, 5.0)
    out = exp.distribution_features(buf, (0.0, 10.0), np.array([5.0]))
    assert out["unique_count"] == 1.0
    assert out["repetition_rate"] == pytest.approx(0.9)
    assert out["max_gap"] == 0.0


def test_distribution_features_wasserstein_zero_for_identical_distributions():
    buf = np.array([1.0, 2.0, 3.0])
    out = exp.distribution_features(buf, (0.0, 4.0), np.array([1.0, 2.0, 3.0]))
    assert out["wasserstein_to_train_normal"] == pytest.approx(0.0, abs=1e-9)


# ------------------------------------------------------- contiguous_events

def test_contiguous_events_splits_on_index_gap():
    idx = np.array([1, 2, 3, 10, 11])
    events = exp.contiguous_events(idx)
    assert [list(e) for e in events] == [[0, 1, 2], [3, 4]]


def test_contiguous_events_single_run():
    idx = np.array([5, 6, 7, 8])
    events = exp.contiguous_events(idx)
    assert len(events) == 1
    assert list(events[0]) == [0, 1, 2, 3]


def test_contiguous_events_all_isolated():
    idx = np.array([1, 3, 5])
    events = exp.contiguous_events(idx)
    assert [list(e) for e in events] == [[0], [1], [2]]


# ------------------------------------------------------- event_grouped_bootstrap_resample

def test_event_grouped_bootstrap_resample_keeps_events_whole():
    events = [np.array([0, 1]), np.array([2, 3, 4])]
    rng = np.random.default_rng(0)
    sample = exp.event_grouped_bootstrap_resample(events, rng)
    # every resampled position must belong to a whole original event, never a
    # partial event (length of sample is a sum of {2,3}-sized chunks)
    assert len(sample) in {2, 3, 4, 5, 6}
    for pos in sample:
        assert pos in {0, 1, 2, 3, 4}


def test_event_grouped_bootstrap_resample_empty_events():
    assert len(exp.event_grouped_bootstrap_resample([], np.random.default_rng(0))) == 0


def test_event_grouped_bootstrap_resample_deterministic_with_seeded_rng():
    events = [np.array([0]), np.array([1]), np.array([2])]
    s1 = exp.event_grouped_bootstrap_resample(events, np.random.default_rng(42))
    s2 = exp.event_grouped_bootstrap_resample(events, np.random.default_rng(42))
    assert np.array_equal(s1, s2)


# ------------------------------------------------------- event_grouped_permute_labels

def test_event_grouped_permute_labels_preserves_label_counts():
    events = [np.array([0, 1]), np.array([2, 3]), np.array([4, 5])]
    labels = np.array([1, 1, 0, 0, 0, 0])
    rng = np.random.default_rng(0)
    permuted = exp.event_grouped_permute_labels(events, labels, rng)
    assert sorted(permuted.tolist()) == sorted(labels.tolist())


def test_event_grouped_permute_labels_keeps_events_uniform():
    events = [np.array([0, 1, 2]), np.array([3, 4])]
    labels = np.array([1, 1, 1, 0, 0])
    rng = np.random.default_rng(1)
    permuted = exp.event_grouped_permute_labels(events, labels, rng)
    # each event's rows still share one label after permutation
    assert len(set(permuted[[0, 1, 2]].tolist())) == 1
    assert len(set(permuted[[3, 4]].tolist())) == 1


def test_event_grouped_permute_labels_empty_events_is_noop():
    labels = np.array([1, 0])
    out = exp.event_grouped_permute_labels([], labels, np.random.default_rng(0))
    assert np.array_equal(out, labels)


# ------------------------------------------------------- fit_threshold / recall_at_threshold

def test_fit_threshold_bounds_empirical_fpr():
    rng = np.random.default_rng(0)
    normal_scores = rng.normal(size=10000)
    threshold, achieved = exp.fit_threshold(normal_scores, max_fpr=0.003)
    assert achieved <= 0.003 + 1e-9
    fired = np.sum(normal_scores > threshold) / len(normal_scores)
    assert fired == pytest.approx(achieved)


def test_recall_at_threshold_basic():
    scores = np.array([0.1, 0.9, 0.4, 0.8])
    labels = np.array([0, 1, 0, 1])
    recall = exp.recall_at_threshold(scores, labels, threshold=0.5)
    assert recall == pytest.approx(1.0)


def test_recall_at_threshold_zero_positives():
    scores = np.array([0.1, 0.9])
    labels = np.array([0, 0])
    assert exp.recall_at_threshold(scores, labels, threshold=0.5) == 0.0


# ------------------------------------------------------- percentile_ci

def test_percentile_ci_basic():
    values = list(range(101))   # 0..100
    lo, hi = exp.percentile_ci(values, lo=2.5, hi=97.5)
    assert lo == pytest.approx(2.5, abs=0.5)
    assert hi == pytest.approx(97.5, abs=0.5)


def test_percentile_ci_empty_is_zero():
    assert exp.percentile_ci([]) == (0.0, 0.0)


# ------------------------------------------------------- build_causality_audit

def test_build_causality_audit_ranks_by_importance():
    names = ["last_pressure", "exponent", "q50"]
    importances = [0.1, 0.7, 0.2]
    rows = exp.build_causality_audit(names, importances, top_k=3)
    assert [r["feature"] for r in rows] == ["exponent", "q50", "last_pressure"]
    assert all(r["keep"] for r in rows)


def test_build_causality_audit_unknown_feature_flagged_not_keep():
    names = ["mystery_field"]
    importances = [1.0]
    rows = exp.build_causality_audit(names, importances, top_k=1)
    assert rows[0]["keep"] is False
    assert rows[0]["family"] == "unknown"


def test_build_causality_audit_respects_top_k():
    names = ["last_pressure", "exponent", "q50", "step_rate"]
    importances = [0.1, 0.2, 0.3, 0.4]
    rows = exp.build_causality_audit(names, importances, top_k=2)
    assert len(rows) == 2
    assert rows[0]["feature"] == "step_rate"


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


# ------------------------------------------------------- slow replay

@pytest.mark.slow
def test_saved_result_identity_and_decision_rule():
    if not RESULT_PATH.exists():
        pytest.skip("EXP-0032 result not generated in this tree")
    r = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    assert r["experiment"] == "EXP-0032"

    g = r["identity_gates"]
    assert g["comb_equals_protocol_or_pressure_or_if"] is True
    assert g["whole_test_confusion_matches_exp0017"] is True
    assert g["run_detector_modified"] is False
    assert g["exp0017_confusion"] == [4767, 40, 2166, 2374]

    assert set(r["per_attack"]) == {"NMRI", "CMRI"}
    for attack, block in r["per_attack"].items():
        assert set(block["families"]) == {"F1", "F2", "F3", "combined"}
        assert block["verdict"] in {
            "PROCEED-0030", "PROCEED-0031", "PROCEED-BOTH", "NO-GO-CEILING",
        } or block["verdict"].startswith("NO-GO")

    dr = r["decision_rule"]
    assert "overall" in dr and "verdicts" in dr
