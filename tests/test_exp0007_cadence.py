"""Contract tests for the isolated EXP-0007 runner."""

from cadence_features import CADENCE_FEATURES
from exp0007_cadence import PROBABILITY_THRESHOLD, make_classifier


def test_random_forest_configuration_is_frozen():
    classifier = make_classifier()
    assert classifier.n_estimators == 300
    assert classifier.class_weight == "balanced"
    assert classifier.random_state == 0
    assert classifier.n_jobs == -1
    assert PROBABILITY_THRESHOLD == 0.5


def test_feature_matrix_contains_only_frozen_cadence_features():
    assert len(CADENCE_FEATURES) == 33
    assert set(CADENCE_FEATURES) == set(dict.fromkeys(CADENCE_FEATURES))
    assert all(name.startswith("func_") or name in {
        "cadence_event_count_total", "missed_cycles_sum_total",
        "cusum_alarm_count_total", "cusum_max_any_type", "active_type_count",
    } for name in CADENCE_FEATURES)
