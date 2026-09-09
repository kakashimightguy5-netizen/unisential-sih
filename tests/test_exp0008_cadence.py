"""Construction-level TEST-blindness proofs for the EXP-0008 runner."""
from dataclasses import replace
import json

import pytest

import exp0008_cadence_features as cadence
from exp0008_cadence import (
    FROZEN_TEST_CONFIRMATION, PROBABILITY_THRESHOLD, classifier_fingerprint,
    make_classifier, prepare_experiment, score_frozen_test_once,
)
from features_txt import FrameRecord


def record(index, timestamp, *, function, category):
    length, byte_count = {3: (23, 18), 16: (8, -1)}[function]
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=function,
        frame_len_bytes=length, is_request=0, start_register=-1, quantity=-1,
        byte_count=byte_count, length_anomaly=0, rare_function_code=0,
        crc_ok=0, interarrival_seconds=0.0,
        message_entropy_bits_per_byte=0.0, categorized_attack=category,
        specific_attack=0, source=3, destination=1, timestamp=timestamp,
    )


def synthetic_capture():
    rows = []
    index = 0
    for bucket in range(30):
        category = 6 if bucket % 4 == 3 else 0
        for offset, function in ((0.1, 3), (0.2, 16), (2.1, 3), (2.2, 16)):
            rows.append(record(index, bucket * 5.0 + offset, function=function, category=category))
            index += 1
    return tuple(rows)


def serializable_pretest(result):
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def test_mutating_only_test_rows_changes_no_pretest_artifact(monkeypatch):
    monkeypatch.setattr(cadence, "AUDIT_MIN_FRAMES", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_IATS", 1)
    monkeypatch.setattr(cadence, "AUDIT_MIN_WINDOWS", 1)
    original = synthetic_capture()
    _, _, test_indices = cadence._contiguous_blocks(30)
    test_buckets = set(int(index) for index in test_indices)
    mutated = tuple(
        replace(
            item,
            function_code=99,
            frame_len_bytes=1,
            byte_count=777,
            length_anomaly=1,
            categorized_attack=42,
            frame_id=-item.frame_id - 1,
        )
        if int(item.timestamp // cadence.WINDOW_SECONDS) in test_buckets else item
        for item in original
    )

    left, left_artifacts, left_model = prepare_experiment(original)
    right, right_artifacts, right_model = prepare_experiment(mutated)

    assert serializable_pretest(left) == serializable_pretest(right)
    assert dict(left_artifacts.type_map) == dict(right_artifacts.type_map)
    assert left_artifacts.audit == right_artifacts.audit
    assert left_artifacts.baselines == right_artifacts.baselines
    assert left_artifacts.thresholds == right_artifacts.thresholds
    assert left_artifacts.feature_names == right_artifacts.feature_names
    assert classifier_fingerprint(left_model) == classifier_fingerprint(right_model)


def test_random_forest_configuration_and_feature_boundary_are_frozen():
    classifier = make_classifier()
    assert classifier.n_estimators == 300
    assert classifier.class_weight == "balanced"
    assert classifier.random_state == 0
    assert classifier.n_jobs == -1
    assert PROBABILITY_THRESHOLD == 0.5
    forbidden = ("destination", "category", "label", "timestamp", "bucket", "source")
    names = cadence.feature_names_for((3, 16))
    assert len(names) == 33
    assert not any(word in name for name in names for word in forbidden)


def test_frozen_test_requires_exact_explicit_confirmation():
    with pytest.raises(PermissionError):
        score_frozen_test_once("", synthetic_capture())
    assert FROZEN_TEST_CONFIRMATION == "SCORE-EXP-0008-TEST-ONCE"
