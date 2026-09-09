"""Synthetic protocol and 0x03-pressure integrity tests for EXP-0011a."""
from types import MappingProxyType

import pytest

from exp0008_cadence_features import BlockData
from exp0009_payload import AlignedPressure
from exp0011_payload_diagnostic import (
    EXPECTED_SHAPES, PRESSURE_FEATURE_NAMES, PROTOCOL_SEMANTICS,
    build_03_pressure_features, diagnose_payload_gate,
    fit_train_normal_03_baseline,
)
from features_txt import FrameRecord


def record(index, timestamp, *, function=3, category=0, destination=1):
    length, byte_count = {3: (23, 18), 16: (8, -1)}[function]
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=function,
        frame_len_bytes=length, is_request=0, start_register=-1, quantity=-1,
        byte_count=byte_count, length_anomaly=0, rare_function_code=0, crc_ok=0,
        interarrival_seconds=0.0, message_entropy_bits_per_byte=0.0,
        categorized_attack=category, specific_attack=0, source=3,
        destination=destination, timestamp=timestamp,
    )


def type_map():
    return MappingProxyType({shape: shape[0] for shape in EXPECTED_SHAPES.values()})


def block(name, rows, categories):
    return BlockData(
        name=name, records=tuple(rows), emitted_buckets=tuple(sorted(categories)),
        categories=MappingProxyType({
            bucket: frozenset(values) for bucket, values in categories.items()
        }),
    )


def fixture_blocks():
    train_rows = (
        record(1, 0.1), record(2, 2.1), record(3, 0.2, function=16),
        record(4, 5.1, category=6), record(5, 5.2, function=16, category=6),
    )
    validation_rows = (
        record(6, 10.1), record(7, 10.2, function=16),
        record(8, 15.1, category=6), record(9, 15.2, function=16, category=6),
    )
    return (
        block("train", train_rows, {0: {0}, 1: {6}}),
        block("validation", validation_rows, {2: {0}, 3: {6}}),
        train_rows + validation_rows,
    )


def aligned(rows, values):
    return AlignedPressure(
        MappingProxyType(dict(zip((item.record_index for item in rows), values))),
        len(rows), None, None,
    )


def test_protocol_semantics_distinguish_value_response_from_acknowledgement():
    assert PROTOCOL_SEMANTICS[3]["carries_returned_register_values"] is True
    assert "returned register values" in PROTOCOL_SEMANTICS[3]["response_body"]
    assert PROTOCOL_SEMANTICS[16]["carries_returned_register_values"] is False
    assert "acknowledgement" in PROTOCOL_SEMANTICS[16]["response_body"]
    assert EXPECTED_SHAPES[3] == (3, 0, 23, 18, 0)
    assert EXPECTED_SHAPES[16] == (16, 0, 8, -1, 0)


def test_schema_limitation_requires_zero_0x10_pressure_across_pretest():
    train, validation, rows = fixture_blocks()
    values = (10.0, 14.0, None, 20.0, None, 11.0, None, 12.0, None)
    diagnosis = diagnose_payload_gate(
        train, validation, type_map(), aligned(rows, values),
    )
    assert diagnosis.status.startswith("SCHEMA_LIMITATION")
    assert diagnosis.pressure_counts["train"]["0x10"]["normal"]["non_missing"] == 0
    assert diagnosis.pressure_counts["validation"]["0x10"]["dos"]["non_missing"] == 0
    assert all(row["matches_expected"] for row in diagnosis.shape_check.values())


def test_any_pretest_0x10_pressure_classifies_data_sparsity_and_stops():
    train, validation, rows = fixture_blocks()
    values = (10.0, 14.0, None, 20.0, None, 11.0, 99.0, 12.0, None)
    diagnosis = diagnose_payload_gate(
        train, validation, type_map(), aligned(rows, values),
    )
    assert diagnosis.status == "DATA_SPARSITY — 0011a STOPPED"
    assert "cannot be treated as structural" in diagnosis.reason


def test_03_features_use_train_baseline_explicit_availability_and_no_0x10_column():
    train, validation, rows = fixture_blocks()
    aligned_values = aligned(rows, (10.0, 14.0, None, 20.0, None, None, None, 12.0, None))
    baseline = fit_train_normal_03_baseline(train, aligned_values, type_map())
    assert baseline == pytest.approx(12.0)
    features = build_03_pressure_features(train, aligned_values, type_map(), baseline)
    first = features[0]
    assert first["func_03_pressure_last"] == 14.0
    assert first["func_03_pressure_mean"] == 12.0
    assert first["func_03_pressure_min"] == 10.0
    assert first["func_03_pressure_max"] == 14.0
    assert first["func_03_pressure_deviation_mean"] == 0.0
    assert first["func_03_pressure_deviation_max_abs"] == 2.0
    assert first["func_03_pressure_rate_of_change"] == 2.0
    assert first["func_03_pressure_available"] == 1.0
    missing = build_03_pressure_features(
        validation, aligned_values, type_map(), baseline,
    )[2]
    assert missing["func_03_pressure_available"] == 0.0
    assert all(value == 0.0 for value in missing.values())
    assert len(PRESSURE_FEATURE_NAMES) == 8
    assert not any("func_10" in name for name in PRESSURE_FEATURE_NAMES)


def test_type_aware_diagnosis_and_features_call_injected_mapper():
    train, validation, rows = fixture_blocks()
    aligned_values = aligned(rows, (10.0, 14.0, None, 20.0, None, 11.0, None, 12.0, None))
    calls = []

    def spy(item, mapping):
        calls.append(item.record_index)
        shape = (
            item.function_code, item.is_request, item.frame_len_bytes,
            item.byte_count, item.length_anomaly,
        )
        return mapping.get(shape) if item.destination == 1 and item.source == 3 else None

    diagnose_payload_gate(train, validation, type_map(), aligned_values, mapper=spy)
    assert calls
    calls.clear()
    baseline = fit_train_normal_03_baseline(
        train, aligned_values, type_map(), mapper=spy,
    )
    assert calls
    calls.clear()
    build_03_pressure_features(
        validation, aligned_values, type_map(), baseline, mapper=spy,
    )
    assert calls
