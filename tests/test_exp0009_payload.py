"""Synthetic alignment and transformation proofs for EXP-0009a."""
from dataclasses import replace
from types import MappingProxyType

import pytest

from exp0008_cadence_features import BlockData, PreTestSplit, _contiguous_blocks
from exp0009_payload import (
    AlignedPressure, align_pretest_pressure, audit_train_pressure,
    build_pressure_features, fit_pressure_baselines, pressure_feature_names,
)
from features_txt import FrameRecord


def record(index, timestamp, *, function=3, destination=1, category=0):
    length, byte_count = {3: (23, 18), 16: (8, -1)}[function]
    return FrameRecord(
        record_index=index, frame_id=index, address=4, function_code=function,
        frame_len_bytes=length, is_request=0, start_register=-1, quantity=-1,
        byte_count=byte_count, length_anomaly=0, rare_function_code=0, crc_ok=0,
        interarrival_seconds=0.0, message_entropy_bits_per_byte=0.0,
        categorized_attack=category, specific_attack=0, source=3,
        destination=destination, timestamp=timestamp,
    )


def arff(item, pressure="?"):
    direction = 0 if item.destination == 1 else 1
    command_fields = ["SECRET"] * 10
    return (
        "4", str(item.function_code), str(item.frame_len_bytes), *command_fields,
        pressure, "CRC", str(direction), str(item.timestamp), "0",
        str(item.categorized_attack), str(item.specific_attack),
    )


def type_map():
    return MappingProxyType({
        (3, 0, 23, 18, 0): 3,
        (16, 0, 8, -1, 0): 16,
    })


def block(name, rows, categories):
    return BlockData(
        name, tuple(rows), tuple(sorted(categories)),
        MappingProxyType({key: frozenset(value) for key, value in categories.items()}),
    )


def synthetic_split():
    train, validation, _ = _contiguous_blocks(30)
    return PreTestSplit(
        "synthetic-pretest-v1", "synthetic",
        tuple(map(int, train)), tuple(map(int, validation)), (17, 18),
    )


def synthetic_rows():
    rows = []
    index = 1
    for bucket in range(30):
        category = 6 if bucket % 4 == 3 else 0
        for offset, function in ((0.1, 3), (0.2, 16), (2.1, 3), (2.2, 16)):
            rows.append(record(index, bucket * 5 + offset, function=function, category=category))
            index += 1
    return tuple(rows)


def test_alignment_reads_only_pretest_egress_pressure_and_ignores_command_fields():
    rows = synthetic_rows()
    arff_rows = tuple(arff(item, str(item.record_index / 10)) for item in rows)
    aligned = align_pretest_pressure(rows, arff_rows, split=synthetic_split())
    assert aligned.values
    assert all(rows[index - 1].destination == 1 for index in aligned.values)
    assert max(aligned.values) < len(rows)
    assert all(value == pytest.approx(index / 10) for index, value in aligned.values.items())

    mixed = (replace(rows[0], destination=3), *rows[1:])
    mixed_arff = (
        arff(mixed[0], "not-parsed"),
        *(arff(item, "1.25" if item.record_index == 2 else "2") for item in mixed[1:]),
    )
    aligned = align_pretest_pressure(mixed, mixed_arff, split=synthetic_split())
    assert 1 not in aligned.values
    assert aligned.values.get(2) == 1.25


def test_alignment_rejects_pretest_direction_label_or_time_mismatch():
    rows = synthetic_rows()
    arff_rows = [list(arff(item, "1")) for item in rows]
    arff_rows[0][15] = "1"
    with pytest.raises(ValueError, match="pre-TEST alignment mismatch"):
        align_pretest_pressure(rows, arff_rows, split=synthetic_split())


def test_train_only_baselines_and_hand_calculated_features_have_no_missingness_input():
    rows = (
        record(1, 0.1), record(2, 2.1),
        record(3, 5.1, category=6), record(4, 7.1, category=6),
        record(5, 10.1), record(6, 12.1),
        record(7, 15.1, function=16), record(8, 17.1, function=16),
    )
    train = block("train", rows, {0: {0}, 1: {6}, 2: {0}, 3: {0}})
    arff_rows = tuple(arff(item, value) for item, value in zip(
        rows, ("10", "14", "100", "200", "?", "?", "20", "20"),
    ))
    aligned = AlignedPressure(
        MappingProxyType({
            item.record_index: None if value == "?" else float(value)
            for item, value in zip(
                rows, ("10", "14", "100", "200", "?", "?", "20", "20"),
            )
        }),
        len(rows), None, None,
    )
    baselines = fit_pressure_baselines(train, aligned, type_map())
    assert baselines[3] == pytest.approx(12.0)
    assert baselines[16] == pytest.approx(20.0)
    features = build_pressure_features(train, aligned, type_map(), baselines)
    assert features[0]["func_03_pressure_last"] == 14.0
    assert features[0]["func_03_pressure_mean"] == 12.0
    assert features[0]["func_03_pressure_min"] == 10.0
    assert features[0]["func_03_pressure_max"] == 14.0
    assert features[0]["func_03_pressure_deviation_mean"] == 0.0
    assert features[0]["func_03_pressure_deviation_max_abs"] == 2.0
    assert features[0]["func_03_pressure_rate_of_change"] == 2.0
    assert features[2]["func_03_pressure_last"] == 12.0
    assert features[2]["func_03_pressure_deviation_mean"] == 0.0
    names = pressure_feature_names((3, 16))
    assert len(names) == 14
    assert not any("missing" in name or "present" in name for name in names)


def test_payload_gate_rejects_perfect_presence_proxy():
    rows = (
        record(1, 0.1), record(2, 1.1),
        record(3, 5.1, category=6), record(4, 6.1, category=6),
        *(record(index, index * 5.0 + 0.1) for index in range(5, 35)),
    )
    categories = {0: {0}, 1: {6}, **{index: {0} for index in range(5, 35)}}
    train = block("train", rows, categories)
    values = ["1", "2", "?", "?", *("1" for _ in range(30))]
    aligned = AlignedPressure(
        MappingProxyType({
            item.record_index: None if value == "?" else float(value)
            for item, value in zip(rows, values)
        }),
        len(rows), None, None,
    )
    audit = audit_train_pressure(train, aligned, type_map())
    assert not audit["passed"]
    assert audit["perfect_separation_by_presence"]
    assert audit["status"] == "STOPPED — PAYLOAD GATE"
