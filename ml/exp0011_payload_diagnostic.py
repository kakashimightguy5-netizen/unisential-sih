#!/usr/bin/env python3
"""Protocol diagnosis and 0x03-only response pressure features for EXP-0011a."""
from __future__ import annotations

import math
from dataclasses import dataclass
from statistics import mean
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

from exp0008_cadence_features import (
    DOS_CATEGORY, WINDOW_SECONDS, BlockData, Mapper, TypeMap,
    canonical_response_type,
)
from exp0009_payload import AlignedPressure, align_pretest_pressure
from features_txt import FrameRecord

READ_HOLDING_REGISTERS = 0x03
WRITE_MULTIPLE_REGISTERS = 0x10
EXPECTED_SHAPES = MappingProxyType({
    READ_HOLDING_REGISTERS: (3, 0, 23, 18, 0),
    WRITE_MULTIPLE_REGISTERS: (16, 0, 8, -1, 0),
})
PROTOCOL_SEMANTICS = MappingProxyType({
    READ_HOLDING_REGISTERS: MappingProxyType({
        "name": "Read Holding Registers",
        "response_body": "byte count followed by returned register values",
        "carries_returned_register_values": True,
    }),
    WRITE_MULTIPLE_REGISTERS: MappingProxyType({
        "name": "Write Multiple Registers",
        "response_body": "starting address and quantity written acknowledgement",
        "carries_returned_register_values": False,
    }),
})
PRESSURE_TYPE = READ_HOLDING_REGISTERS
PRESSURE_FEATURE_NAMES = (
    "func_03_pressure_last", "func_03_pressure_mean", "func_03_pressure_min",
    "func_03_pressure_max", "func_03_pressure_deviation_mean",
    "func_03_pressure_deviation_max_abs", "func_03_pressure_rate_of_change",
    "func_03_pressure_available",
)


@dataclass(frozen=True)
class PayloadDiagnosis:
    status: str
    reason: str
    protocol: Mapping
    shape_check: Mapping
    pressure_counts: Mapping
    aligned: AlignedPressure


@dataclass(frozen=True)
class Payload03Artifacts:
    diagnosis: PayloadDiagnosis
    baseline: float | None
    feature_names: tuple[str, ...]
    train_features: Mapping[int, Mapping[str, float]]
    validation_features: Mapping[int, Mapping[str, float]]


def _shape_for_type(type_map: TypeMap, response_type: int) -> tuple[tuple[int, ...], ...]:
    return tuple(sorted(shape for shape, mapped in type_map.items() if mapped == response_type))


def _class_name(categories: frozenset[int]) -> str | None:
    if categories == frozenset({0}):
        return "normal"
    if DOS_CATEGORY in categories:
        return "dos"
    return None


def _pressure_counts(
    block: BlockData, aligned: AlignedPressure, type_map: TypeMap, mapper: Mapper,
) -> Mapping:
    counts = {
        response_type: {
            "normal": {"frames": 0, "non_missing": 0},
            "dos": {"frames": 0, "non_missing": 0},
            "other": {"frames": 0, "non_missing": 0},
        }
        for response_type in sorted(set(type_map.values()))
    }
    for record in block.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        if bucket not in block.categories:
            continue
        response_type = mapper(record, type_map)
        if response_type not in counts:
            continue
        class_name = _class_name(block.categories[bucket]) or "other"
        counts[response_type][class_name]["frames"] += 1
        if aligned.values.get(record.record_index) is not None:
            counts[response_type][class_name]["non_missing"] += 1
    return MappingProxyType({
        f"0x{response_type:02x}": MappingProxyType({
            class_name: MappingProxyType(dict(values))
            for class_name, values in by_class.items()
        })
        for response_type, by_class in counts.items()
    })


def diagnose_payload_gate(
    train: BlockData, validation: BlockData, type_map: TypeMap,
    aligned: AlignedPressure, mapper: Mapper = canonical_response_type,
) -> PayloadDiagnosis:
    """Classify the 0x10 gate failure using protocol semantics and pre-TEST data."""
    shape_check = {}
    shape_mismatch = False
    for response_type, expected in EXPECTED_SHAPES.items():
        observed = _shape_for_type(type_map, response_type)
        matches = observed == (expected,)
        shape_check[f"0x{response_type:02x}"] = {
            "expected": list(expected), "observed": [list(item) for item in observed],
            "matches_expected": matches,
        }
        shape_mismatch |= not matches
    counts = MappingProxyType({
        "train": _pressure_counts(train, aligned, type_map, mapper),
        "validation": _pressure_counts(validation, aligned, type_map, mapper),
    })
    train_10 = sum(
        counts["train"]["0x10"][name]["non_missing"]
        for name in ("normal", "dos", "other")
    )
    validation_10 = sum(
        counts["validation"]["0x10"][name]["non_missing"]
        for name in ("normal", "dos", "other")
    )
    train_normal_03 = counts["train"]["0x03"]["normal"]["non_missing"]
    if shape_mismatch:
        status = "STOPPED — PROTOCOL/SHAPE CONTRADICTION"
        reason = "canonical response shapes do not match the preregistered Modbus forms"
    elif train_10 or validation_10:
        status = "DATA_SPARSITY — 0011a STOPPED"
        reason = (
            "pressure exists on canonical 0x10 in pre-TEST data; absence from the "
            "TRAIN-normal baseline cannot be treated as structural"
        )
    elif not train_normal_03:
        status = "STOPPED — NO TRAIN-NORMAL 0x03 PRESSURE"
        reason = "no TRAIN-normal 0x03 pressure baseline can be fitted"
    else:
        status = "SCHEMA_LIMITATION — 0x03-ONLY PAYLOAD AUTHORIZED"
        reason = (
            "0x10 is an acknowledgement-only Write Multiple Registers response and has "
            "zero pressure values throughout TRAIN and VALIDATION; 0x03 returns values"
        )
    return PayloadDiagnosis(
        status=status, reason=reason,
        protocol=MappingProxyType({
            f"0x{key:02x}": value for key, value in PROTOCOL_SEMANTICS.items()
        }),
        shape_check=MappingProxyType(shape_check), pressure_counts=counts,
        aligned=aligned,
    )


def fit_train_normal_03_baseline(
    train: BlockData, aligned: AlignedPressure, type_map: TypeMap,
    mapper: Mapper = canonical_response_type,
) -> float:
    values = [
        value for record in train.records
        if (bucket := math.floor(record.timestamp / WINDOW_SECONDS)) in train.categories
        and train.categories[bucket] == frozenset({0})
        and mapper(record, type_map) == PRESSURE_TYPE
        and (value := aligned.values.get(record.record_index)) is not None
    ]
    if not values:
        raise ValueError("no TRAIN-normal 0x03 pressure baseline")
    return mean(values)


def build_03_pressure_features(
    block: BlockData, aligned: AlignedPressure, type_map: TypeMap, baseline: float,
    mapper: Mapper = canonical_response_type,
) -> Mapping[int, Mapping[str, float]]:
    """Build 0x03 summaries; zero is explicit only when availability is zero."""
    observations: dict[int, list[tuple[float, float]]] = {}
    for record in block.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        value = aligned.values.get(record.record_index)
        if (
            bucket in block.categories and mapper(record, type_map) == PRESSURE_TYPE
            and value is not None
        ):
            observations.setdefault(bucket, []).append((record.timestamp, value))
    output = {}
    for bucket in block.emitted_buckets:
        items = sorted(observations.get(bucket, ()))
        if items:
            values = [value for _, value in items]
            elapsed = items[-1][0] - items[0][0]
            row = {
                "func_03_pressure_last": values[-1],
                "func_03_pressure_mean": mean(values),
                "func_03_pressure_min": min(values),
                "func_03_pressure_max": max(values),
                "func_03_pressure_deviation_mean": mean(value - baseline for value in values),
                "func_03_pressure_deviation_max_abs": max(
                    abs(value - baseline) for value in values
                ),
                "func_03_pressure_rate_of_change": (
                    (values[-1] - values[0]) / elapsed if elapsed > 0 else 0.0
                ),
                "func_03_pressure_available": 1.0,
            }
        else:
            row = {name: 0.0 for name in PRESSURE_FEATURE_NAMES}
        output[bucket] = MappingProxyType({name: float(row[name]) for name in PRESSURE_FEATURE_NAMES})
    return MappingProxyType(output)


def prepare_03_payload_artifacts(
    train: BlockData, validation: BlockData, type_map: TypeMap,
    *, records: Sequence[FrameRecord] | None = None,
    arff_rows: Iterable[Sequence[str]] | None = None,
    mapper: Mapper = canonical_response_type,
) -> Payload03Artifacts:
    aligned = align_pretest_pressure(records, arff_rows)
    diagnosis = diagnose_payload_gate(train, validation, type_map, aligned, mapper)
    if not diagnosis.status.startswith("SCHEMA_LIMITATION"):
        return Payload03Artifacts(
            diagnosis, None, PRESSURE_FEATURE_NAMES,
            MappingProxyType({}), MappingProxyType({}),
        )
    baseline = fit_train_normal_03_baseline(train, aligned, type_map, mapper)
    return Payload03Artifacts(
        diagnosis=diagnosis, baseline=baseline, feature_names=PRESSURE_FEATURE_NAMES,
        train_features=build_03_pressure_features(
            train, aligned, type_map, baseline, mapper,
        ),
        validation_features=build_03_pressure_features(
            validation, aligned, type_map, baseline, mapper,
        ),
    )
