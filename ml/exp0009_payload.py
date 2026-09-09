#!/usr/bin/env python3
"""Aligned response-pressure features and TRAIN-only audit for EXP-0009a."""
from __future__ import annotations

import csv
import hashlib
import math
from dataclasses import dataclass
from pathlib import Path
from statistics import mean
from types import MappingProxyType
from typing import Iterable, Mapping, Sequence

import numpy as np

from exp0008_cadence_features import (
    DOS_CATEGORY, WINDOW_SECONDS, BlockData, Mapper, TypeMap,
    PreTestSplit, canonical_response_type, partition_pretest_inputs,
)
from features_txt import RAW_TXT, FrameRecord, iter_records

RAW_ARFF = Path(__file__).resolve().parent.parent / "data" / "raw" / "IanArffDataset.arff"
TXT_SHA256 = "ce2d69e3ada867b498a1db4560d609c35d23667f4f5cf2dea57ddd63fe7d93e3"
ARFF_SHA256 = "970a7bcd3949d09ac7baff11603538b142f214ee47ed70baf9efb3344f4af459"
PRESSURE_FIELD = "pressure measurement"
PRESSURE_FEATURES = (
    "last", "mean", "min", "max", "deviation_mean", "deviation_max_abs",
    "rate_of_change",
)


@dataclass(frozen=True)
class AlignedPressure:
    """Pressure values retained only for pre-TEST egress records."""

    values: Mapping[int, float | None]
    row_count: int
    txt_sha256: str | None
    arff_sha256: str | None


@dataclass(frozen=True)
class PressureArtifacts:
    aligned: AlignedPressure
    audit: Mapping
    baselines: Mapping[int, float]
    feature_names: tuple[str, ...]
    train_features: Mapping[int, Mapping[str, float]]
    validation_features: Mapping[int, Mapping[str, float]]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _arff_data_rows(path: Path) -> Iterable[tuple[str, ...]]:
    in_data = False
    with path.open("r", encoding="utf-8") as source:
        for raw_line in source:
            line = raw_line.strip()
            if not line or line.startswith("%"):
                continue
            if not in_data:
                if line.lower() == "@data":
                    in_data = True
                continue
            parsed = next(csv.reader([line], skipinitialspace=True))
            yield tuple(value.strip().strip("'") for value in parsed)
    if not in_data:
        raise ValueError("ARFF has no @data section")


def _parse_optional_float(token: str) -> float | None:
    if token == "?":
        return None
    value = float(token)
    return value if math.isfinite(value) else None


def align_pretest_pressure(
    records: Sequence[FrameRecord] | None = None,
    arff_rows: Iterable[Sequence[str]] | None = None,
    *,
    txt_path: Path = RAW_TXT,
    arff_path: Path = RAW_ARFF,
    split: PreTestSplit | None = None,
) -> AlignedPressure:
    """Verify alignment while parsing pressure only for TRAIN/VALIDATION egress rows."""
    using_files = records is None and arff_rows is None
    if (records is None) != (arff_rows is None):
        raise ValueError("synthetic records and ARFF rows must be supplied together")
    if using_files:
        txt_hash, arff_hash = _sha256(txt_path), _sha256(arff_path)
        if txt_hash != TXT_SHA256:
            raise ValueError(f"TXT sha256 mismatch: {txt_hash}")
        if arff_hash != ARFF_SHA256:
            raise ValueError(f"ARFF sha256 mismatch: {arff_hash}")
        materialized = tuple(iter_records(txt_path))
        rows = _arff_data_rows(arff_path)
    else:
        txt_hash = arff_hash = None
        materialized = tuple(records or ())
        rows = iter(arff_rows or ())

    inputs = partition_pretest_inputs(materialized, split=split)
    pretest_buckets = set(inputs.train.emitted_buckets) | set(inputs.validation.emitted_buckets)
    values: dict[int, float | None] = {}
    sentinel = object()
    row_count = 0
    row_iterator = iter(rows)
    for record in materialized:
        row = next(row_iterator, sentinel)
        if row is sentinel:
            raise ValueError("ARFF has fewer rows than TXT")
        row_count += 1
        if record.record_index != row_count:
            raise ValueError(f"TXT row index mismatch at row {row_count}")
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        if record.destination == 1 and bucket in pretest_buckets:
            if len(row) != 20:
                raise ValueError(f"ARFF row {row_count} has {len(row)} fields, expected 20")
            try:
                arff_direction = int(row[15])
                timestamp = float(row[16])
                category = int(row[18])
                specific = int(row[19])
            except ValueError as error:
                raise ValueError(f"ARFF alignment field parse failed at row {row_count}") from error
            if (
                arff_direction != 0
                or timestamp != record.timestamp
                or category != record.categorized_attack
                or specific != record.specific_attack
            ):
                raise ValueError(f"TXT/ARFF pre-TEST alignment mismatch at row {row_count}")
            values[record.record_index] = _parse_optional_float(row[13])
    if next(row_iterator, sentinel) is not sentinel:
        raise ValueError("ARFF has more rows than TXT")
    return AlignedPressure(
        values=MappingProxyType(values), row_count=row_count,
        txt_sha256=txt_hash, arff_sha256=arff_hash,
    )


def pressure_feature_names(response_types: Iterable[int]) -> tuple[str, ...]:
    return tuple(
        f"func_{response_type:02x}_pressure_{name}"
        for response_type in sorted(response_types) for name in PRESSURE_FEATURES
    )


def _class_values(
    block: BlockData, aligned: AlignedPressure, type_map: TypeMap,
    mapper: Mapper,
) -> dict[str, list[float]]:
    output = {"normal": [], "dos": []}
    for record in block.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        if bucket not in block.categories or mapper(record, type_map) is None:
            continue
        label = "normal" if block.categories[bucket] == frozenset({0}) else (
            "dos" if DOS_CATEGORY in block.categories[bucket] else None
        )
        value = aligned.values.get(record.record_index)
        if label is not None and value is not None:
            output[label].append(value)
    return output


def _summary(values: Sequence[float]) -> dict[str, float | int | None]:
    if not values:
        return {
            "finite_count": 0, "unique_count": 0, "min": None, "q25": None,
            "median": None, "q75": None, "max": None,
        }
    array = np.asarray(values, dtype=float)
    return {
        "finite_count": len(values), "unique_count": len(set(values)),
        "min": float(array.min()), "q25": float(np.quantile(array, 0.25)),
        "median": float(np.quantile(array, 0.50)),
        "q75": float(np.quantile(array, 0.75)), "max": float(array.max()),
    }


def audit_train_pressure(
    train: BlockData, aligned: AlignedPressure, type_map: TypeMap,
    mapper: Mapper = canonical_response_type,
) -> dict:
    """Audit response pressure using TRAIN labels only; return a frozen gate result."""
    class_values = _class_values(train, aligned, type_map, mapper)
    window_presence = {"normal": [], "dos": []}
    for bucket in train.emitted_buckets:
        categories = train.categories[bucket]
        label = "normal" if categories == frozenset({0}) else (
            "dos" if DOS_CATEGORY in categories else None
        )
        if label is None:
            continue
        present = any(
            aligned.values.get(record.record_index) is not None
            and mapper(record, type_map) is not None
            for record in train.records
            if math.floor(record.timestamp / WINDOW_SECONDS) == bucket
        )
        window_presence[label].append(present)

    reasons = []
    if not class_values["normal"]:
        reasons.append("no usable TRAIN-normal response pressure measurements")
    normal_by_type = {item: 0 for item in sorted(set(type_map.values()))}
    for record in train.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        response_type = mapper(record, type_map)
        if (
            response_type in normal_by_type
            and bucket in train.categories
            and train.categories[bucket] == frozenset({0})
            and aligned.values.get(record.record_index) is not None
        ):
            normal_by_type[response_type] += 1
    missing_baselines = [item for item, count in normal_by_type.items() if not count]
    if missing_baselines:
        formatted = ", ".join(f"0x{item:02x}" for item in missing_baselines)
        reasons.append(f"no TRAIN-normal pressure baseline for {formatted}")
    normal_presence = set(window_presence["normal"])
    dos_presence = set(window_presence["dos"])
    perfect_presence = bool(normal_presence and dos_presence and normal_presence.isdisjoint(dos_presence))
    if perfect_presence:
        reasons.append("pressure presence perfectly separates TRAIN Normal and DoS windows")
    perfect_range = False
    if class_values["normal"] and class_values["dos"]:
        normal_min, normal_max = min(class_values["normal"]), max(class_values["normal"])
        dos_min, dos_max = min(class_values["dos"]), max(class_values["dos"])
        perfect_range = normal_max < dos_min or dos_max < normal_min
        if perfect_range:
            reasons.append("pressure value ranges perfectly separate TRAIN Normal and DoS")
    overlap = len(set(class_values["normal"]) & set(class_values["dos"]))
    return {
        "status": "VALIDATED — PAYLOAD AUDIT PASS" if not reasons else "STOPPED — PAYLOAD GATE",
        "passed": not reasons, "reasons": reasons,
        "population": "TRAIN canonical response frames only",
        "presence_by_window": {
            label: {
                "present": int(sum(flags)), "missing": int(len(flags) - sum(flags)),
                "total": len(flags),
            } for label, flags in window_presence.items()
        },
        "values": {label: _summary(values) for label, values in class_values.items()},
        "exact_value_overlap_count": overlap,
        "perfect_separation_by_presence": perfect_presence,
        "perfect_separation_by_value_range": perfect_range,
    }


def fit_pressure_baselines(
    train: BlockData, aligned: AlignedPressure, type_map: TypeMap,
    mapper: Mapper = canonical_response_type,
) -> Mapping[int, float]:
    """Fit per-type means from TRAIN pure-Normal response measurements only."""
    values: dict[int, list[float]] = {item: [] for item in sorted(set(type_map.values()))}
    for record in train.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        response_type = mapper(record, type_map)
        value = aligned.values.get(record.record_index)
        if (
            response_type in values and value is not None
            and bucket in train.categories
            and train.categories[bucket] == frozenset({0})
        ):
            values[response_type].append(value)
    missing = [response_type for response_type, items in values.items() if not items]
    if missing:
        formatted = ", ".join(f"0x{item:02x}" for item in missing)
        raise ValueError(f"no TRAIN-normal pressure baseline for {formatted}")
    return MappingProxyType({response_type: mean(items) for response_type, items in values.items()})


def build_pressure_features(
    block: BlockData, aligned: AlignedPressure, type_map: TypeMap,
    baselines: Mapping[int, float], mapper: Mapper = canonical_response_type,
) -> Mapping[int, Mapping[str, float]]:
    """Transform one block with frozen baselines and no presence indicator."""
    by_bucket: dict[int, dict[int, list[tuple[float, float]]]] = {}
    for record in block.records:
        bucket = math.floor(record.timestamp / WINDOW_SECONDS)
        response_type = mapper(record, type_map)
        value = aligned.values.get(record.record_index)
        if bucket in block.categories and response_type in baselines and value is not None:
            by_bucket.setdefault(bucket, {}).setdefault(response_type, []).append(
                (record.timestamp, value)
            )
    names = pressure_feature_names(baselines)
    output: dict[int, Mapping[str, float]] = {}
    for bucket in block.emitted_buckets:
        features = {name: 0.0 for name in names}
        for response_type, baseline in baselines.items():
            observations = sorted(by_bucket.get(bucket, {}).get(response_type, ()))
            values = [value for _, value in observations]
            if values:
                first_time, first = observations[0]
                last_time, last = observations[-1]
                elapsed = last_time - first_time
                feature_values = {
                    "last": last, "mean": mean(values), "min": min(values),
                    "max": max(values),
                    "deviation_mean": mean(value - baseline for value in values),
                    "deviation_max_abs": max(abs(value - baseline) for value in values),
                    "rate_of_change": (last - first) / elapsed if elapsed > 0 else 0.0,
                }
            else:
                feature_values = {
                    "last": baseline, "mean": baseline, "min": baseline,
                    "max": baseline, "deviation_mean": 0.0,
                    "deviation_max_abs": 0.0, "rate_of_change": 0.0,
                }
            for name, value in feature_values.items():
                features[f"func_{response_type:02x}_pressure_{name}"] = float(value)
        output[bucket] = MappingProxyType(features)
    return MappingProxyType(output)


def prepare_pressure_artifacts(
    train: BlockData, validation: BlockData, type_map: TypeMap,
    *, records: Sequence[FrameRecord] | None = None,
    arff_rows: Iterable[Sequence[str]] | None = None,
    mapper: Mapper = canonical_response_type,
) -> PressureArtifacts:
    aligned = align_pretest_pressure(records, arff_rows)
    audit = audit_train_pressure(train, aligned, type_map, mapper)
    if not audit["passed"]:
        return PressureArtifacts(
            aligned, MappingProxyType(audit), MappingProxyType({}),
            pressure_feature_names(sorted(set(type_map.values()))),
            MappingProxyType({}), MappingProxyType({}),
        )
    baselines = fit_pressure_baselines(train, aligned, type_map, mapper)
    return PressureArtifacts(
        aligned=aligned, audit=MappingProxyType(audit), baselines=baselines,
        feature_names=pressure_feature_names(baselines),
        train_features=build_pressure_features(train, aligned, type_map, baselines, mapper),
        validation_features=build_pressure_features(
            validation, aligned, type_map, baselines, mapper,
        ),
    )
