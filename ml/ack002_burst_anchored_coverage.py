#!/usr/bin/env python3
"""ACK-002 — burst-level feasibility check for an ack-anchored consequence detector.

FEASIBILITY CHECK ONLY. No classifier, detector, rule or threshold is built or
scored here — counting and coverage statistics only. `run_detector`,
`iforest_detector.py`, `rules.py`, Layer A, `app.py`, DoS files and CMRI's closed
files are not touched. `features_windowed.build_windows`/`Window` are imported
read-only (via `exp0021_msci_mpci.Blocks`) for the bucket-category lookup only, same
as ACK-001.

ACK-001 found per-write consequence attribution structurally impossible: write-acks
and pressure-reads share a ~3.4s median cadence, so the next write almost always
arrives before enough pressure samples accumulate to observe an individual write's
consequence (censoring-aware scorability was exactly 0.00% at every horizon). This
script asks a different, cheaper question: instead of "what happened after THIS
write," does a clean observation window exist after an entire BURST of writes ends,
before the next burst begins?

Design under test (not built here): merge consecutive observable egress `0x10`
write-acks (legitimate and malicious alike — a real deployment cannot see attack
labels) into bursts using a gap threshold that is derived WITHOUT looking at attack
labels (3x the median inter-ack gap, fixed before any label-based outcome is
examined — not a value search over what best separates attack from normal). Then
measure, for each completed burst, how many egress `0x03` pressure-response samples
arrive strictly after the burst ends and strictly before the next burst begins (or
before end-of-scope). Labels are applied only at reporting time.

`source` is never parsed, bound, filtered on, or used anywhere in this file. Egress
is `destination == 1` only. TRAIN/VALIDATION boundaries come only from the corrected
manifest `verified-egress-5s-exp0008-pretest-v1` via `exp0021_msci_mpci.Blocks`.
TEST is not read.
"""
from __future__ import annotations

import json
import os
import platform
from importlib.metadata import version
from pathlib import Path

import numpy as np

from ack001_ack_anchored_coverage import (
    Ack,
    Scan,
    _is_request,
    bucket_of,
    count_in_range,
    is_ack,
    is_pressure_response,
)
from exp0009_payload import ARFF_SHA256, RAW_ARFF, TXT_SHA256, _arff_data_rows, _sha256
from exp0017_operational import load_result
from exp0021_msci_mpci import Blocks, EXP0017_TEST_CONFUSION
from features_txt import RAW_TXT

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments" / "ack002_coverage.json"
)

CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
CATEGORY_INDEX = {name: i for i, name in enumerate(CATEGORY_NAMES)}

# pre-registered stopping rule
INFEASIBLE_MAJORITY_THRESHOLD = 0.5
GAP_THRESHOLD_MULTIPLE = 3.0
MIN_CLEAN_SAMPLES_FOR_COVERAGE = 2


def scan_acks_and_pressure(blocks: Blocks, *, txt_path: Path = RAW_TXT,
                            arff_path: Path = RAW_ARFF) -> Scan:
    """Identical scan to ACK-001's (re-used, not re-implemented separately, to avoid
    two independently-buggy copies of the alignment/shape logic). Re-imported here
    unchanged rather than duplicated."""
    if _sha256(txt_path) != TXT_SHA256:
        raise ValueError("TXT sha256 mismatch")
    if _sha256(arff_path) != ARFF_SHA256:
        raise ValueError("ARFF sha256 mismatch")

    scope = blocks.train | blocks.validation
    scan = Scan()
    rows = iter(_arff_data_rows(arff_path))
    sentinel = object()
    row_count = 0
    with txt_path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) != 6:
                continue
            hexframe, cat, spec, src, dst, ts_s = parts
            try:
                frame = bytes.fromhex(hexframe)
                ts = float(ts_s)
                cat_i, spec_i = int(cat), int(spec)
                dst_i = int(dst)
            except ValueError:
                continue
            row = next(rows, sentinel)
            if row is sentinel:
                raise ValueError("ARFF has fewer rows than TXT")
            row_count += 1
            if dst_i != 1:
                continue
            if len(row) != 20:
                raise ValueError(f"ARFF row {row_count} has {len(row)} fields, expected 20")
            if (int(row[15]) != 0 or float(row[16]) != ts
                    or int(row[18]) != cat_i or int(row[19]) != spec_i):
                raise ValueError(f"TXT/ARFF alignment mismatch at row {row_count}")
            scan.egress_rows += 1

            n = len(frame)
            if n < 2:
                continue
            func = frame[1]
            is_req = _is_request(frame)

            bucket = bucket_of(ts)
            if bucket not in scope:
                continue

            if is_ack(func, n, is_req):
                scan.egress_acks += 1
                scan.acks.append(Ack(ts=ts, bucket=bucket, cat=cat_i, spec=spec_i))
            elif is_pressure_response(func, n, is_req):
                scan.egress_pressure += 1
                scan.pressure_ts.append(ts)
        if next(rows, sentinel) is not sentinel:
            raise ValueError("ARFF has more rows than TXT")

    scan.acks.sort(key=lambda a: a.ts)
    scan.pressure_ts.sort()
    return scan


# --------------------------------------------------------------- gap distribution (label-blind)

def inter_ack_gaps(acks: list[Ack]) -> np.ndarray:
    """Gaps between consecutive acks by timestamp, unlabeled. Empty array if <2 acks."""
    if len(acks) < 2:
        return np.array([], dtype=float)
    ts = np.array([a.ts for a in acks], dtype=float)
    return np.diff(ts)


def gap_distribution_summary(gaps: np.ndarray) -> dict:
    if gaps.size == 0:
        return {"n_gaps": 0}
    return {
        "n_gaps": int(gaps.size),
        "median": float(np.median(gaps)),
        "mean": float(np.mean(gaps)),
        "p50": float(np.percentile(gaps, 50)),
        "p75": float(np.percentile(gaps, 75)),
        "p90": float(np.percentile(gaps, 90)),
        "p95": float(np.percentile(gaps, 95)),
        "p99": float(np.percentile(gaps, 99)),
        "max": float(np.max(gaps)),
        "min": float(np.min(gaps)),
    }


def derive_gap_threshold(gaps: np.ndarray, *, multiple: float = GAP_THRESHOLD_MULTIPLE) -> float:
    """Label-blind: threshold is a fixed multiple of the median inter-ack gap,
    computed over ALL acks regardless of label. Chosen before examining any
    label-based outcome, not fitted to maximize attack/normal separation."""
    if gaps.size == 0:
        raise ValueError("cannot derive a gap threshold with fewer than 2 acks")
    return float(multiple * np.median(gaps))


# --------------------------------------------------------------- burst construction

class Burst:
    __slots__ = ("acks", "start", "end")

    def __init__(self, acks: list[Ack]):
        self.acks = acks
        self.start = acks[0].ts
        self.end = acks[-1].ts

    @property
    def n_acks(self) -> int:
        return len(self.acks)

    @property
    def duration(self) -> float:
        return self.end - self.start

    @property
    def cats(self) -> set[int]:
        return {a.cat for a in self.acks}


def merge_bursts(acks: list[Ack], threshold: float) -> list[Burst]:
    """Merge consecutive acks (sorted by ts, any label) into bursts: a new burst
    starts whenever the gap to the previous ack exceeds `threshold`. Acks with an
    exactly-threshold gap merge into the SAME burst (<=, not <)."""
    if not acks:
        return []
    bursts: list[Burst] = []
    current = [acks[0]]
    for prev, cur in zip(acks, acks[1:]):
        gap = cur.ts - prev.ts
        if gap <= threshold:
            current.append(cur)
        else:
            bursts.append(Burst(current))
            current = [cur]
    bursts.append(Burst(current))
    return bursts


# --------------------------------------------------------------- post-burst window

def post_burst_clean_count(burst_end: float, window_end: float,
                            pressure_ts: list[float]) -> int:
    """Pressure samples strictly after burst_end and strictly before window_end."""
    return count_in_range(pressure_ts, burst_end, window_end,
                           lo_inclusive=False, hi_inclusive=False)


def burst_windows(bursts: list[Burst], scope_end: float) -> list[tuple[Burst, float]]:
    """Pairs each burst with the timestamp its uncontaminated window ends at: the
    next burst's start, or scope_end for the last burst. Every burst here is
    'completed' per the pre-registration (reaching end-of-scope is a real boundary,
    not contamination)."""
    out = []
    for i, b in enumerate(bursts):
        window_end = bursts[i + 1].start if i + 1 < len(bursts) else scope_end
        out.append((b, window_end))
    return out


# --------------------------------------------------------------- reporting

def _pct(n: int, d: int) -> float | None:
    return None if d == 0 else 100.0 * n / d


def summarise_group(name: str, entries: list[tuple[Burst, int, float]]) -> dict:
    """entries: (burst, clean_sample_count, window_duration) tuples for one group."""
    n = len(entries)
    if n == 0:
        return {"n_bursts": 0, "note": f"no {name} bursts observed in TRAIN+VAL"}
    counts = [c for _, c, _ in entries]
    durations = [d for _, _, d in entries]
    ge1 = sum(1 for c in counts if c >= 1)
    ge2 = sum(1 for c in counts if c >= 2)
    ge3 = sum(1 for c in counts if c >= 3)
    return {
        "n_bursts": n,
        "pct_with_ge1_clean_sample": _pct(ge1, n),
        "pct_with_ge2_clean_sample": _pct(ge2, n),
        "pct_with_ge3_clean_sample": _pct(ge3, n),
        "median_clean_sample_count": float(np.median(counts)),
        "median_window_duration_seconds": float(np.median(durations)),
        "mean_clean_sample_count": float(np.mean(counts)),
        "mean_window_duration_seconds": float(np.mean(durations)),
    }


def composition_summary(entries: list[tuple[Burst, int, float]]) -> dict:
    """Supporting evidence, not part of the pre-registered stopping rule: how
    heterogeneous is each burst in this group (ack count, category mix)? A burst
    with hundreds of acks spanning multiple categories cannot have its post-burst
    pressure sample attributed to any single write within it — this quantifies
    that caveat directly rather than leaving it implicit."""
    n = len(entries)
    if n == 0:
        return {"n_bursts": 0}
    ack_counts = [b.n_acks for b, _, _ in entries]
    n_multi_category = sum(1 for b, _, _ in entries if len(b.cats) > 1)
    n_contains_normal = sum(1 for b, _, _ in entries
                             if CATEGORY_INDEX["Normal"] in b.cats)
    return {
        "n_bursts": n,
        "median_acks_per_burst": float(np.median(ack_counts)),
        "mean_acks_per_burst": float(np.mean(ack_counts)),
        "max_acks_per_burst": float(np.max(ack_counts)),
        "pct_bursts_spanning_multiple_categories": _pct(n_multi_category, n),
        "pct_bursts_also_containing_normal": _pct(n_contains_normal, n),
    }


def stopping_rule_verdict(by_group: dict) -> dict:
    """Pre-registered rule: >50% of MSCI- or MPCI-containing bursts with fewer than
    2 uncontaminated post-burst pressure samples -> flag likely infeasible."""
    verdicts = {}
    for name in ("MSCI_containing", "MPCI_containing"):
        g = by_group.get(name, {})
        n = g.get("n_bursts", 0)
        if n == 0:
            verdicts[name] = {"verdict": "INFEASIBLE (no data)",
                               "reason": "no such bursts observed in TRAIN+VAL"}
            continue
        pct_ge2 = g.get("pct_with_ge2_clean_sample") or 0.0
        pct_below_2 = 100.0 - pct_ge2
        flagged = pct_below_2 >= (INFEASIBLE_MAJORITY_THRESHOLD * 100.0)
        verdicts[name] = {
            "verdict": "LIKELY INFEASIBLE" if flagged else "not flagged by this rule",
            "pct_bursts_with_ge2_clean_samples": pct_ge2,
            "pct_bursts_with_fewer_than_2_clean_samples": pct_below_2,
            "n_bursts": n,
        }
    return verdicts


# --------------------------------------------------------------- main

def run_experiment() -> dict:
    # ---- identity gate: EXP-0017 reproduced from its checksummed artifact ----
    result = load_result()
    comb = np.array(result.protocol_pred) | np.array(result.pressure_pred) | np.array(result.if_pred)
    assert np.array_equal(comb, np.array(result.comb_pred)), "comb reproduction mismatch"
    y = np.array(result.y_test)
    tn = int(np.sum((comb == 0) & (y == 0)))
    fp = int(np.sum((comb == 1) & (y == 0)))
    fn = int(np.sum((comb == 0) & (y == 1)))
    tp = int(np.sum((comb == 1) & (y == 1)))
    identity_ok = (tn, fp, fn, tp) == EXP0017_TEST_CONFUSION
    if not identity_ok:
        raise ValueError(f"EXP-0017 identity gate FAILED: got {(tn, fp, fn, tp)}, "
                          f"expected {EXP0017_TEST_CONFUSION}")

    blocks = Blocks()
    scan = scan_acks_and_pressure(blocks)

    # ---- label-blind gap threshold ----
    gaps = inter_ack_gaps(scan.acks)
    gap_summary = gap_distribution_summary(gaps)
    threshold = derive_gap_threshold(gaps)

    # ---- burst construction (still label-blind) ----
    bursts = merge_bursts(scan.acks, threshold)
    scope_end = scan.pressure_ts[-1] if scan.pressure_ts else (scan.acks[-1].ts if scan.acks else 0.0)
    scope_end = max(scope_end, scan.acks[-1].ts if scan.acks else 0.0)
    windows = burst_windows(bursts, scope_end)

    # ---- labels applied only now, for reporting ----
    msci_id, mpci_id, normal_id = CATEGORY_INDEX["MSCI"], CATEGORY_INDEX["MPCI"], CATEGORY_INDEX["Normal"]
    groups: dict[str, list[tuple[Burst, int, float]]] = {
        "MSCI_containing": [], "MPCI_containing": [], "Normal_only": [],
    }
    for b, window_end in windows:
        cnt = post_burst_clean_count(b.end, window_end, scan.pressure_ts)
        dur = window_end - b.end
        cats = b.cats
        if msci_id in cats:
            groups["MSCI_containing"].append((b, cnt, dur))
        if mpci_id in cats:
            groups["MPCI_containing"].append((b, cnt, dur))
        if cats == {normal_id}:
            groups["Normal_only"].append((b, cnt, dur))

    by_group = {name: summarise_group(name, entries) for name, entries in groups.items()}
    composition_by_group = {name: composition_summary(entries) for name, entries in groups.items()}

    all_ack_counts = np.array([b.n_acks for b in bursts], dtype=float)
    all_durations = np.array([b.duration for b in bursts], dtype=float)

    summary = {
        "experiment": "ACK-002",
        "status": "TESTED",
        "identity_gates": {
            "exp0017_reproduced": identity_ok,
            "exp0017_confusion": [tn, fp, fn, tp],
            "expected_confusion": list(EXP0017_TEST_CONFUSION),
            "split_id": blocks.split_id,
            "split_sha256": blocks.split_sha256,
        },
        "scan_counts": {
            "egress_rows_train_val_scope_plus_out_of_scope": scan.egress_rows,
            "egress_acks_in_scope": scan.egress_acks,
            "egress_pressure_responses_in_scope": scan.egress_pressure,
        },
        "gap_threshold_derivation": {
            "method": "label_blind_fixed_multiple_of_median",
            "multiple": GAP_THRESHOLD_MULTIPLE,
            "inter_ack_gap_distribution_seconds_all_labels": gap_summary,
            "derived_threshold_seconds": threshold,
        },
        "burst_construction": {
            "n_bursts_total": len(bursts),
            "burst_ack_count_summary": {
                "median": float(np.median(all_ack_counts)) if all_ack_counts.size else None,
                "mean": float(np.mean(all_ack_counts)) if all_ack_counts.size else None,
                "max": float(np.max(all_ack_counts)) if all_ack_counts.size else None,
                "pct_single_ack_bursts": _pct(int(np.sum(all_ack_counts == 1)), len(bursts)),
            },
            "burst_duration_seconds_summary": {
                "median": float(np.median(all_durations)) if all_durations.size else None,
                "mean": float(np.mean(all_durations)) if all_durations.size else None,
                "max": float(np.max(all_durations)) if all_durations.size else None,
            },
        },
        "decision_criterion": {
            "min_clean_samples_for_coverage": MIN_CLEAN_SAMPLES_FOR_COVERAGE,
            "majority_threshold": INFEASIBLE_MAJORITY_THRESHOLD,
        },
        "by_group": by_group,
        "composition_by_group": composition_by_group,
        "environment": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
        },
    }
    summary["stopping_rule_verdict"] = stopping_rule_verdict(by_group)
    return summary


# --------------------------------------------------------------- I/O

def _json_ready(value):
    if isinstance(value, dict):
        return {str(k): _json_ready(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_json_ready(v) for v in value]
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, np.ndarray):
        return _json_ready(value.tolist())
    return value


def write_result_atomic(result, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with tmp.open("w") as fh:
        json.dump(_json_ready(result), fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def main() -> None:
    result = run_experiment()
    write_result_atomic(result)
    print(json.dumps(_json_ready(result), indent=2, sort_keys=True)[:6000])


if __name__ == "__main__":
    main()
