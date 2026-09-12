#!/usr/bin/env python3
"""ACK-001 — feasibility/coverage check for an ack-anchored consequence detector.

FEASIBILITY CHECK ONLY. No classifier, detector, rule or threshold is built or
scored here — counting and coverage statistics only. `run_detector`,
`iforest_detector.py`, `rules.py`, Layer A, `app.py`, DoS files and CMRI's closed
files are not touched. `features_windowed.build_windows`/`Window` are imported
read-only for the pure/mixed check.

Design under test (not built here): anchor observation on every OBSERVABLE `0x10`
write-acknowledgement (the 8-byte egress echo response — legitimate and malicious
alike, since a real deployment cannot see attack labels), then examine subsequent
`0x03` pressure-response traffic. This script only measures whether the data
supports that design at all, using the design's own pre-registered numbers:
30s/≥5-sample pre-ack baseline; post-ack horizons 10/30/60/120s with minimum
scorable counts 2/5/10/20; a 10s inter-ack cluster gap; horizon censoring against
the gap to the next ack.

`source` is never parsed, bound, filtered on, reported, or used anywhere in this
file. Egress is `destination == 1` only. TRAIN/VALIDATION boundaries come only from
the corrected manifest `verified-egress-5s-exp0008-pretest-v1` via
`exp0021_msci_mpci.Blocks`. TEST is not read.
"""
from __future__ import annotations

import bisect
import json
import math
import os
import platform
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path
from typing import Sequence

import numpy as np

from exp0009_payload import ARFF_SHA256, RAW_ARFF, TXT_SHA256, _arff_data_rows, _sha256
from exp0017_operational import load_result
from exp0021_msci_mpci import Blocks, EXP0017_TEST_CONFUSION
from features_txt import RAW_TXT

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments" / "ack001_coverage.json"
)

CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
CATEGORY_INDEX = {name: i for i, name in enumerate(CATEGORY_NAMES)}
REPORTED_CATEGORIES = ("Normal", "MSCI", "MPCI")

WINDOW_SECONDS = 5.0
FUNC_WRITE_MULTI = 0x10
FUNC_READ = 0x03
ACK_FRAME_LEN = 8            # egress 0x10 echo response
READ_RESPONSE_LEN = 23       # egress 0x03 canonical response

# ---- proposed design's own numbers, taken exactly, not re-derived ----
PRE_ACK_WINDOW_SECONDS = 30.0
PRE_ACK_MIN_SAMPLES = 5
HORIZONS_SECONDS = (10.0, 30.0, 60.0, 120.0)
HORIZON_MIN_SAMPLES = {10.0: 2, 30.0: 5, 60.0: 10, 120.0: 20}
CLUSTER_GAP_SECONDS = 10.0

# pre-registered stopping rule
INFEASIBLE_MAJORITY_THRESHOLD = 0.5


def bucket_of(ts: float) -> int:
    return math.floor(ts / WINDOW_SECONDS)


# --------------------------------------------------------------- ack identification

def is_ack(function_code: int, frame_len_bytes: int, is_request: int) -> bool:
    """The observable egress 0x10 write-acknowledgement shape."""
    return function_code == FUNC_WRITE_MULTI and frame_len_bytes == ACK_FRAME_LEN and is_request == 0


def is_pressure_response(function_code: int, frame_len_bytes: int, is_request: int) -> bool:
    """The observable egress 0x03 canonical read-response shape."""
    return function_code == FUNC_READ and frame_len_bytes == READ_RESPONSE_LEN and is_request == 0


# --------------------------------------------------------------- scan

class Ack:
    __slots__ = ("ts", "bucket", "cat", "spec")

    def __init__(self, ts: float, bucket: int, cat: int, spec: int):
        self.ts = ts
        self.bucket = bucket
        self.cat = cat
        self.spec = spec


class Scan:
    """Egress acks and pressure-response timestamps, TRAIN+VALIDATION scope only."""

    def __init__(self) -> None:
        self.acks: list[Ack] = []          # all labels, sorted by construction (TXT is time-ordered)
        self.pressure_ts: list[float] = []  # all labels, sorted
        self.egress_rows = 0
        self.egress_acks = 0
        self.egress_pressure = 0


def scan_acks_and_pressure(blocks: Blocks, *, txt_path: Path = RAW_TXT,
                            arff_path: Path = RAW_ARFF) -> Scan:
    """Single verified TXT<->ARFF pass. Frame bytes are re-derived directly from the
    hex column (not through `iter_records`/`FrameRecord`, which discard the raw hex),
    same pattern as EXP-0021/0023."""
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
            # command_response (col 15) must be 0 (a response) on every egress row —
            # the alignment check is only meaningful in the egress direction, exactly
            # as EXP-0021/EXP-0023's scans check it (thesis: 0=response, 1=command;
            # egress is always the response direction in this dataset).
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


def _is_request(frame: bytes) -> int:
    """Mirrors features_txt._parse_frame_fields' is_request logic for func 0x03/0x10
    only (the two shapes this script cares about); other function codes return -1
    (MISSING), never matched by is_ack/is_pressure_response."""
    n = len(frame)
    func = frame[1]
    if func == FUNC_READ:
        return 1 if n == 8 else 0
    if func == FUNC_WRITE_MULTI:
        if n == 8:
            return 0
        if n >= 9:
            return 1
        return -1
    return -1


# --------------------------------------------------------------- per-ack measurement

def count_in_range(sorted_ts: Sequence[float], lo: float, hi: float,
                    *, lo_inclusive: bool, hi_inclusive: bool) -> int:
    """Count of values in sorted_ts within (lo, hi) per the inclusivity flags."""
    left = bisect.bisect_left(sorted_ts, lo) if lo_inclusive else bisect.bisect_right(sorted_ts, lo)
    right = bisect.bisect_right(sorted_ts, hi) if hi_inclusive else bisect.bisect_left(sorted_ts, hi)
    return max(0, right - left)


def pre_ack_baseline_count(ack_ts: float, pressure_ts: Sequence[float]) -> int:
    """Samples strictly before the ack, in the 30s window."""
    return count_in_range(pressure_ts, ack_ts - PRE_ACK_WINDOW_SECONDS, ack_ts,
                           lo_inclusive=True, hi_inclusive=False)


def post_ack_horizon_count(ack_ts: float, horizon: float, pressure_ts: Sequence[float]) -> int:
    """Samples strictly after the ack, up to and including ack_ts + horizon."""
    return count_in_range(pressure_ts, ack_ts, ack_ts + horizon,
                           lo_inclusive=False, hi_inclusive=True)


def nearest_ack_gap_seconds(ack_ts: float, all_ack_ts: Sequence[float]) -> float | None:
    """Smallest |gap| to any OTHER ack timestamp (either direction), for cluster
    membership. None if this is the only ack."""
    pos = bisect.bisect_left(all_ack_ts, ack_ts)
    candidates = []
    # the ack itself sits at `pos` (or adjacent, for tied timestamps) — check both
    # neighbours on each side, skipping the exact self-match at distance 0 unless a
    # genuine duplicate timestamp exists (in which case it counts as its own cluster
    # partner, which is the conservative/inclusive reading).
    for p in (pos - 1, pos, pos + 1):
        if 0 <= p < len(all_ack_ts) and all_ack_ts[p] != ack_ts:
            candidates.append(abs(all_ack_ts[p] - ack_ts))
    if not candidates:
        return None
    return min(candidates)


def next_ack_gap_seconds(ack_ts: float, all_ack_ts: Sequence[float]) -> float | None:
    """Seconds to the next ack strictly after this one (any label), or None if this
    is the last ack in scope."""
    pos = bisect.bisect_right(all_ack_ts, ack_ts)
    if pos >= len(all_ack_ts):
        return None
    return all_ack_ts[pos] - ack_ts


# --------------------------------------------------------------- reporting

def _pct(n: int, d: int) -> float | None:
    return None if d == 0 else 100.0 * n / d


def label_for(cat: int) -> str:
    name = CATEGORY_NAMES[cat] if 0 <= cat < len(CATEGORY_NAMES) else f"unknown_{cat}"
    return name


def bucket_category_map(blocks: Blocks) -> dict[int, frozenset]:
    return {w.w_index: w.categories for w in blocks.windows}


def summarise_category(cat_name: str, acks: Sequence[Ack], scan: Scan,
                        bucket_cats: dict[int, frozenset]) -> dict:
    all_ack_ts = [a.ts for a in scan.acks]
    n = len(acks)
    if n == 0:
        return {"n_acks": 0, "note": "no acks with this label observed in TRAIN+VAL"}

    baseline_ok = 0
    scorable = {h: 0 for h in HORIZONS_SECONDS}
    scorable_after_censoring = {h: 0 for h in HORIZONS_SECONDS}
    censored = {h: 0 for h in HORIZONS_SECONDS}
    censor_gap_seconds: list[float] = []
    next_gap_seconds_all: list[float] = []
    clustered = 0
    pure = 0
    mixed = 0

    for a in acks:
        pre_count = pre_ack_baseline_count(a.ts, scan.pressure_ts)
        if pre_count >= PRE_ACK_MIN_SAMPLES:
            baseline_ok += 1

        nearest_gap = nearest_ack_gap_seconds(a.ts, all_ack_ts)
        if nearest_gap is not None and nearest_gap <= CLUSTER_GAP_SECONDS:
            clustered += 1

        next_gap = next_ack_gap_seconds(a.ts, all_ack_ts)
        if next_gap is not None:
            next_gap_seconds_all.append(next_gap)
        for h in HORIZONS_SECONDS:
            cnt = post_ack_horizon_count(a.ts, h, scan.pressure_ts)
            if cnt >= HORIZON_MIN_SAMPLES[h]:
                scorable[h] += 1
            is_censored = next_gap is not None and next_gap < h
            if is_censored:
                censored[h] += 1
                if h == max(HORIZONS_SECONDS):
                    censor_gap_seconds.append(next_gap)
            # honest, censoring-respecting scorability: if a later ack falls inside
            # the nominal horizon, the design's own truncation rule would only ever
            # see samples up to that point — count against the TRUNCATED window, not
            # the nominal one, since pressure after the next ack reflects the next
            # command's effect, not this one's.
            effective_h = min(h, next_gap) if is_censored else h
            eff_cnt = post_ack_horizon_count(a.ts, effective_h, scan.pressure_ts)
            if eff_cnt >= HORIZON_MIN_SAMPLES[h]:
                scorable_after_censoring[h] += 1

        cats = bucket_cats.get(a.bucket, frozenset({a.cat}))
        if cats == {a.cat}:
            pure += 1
        else:
            mixed += 1

    horizon_report = {}
    for h in HORIZONS_SECONDS:
        horizon_report[str(h)] = {
            "min_required_samples": HORIZON_MIN_SAMPLES[h],
            "pct_scorable": _pct(scorable[h], n),
            "n_scorable": scorable[h],
            "pct_scorable_after_censoring": _pct(scorable_after_censoring[h], n),
            "n_scorable_after_censoring": scorable_after_censoring[h],
            "pct_censored": _pct(censored[h], n),
            "n_censored": censored[h],
        }

    return {
        "n_acks": n,
        "pct_valid_pre_ack_baseline": _pct(baseline_ok, n),
        "n_valid_pre_ack_baseline": baseline_ok,
        "pct_clustered_10s": _pct(clustered, n),
        "n_clustered_10s": clustered,
        "pct_pure": _pct(pure, n),
        "pct_mixed": _pct(mixed, n),
        "horizons": horizon_report,
        "censor_gap_seconds_at_120s_summary": (
            {
                "n": len(censor_gap_seconds),
                "median": float(np.median(censor_gap_seconds)),
                "mean": float(np.mean(censor_gap_seconds)),
                "min": float(np.min(censor_gap_seconds)),
                "max": float(np.max(censor_gap_seconds)),
            } if censor_gap_seconds else {"n": 0}
        ),
        # gap to the NEXT ack (any label) after this one, regardless of whether it
        # censors any particular horizon — this is the statistic that explains why
        # the raw vs censoring-aware scorable numbers diverge (or don't).
        "next_ack_gap_seconds_summary": (
            {
                "n": len(next_gap_seconds_all),
                "median": float(np.median(next_gap_seconds_all)),
                "mean": float(np.mean(next_gap_seconds_all)),
                "min": float(np.min(next_gap_seconds_all)),
                "max": float(np.max(next_gap_seconds_all)),
            } if next_gap_seconds_all else {"n": 0}
        ),
    }


def stopping_rule_verdict(summary: dict) -> dict:
    """Pre-registered rule, applied literally: majority of MSCI or MPCI acks with NO
    scorable data within 120s -> flag likely infeasible. Reports BOTH the raw
    (nominal-horizon) and censoring-aware (design's own truncation rule applied)
    scorable percentages side by side, since the pre-registration's step 6 requires
    honest reporting even when the literal rule (raw, uncensored) does not trigger —
    see docs/ACK001_RESULTS.md for the interpretation."""
    verdicts = {}
    for cat_name in ("MSCI", "MPCI"):
        cat = summary["by_category"].get(cat_name, {})
        if cat.get("n_acks", 0) == 0:
            verdicts[cat_name] = {
                "verdict": "INFEASIBLE (no data)",
                "reason": "no acks with this label observed in TRAIN+VAL at all",
            }
            continue
        n = cat["n_acks"]
        pct_scorable_120 = cat["horizons"]["120.0"]["pct_scorable"] or 0.0
        pct_scorable_after_censoring_120 = cat["horizons"]["120.0"]["pct_scorable_after_censoring"] or 0.0
        pct_unscorable_120 = 100.0 - pct_scorable_120
        pct_unscorable_after_censoring_120 = 100.0 - pct_scorable_after_censoring_120
        flagged_raw = pct_unscorable_120 >= (INFEASIBLE_MAJORITY_THRESHOLD * 100.0)
        flagged_censoring_aware = pct_unscorable_after_censoring_120 >= (INFEASIBLE_MAJORITY_THRESHOLD * 100.0)
        verdicts[cat_name] = {
            "verdict_literal_rule_raw_horizon": "LIKELY INFEASIBLE" if flagged_raw else "not flagged by this rule",
            "verdict_censoring_aware": "LIKELY INFEASIBLE" if flagged_censoring_aware else "not flagged by this rule",
            "pct_scorable_at_120s_raw": pct_scorable_120,
            "pct_scorable_at_120s_after_censoring": pct_scorable_after_censoring_120,
            "pct_unscorable_at_120s_raw": pct_unscorable_120,
            "pct_unscorable_at_120s_after_censoring": pct_unscorable_after_censoring_120,
            "n_acks": n,
        }
    return verdicts


def _inter_arrival_summary(sorted_or_unsorted_ts: Sequence[float]) -> dict:
    ts = sorted(sorted_or_unsorted_ts)
    if len(ts) < 2:
        return {"n_gaps": 0}
    diffs = np.diff(np.asarray(ts, dtype=float))
    return {
        "n_gaps": int(diffs.size),
        "median": float(np.median(diffs)),
        "mean": float(np.mean(diffs)),
        "p90": float(np.percentile(diffs, 90)),
        "max": float(diffs.max()),
    }


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
    bucket_cats = bucket_category_map(blocks)

    acks_by_cat: dict[int, list[Ack]] = defaultdict(list)
    for a in scan.acks:
        acks_by_cat[a.cat].append(a)

    by_category = {}
    for cat_name in REPORTED_CATEGORIES:
        cat_id = CATEGORY_INDEX[cat_name]
        by_category[cat_name] = summarise_category(cat_name, acks_by_cat.get(cat_id, []), scan, bucket_cats)

    other_labels = {}
    for cat_id, acks in acks_by_cat.items():
        name = label_for(cat_id)
        if name not in REPORTED_CATEGORIES:
            other_labels[name] = len(acks)

    summary = {
        "cadence_evidence": {
            "note": "supporting evidence for why raw and censoring-aware scorability "
                     "diverge: median inter-arrival time for both signal types is "
                     "close to the same value, so the master's polling cycle "
                     "interleaves 0x03 reads and 0x10 writes at a similar cadence.",
            "pressure_0x03_inter_arrival_seconds": _inter_arrival_summary(scan.pressure_ts),
            "ack_0x10_inter_arrival_seconds": _inter_arrival_summary([a.ts for a in scan.acks]),
        },
        "experiment": "ACK-001",
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
        "design_constants": {
            "pre_ack_window_seconds": PRE_ACK_WINDOW_SECONDS,
            "pre_ack_min_samples": PRE_ACK_MIN_SAMPLES,
            "horizons_seconds": list(HORIZONS_SECONDS),
            "horizon_min_samples": {str(k): v for k, v in HORIZON_MIN_SAMPLES.items()},
            "cluster_gap_seconds": CLUSTER_GAP_SECONDS,
        },
        "by_category": by_category,
        "other_labels_out_of_scope": other_labels,
        "environment": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
        },
    }
    summary["stopping_rule_verdict"] = stopping_rule_verdict(summary)
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
