"""EXP-0017 guarded evaluation and checksummed, non-executable result replay.

Extends the exact-confirmation pattern in exp0008_cadence.score_frozen_test_once;
an exclusive attempt ledger additionally prevents accidental repeat scoring.
ARFF-row-aligned pressure is NOT a live packet-byte decode.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
from importlib.metadata import version

import numpy as np

from exp0008_cadence_features import load_pretest_split, GUARD_WINDOWS
from features_windowed import CATEGORY_NAMES, Window
from iforest_detector import DetectorResult
from rules import RuleHit

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data/experiments/exp0017_detector.json"
ATTEMPT_PATH = ROOT / "data/experiments/exp0017_test_attempt.json"
CONFIRMATION = "SCORE-EXP-0017-FROZEN-TEST-ONCE"
LIMITATION = ("Pressure uses ARFF 'pressure measurement' row-aligned to TXT canonical "
              "0x03 responses, NOT live packet-byte decoding. Register map/scale is "
              "undocumented; bounds are empirical TRAIN-normal extrema. Offline "
              "simulated data-diode view; one testbed.")


def begin_evaluation(confirmation: str) -> None:
    if confirmation != CONFIRMATION:
        raise PermissionError("EXP-0017 TEST requires the exact explicit confirmation token")
    load_pretest_split()  # reject an invalid manifest before consuming the attempt
    if RESULT_PATH.exists():
        raise FileExistsError("EXP-0017 output exists; TEST must not be rescored")
    ATTEMPT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ATTEMPT_PATH.open("x", encoding="utf-8") as out:
        json.dump({"experiment": "EXP-0017", "status": "IMPLEMENTED — attempt consumed",
                   "started_utc": datetime.now(timezone.utc).isoformat(),
                   "authorization": "User explicitly approved one guarded EXP-0017 evaluation"}, out)


def manifest_indices(windows):
    split = load_pretest_split()
    ids = [w.w_index for w in windows]
    if ids != sorted(set(ids)):
        raise ValueError("window IDs must be unique and chronological")
    lookup = {b: i for i, b in enumerate(ids)}
    try:
        train = np.array([lookup[b] for b in split.train_bucket_ids], dtype=int)
        val = np.array([lookup[b] for b in split.validation_bucket_ids], dtype=int)
    except KeyError as exc:
        raise ValueError("missing manifest bucket") from exc
    # Identical to the existing guarded _test_block: skip two eligible buckets.
    test = np.array([i for i, b in enumerate(ids) if b > split.final_pretest_bucket_id]
                    [2 * GUARD_WINDOWS:], dtype=int)
    return split, train, val, test


def _plain(value):
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, np.ndarray):
        return _plain(value.tolist())
    if isinstance(value, (list, tuple, frozenset)):
        return [_plain(v) for v in (sorted(value) if isinstance(value, frozenset) else value)]
    if isinstance(value, np.generic):
        return value.item()
    return value


def _encoded(value):
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def summarize(result):
    old = result.protocol_pred | result.if_pred
    cm = result.metrics(result.comb_pred)
    old_cm = result.metrics(old)
    checks = {
        "threshold": result.threshold == 0.6745465823488428,
        "pressure_bounds": tuple(result.pressure_bounds) == (0.482759, 38.7471),
        "historical_confusion": [int(old_cm[k]) for k in ("tn", "fp", "fn", "tp")] == [4771, 36, 3793, 747],
        "operational_confusion": [int(cm[k]) for k in ("tn", "fp", "fn", "tp")] == [4767, 40, 2166, 2374],
        "elementwise_composition": np.array_equal(result.comb_pred, old | result.pressure_pred),
        "pressure_explanations": all(any(r.startswith("pressure_") for r in h.reasons)
                                     for h, p in zip(result.rule_hits, result.pressure_pred) if p),
    }
    categories = []
    for c, name in enumerate(CATEGORY_NAMES):
        modes = ("dominant",) if c == 0 else ("dominant", "pure", "containing")
        for mode in modes:
            mask = np.array([w.dominant_attack_category == c if mode == "dominant" else
                             c in w.categories and (mode == "containing" or w.categories <= {0, c})
                             for w in result.test_windows])
            n = int(mask.sum())
            flags = int(result.comb_pred[mask].sum())
            categories.append({"category": name, "cohort": mode, "n": n,
                               "flagged": flags, "rate": flags / n if n else None,
                               "protocol_flags": int(result.protocol_pred[mask].sum()),
                               "if_flags": int(result.if_pred[mask].sum()),
                               "pressure_flags": int(result.pressure_pred[mask].sum())})
    reference = json.loads((ROOT / "data/experiments/exp0016_pressure_bounds_rule.json").read_text(encoding="utf-8"))
    cohorts = {(r["category"], r["cohort"]): r for r in categories}
    checks["exp0016_cohort_identity"] = all(
        cohorts[(r["category"], r["cohort"])]["n"] == r["n_positive"]
        and cohorts[(r["category"], r["cohort"])]["flagged"] == r["combined_with_pressure_rule"]["tp"]
        and cohorts[(r["category"], r["cohort"])]["pressure_flags"] == r["pressure_rule_alone"]["tp"]
        for r in reference["per_cohort_test"]
    )
    return _plain({"status": "VALIDATED" if all(checks.values()) else "TESTED — IDENTITY FAILURE",
                   "experiment": "EXP-0017", "checks": checks, "metrics": cm,
                   "historical_metrics": old_cm, "per_category": categories,
                   "limitation": LIMITATION})


def save_result(result):
    from exp0009_payload import ARFF_SHA256, TXT_SHA256
    tracked_sources = ["ml/iforest_detector.py", "ml/exp0017_operational.py", "ml/rules.py",
                       "ml/features_windowed.py", "ml/features_txt.py",
                       "ml/exp0016_pressure_bounds_rule.py", "ml/exp0009_payload.py",
                       "ml/exp0008_cadence_features.py",
                       "ml/splits/verified_egress_5s_exp0008_pretest_v1.json",
                       "data/experiments/exp0016_pressure_bounds_rule.json"]
    payload = {"schema_version": 1, "summary": summarize(result), "result": asdict(result),
               "identity": {"raw_txt_sha256": TXT_SHA256, "raw_arff_sha256": ARFF_SHA256,
                            "raw_row_count": 274628,
                            "source_sha256": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest()
                                              for p in tracked_sources},
                            "python": platform.python_version(),
                            "packages": {p: version(p) for p in ("numpy", "scipy", "scikit-learn")}}}
    raw = _encoded(payload)
    envelope = {"sha256": hashlib.sha256(raw).hexdigest(), "payload": _plain(payload)}
    # Exclusive output creation; never overwrite a prior scored result.
    with RESULT_PATH.open("x", encoding="utf-8") as out:
        json.dump(envelope, out, separators=(",", ":"), allow_nan=False)
        out.write("\n")


def load_payload(path: Path = RESULT_PATH):
    envelope = json.loads(path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    if hashlib.sha256(_encoded(payload)).hexdigest() != envelope["sha256"]:
        raise ValueError("EXP-0017 saved output checksum mismatch")
    if payload["schema_version"] != 1 or payload["summary"]["experiment"] != "EXP-0017":
        raise ValueError("unknown evaluation artifact")
    split = load_pretest_split()
    if (payload["result"]["split_id"], payload["result"]["split_sha256"]) != (split.split_id, split.membership_sha256):
        raise ValueError("saved output manifest identity mismatch")
    for name, expected in payload["identity"]["source_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"saved output source identity mismatch: {name}")
    if payload["summary"]["status"] != "VALIDATED":
        raise ValueError("EXP-0017 identity checks failed; inspect saved output, do not rescore")
    return payload


def load_result(path: Path = RESULT_PATH):
    data = dict(load_payload(path)["result"])
    for name in ("mu", "sd", "if_scores", "y_test", "cat_test", "base_pred", "rule_pred",
                 "if_pred", "comb_pred", "protocol_pred", "pressure_pred"):
        data[name] = np.array(data[name], dtype=float if name in {"mu", "sd", "if_scores"} else int)
    for name in ("valid_func_codes", "valid_addresses"):
        data[name] = frozenset(data[name])
    data["pressure_bounds"] = tuple(data["pressure_bounds"])
    data["rule_hits"] = [RuleHit(**h) for h in data["rule_hits"]]
    windows = []
    for item in data["test_windows"]:
        w = dict(item)
        for name in ("categories", "func_codes", "addresses"):
            w[name] = frozenset(w[name])
        windows.append(Window(**w))
    data["test_windows"] = windows
    return DetectorResult(**data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--score-frozen-test", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.score_frozen_test:
        from iforest_detector import run_detector
        result = run_detector(confirmation=args.confirm)
        print(json.dumps(summarize(result), indent=2))
    else:
        if args.confirm:
            parser.error("--confirm requires --score-frozen-test")
        print(json.dumps(load_payload()["summary"], indent=2))


if __name__ == "__main__":
    main()
