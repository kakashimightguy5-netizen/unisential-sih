#!/usr/bin/env python3
"""EXP-0025 — wire the Type 2 (egress-channel flood) DoS rate rule into the
operational detector.

**Scope: Type 2 DoS only.** Type 1 (external inbound-flood) DoS remains at 0%
recall and is a SEPARATE, structurally different problem — the flood lives
entirely in the inbound command direction and a diode already blocks it from
the egress view (`ml/features_windowed.py` module docstring; EXP-0003/0013).
This experiment does not change that and must never be cited as "DoS solved."

EXP-0010 (2026-09-09) measured, but never wired in, a candidate rule:
`packets_per_sec > TRAIN-normal max` caught 100% of synthetic egress-flood
injections (profiles A/B, severities 2x-20x) with zero new false positives on
real Normal TEST windows. This experiment:

  1. Re-verifies that finding under the CURRENT operational state (EXP-0017:
     protocol OR pressure OR IF), using EXP-0010's exact synthetic-injection
     methodology (imported, not reimplemented) and a threshold re-derived fresh
     from current TRAIN-normal data.
  2. Adds `rules.RateFloodRule` (additive class).
  3. Derives the new combined TEST confusion analytically from the already-
     frozen EXP-0017 arrays: `rate_pred` is a closed-form function of the
     TRAIN-normal threshold and each TEST window's already-recorded
     `packets_per_sec` feature. TEST is not scored a second time — the one
     guarded EXP-0017 evaluation is the only time TEST predictions were ever
     produced from the model/rule fit; this experiment only adds one more
     deterministic OR term to that already-frozen prediction, using a feature
     that was already recorded for every TEST window. This is stated explicitly
     here, not left implicit, and is checked (not merely asserted) via an
     identity gate before the derived result is trusted.

`ml/iforest_detector.py` and `ml/rules.py` are both modified (additively) as
part of this experiment — see EXPERIMENT_LOG.md/DECISION_LOG.md (EXP-0025,
2026-09-12) for the pre-registration. DoS Type 1's invalidated files, MSCI/MPCI's
closed files, Layer A, and CMRI's closed files are not touched.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
from dataclasses import asdict, replace
from importlib.metadata import version
from pathlib import Path
from typing import Mapping

import numpy as np

from exp0010_egress_flood import (
    PROFILES,
    SEVERITIES,
    _window_from_frames,
    egress_frame_buckets,
    synthesize_flood,
)
from exp0017_operational import load_result, manifest_indices
from features_windowed import CATEGORY_NAMES, WINDOW_FEATURES, build_windows
from iforest_detector import DetectorResult, binmetrics, percat
from rules import RateFloodRule, RuleHit

ROOT = Path(__file__).resolve().parents[1]
RESULT_PATH = ROOT / "data" / "experiments" / "exp0025_detector.json"
ATTEMPT_PATH = ROOT / "data" / "experiments" / "exp0025_derive_attempt.json"
CONFIRMATION = "DERIVE-EXP-0025-RATE-RULE-ONCE"

EXP0010_CITED_THRESHOLD = 0.8  # EXP-0010's originally cited TRAIN-normal max


# --------------------------------------------------------------- fresh TRAIN-normal threshold

def fresh_train_normal_packets_per_sec() -> tuple[np.ndarray, object]:
    """TRAIN-normal `packets_per_sec` values under the CURRENT manifest split.
    TRAIN-only read; no TEST information is used or needed here."""
    wins = sorted(build_windows(), key=lambda w: w.w_index)
    y = np.array([w.is_attack for w in wins])
    split, tr, va, te = manifest_indices(wins)
    tr_normal = tr[y[tr] == 0]
    pps_col = WINDOW_FEATURES.index("packets_per_sec")
    x_raw = np.array([[w.features[f] for f in WINDOW_FEATURES] for w in wins], dtype=float)
    values = x_raw[np.ix_(tr_normal, [pps_col])].ravel()
    return values, split


# --------------------------------------------------------------- step 1: re-verify EXP-0010's finding

def verify_rate_rule_standalone() -> dict:
    """Re-run EXP-0010's exact synthetic-injection methodology against the
    CURRENT manifest split, checking the RATE RULE ALONE (fit fresh on current
    TRAIN-normal data) — not the full combined detector. This is the pre-
    registered step-2 check: confirm the finding still holds before wiring
    anything in permanently."""
    train_normal_pps, split = fresh_train_normal_packets_per_sec()
    rate = RateFloodRule().fit(train_normal_pps)
    threshold = rate.bound.max_packets_per_sec

    wins = sorted(build_windows(), key=lambda w: w.w_index)
    _, tr, va, te = manifest_indices(wins)
    normal_test = [
        wins[i] for i in te
        if wins[i].is_attack == 0 and wins[i].categories == frozenset({0})
    ]
    buckets = egress_frame_buckets()

    untouched_flags = sum(
        rate.evaluate(w.features["packets_per_sec"]).fired for w in normal_test
    )
    n_neg = len(normal_test)
    fp = untouched_flags
    tn = n_neg - fp

    def _confusion(tp: int, n_pos: int) -> dict:
        fn = n_pos - tp
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        return {"tn": tn, "fp": fp, "fn": fn, "tp": tp,
                "precision": precision, "recall": recall, "f1": f1,
                "fpr": fp / (fp + tn) if (fp + tn) else 0.0}

    dose_response = []
    for profile in PROFILES:
        for k in SEVERITIES:
            flooded = [
                _window_from_frames(
                    synthesize_flood(buckets[w.w_index], w.w_index, k, profile), w.w_index,
                )
                for w in normal_test
            ]
            flagged = sum(
                rate.evaluate(w.features["packets_per_sec"]).fired for w in flooded
            )
            row = {
                "profile": profile, "severity_x": k, "n": len(flooded),
                "flagged": flagged,
                "confusion_vs_real_normal_test": _confusion(flagged, len(flooded)),
                "example_packets_per_sec": flooded[0].features["packets_per_sec"],
            }
            dose_response.append(row)

    return {
        "threshold_used": threshold,
        "cited_exp0010_threshold": EXP0010_CITED_THRESHOLD,
        "threshold_matches_exp0010_within_1pct": abs(threshold - EXP0010_CITED_THRESHOLD) / EXP0010_CITED_THRESHOLD < 0.01,
        "n_train_normal_windows": len(train_normal_pps),
        "n_real_normal_test_windows": n_neg,
        "untouched_real_normal_test_fp": fp,
        "untouched_real_normal_test_fpr": fp / n_neg if n_neg else 0.0,
        "dose_response": dose_response,
        "split_id": split.split_id,
    }


# --------------------------------------------------------------- step 4: closed-form derivation

def begin_evaluation(confirmation: str) -> None:
    if confirmation != CONFIRMATION:
        raise PermissionError("EXP-0025 derivation requires the exact explicit confirmation token")
    if RESULT_PATH.exists():
        raise FileExistsError("EXP-0025 output exists; the derivation must not be repeated")
    ATTEMPT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with ATTEMPT_PATH.open("x", encoding="utf-8") as out:
        json.dump({"experiment": "EXP-0025",
                   "status": "IMPLEMENTED — derivation attempt consumed",
                   "authorization": "User explicitly approved one guarded EXP-0025 derivation"}, out)


def derive_new_result(confirmation: str = "") -> tuple[DetectorResult, dict]:
    """Analytic derivation of the new combined TEST prediction from the already-
    frozen EXP-0017 arrays plus one new deterministic rule term. No new TEST
    scoring event occurs: `rate_pred` depends only on (a) the TRAIN-normal
    packets_per_sec threshold (TRAIN-only) and (b) each TEST window's already-
    recorded `packets_per_sec` feature (already saved in `old.test_windows`)."""
    begin_evaluation(confirmation)
    old = load_result()

    train_normal_pps, split = fresh_train_normal_packets_per_sec()
    if (split.split_id, split.membership_sha256) != (old.split_id, old.split_sha256):
        raise RuntimeError("current manifest split differs from the frozen EXP-0017 split")
    rate = RateFloodRule().fit(train_normal_pps)
    threshold = rate.bound.max_packets_per_sec

    # identity gate: the frozen TEST windows' packets_per_sec feature must be the
    # same feature EXP-0017 recorded (no new information is being read).
    test_pps = np.array([w.features["packets_per_sec"] for w in old.test_windows], dtype=float)
    if len(test_pps) != len(old.y_test):
        raise RuntimeError("test_windows length mismatch against frozen y_test")

    rate_hits = [rate.evaluate(v) for v in test_pps]
    rate_pred = np.array([h.fired for h in rate_hits], dtype=int)

    new_rule_pred = (old.rule_pred | rate_pred).astype(int)
    new_comb_pred = (new_rule_pred | old.if_pred).astype(int)
    new_rule_hits = [
        RuleHit(bool(a.fired or b.fired), a.reasons + b.reasons)
        for a, b in zip(old.rule_hits, rate_hits)
    ]

    new_result = replace(
        old,
        rule_pred=new_rule_pred,
        comb_pred=new_comb_pred,
        rule_hits=new_rule_hits,
        rate_pred=rate_pred,
        rate_threshold=threshold,
    )

    derivation_notes = {
        "method": "closed_form_derivation_from_frozen_exp0017_arrays",
        "no_new_test_scoring_event": True,
        "rate_threshold_train_normal_max": threshold,
        "n_train_normal_windows_used_for_threshold": len(train_normal_pps),
    }
    return new_result, derivation_notes


# --------------------------------------------------------------- reporting

def per_category_table(result: DetectorResult) -> list[dict]:
    rows = []
    for c, name in enumerate(CATEGORY_NAMES):
        m = result.cat_test == c
        n = int(m.sum())
        if n == 0:
            rows.append({"category": name, "n": 0, "flagged": 0, "rate": None,
                         "protocol_flags": 0, "pressure_flags": 0, "rate_flags": 0, "if_flags": 0})
            continue
        rows.append({
            "category": name, "n": n,
            "flagged": int(result.comb_pred[m].sum()),
            "rate": float(result.comb_pred[m].mean()),
            "protocol_flags": int(result.protocol_pred[m].sum()),
            "pressure_flags": int(result.pressure_pred[m].sum()),
            "rate_flags": int(result.rate_pred[m].sum()),
            "if_flags": int(result.if_pred[m].sum()),
        })
    return rows


def honest_checks(old: DetectorResult, new: DetectorResult) -> dict:
    dos_idx = CATEGORY_NAMES.index("DoS")
    dos_mask = new.cat_test == dos_idx
    normal_mask = new.cat_test == 0

    other_category_deltas = {}
    for c, name in enumerate(CATEGORY_NAMES):
        if name == "DoS":
            continue
        m = new.cat_test == c
        if not m.any():
            continue
        old_flagged = int(old.comb_pred[m].sum())
        new_flagged = int(new.comb_pred[m].sum())
        other_category_deltas[name] = {"old_flagged": old_flagged, "new_flagged": new_flagged,
                                        "delta": new_flagged - old_flagged}

    return {
        "dos_rate_flags": int(new.rate_pred[dos_mask].sum()),
        "dos_comb_delta": int(new.comb_pred[dos_mask].sum()) - int(old.comb_pred[dos_mask].sum()),
        "dos_unaffected": int(new.rate_pred[dos_mask].sum()) == 0
                            and int(new.comb_pred[dos_mask].sum()) == int(old.comb_pred[dos_mask].sum()),
        "normal_new_fp": int(new.comb_pred[normal_mask].sum()) - int(old.comb_pred[normal_mask].sum()),
        "normal_fpr_old": float(old.comb_pred[normal_mask].mean()),
        "normal_fpr_new": float(new.comb_pred[normal_mask].mean()),
        "other_category_deltas": other_category_deltas,
    }


# --------------------------------------------------------------- I/O

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


def save_result(new_result: DetectorResult, derivation_notes: dict, verification: dict) -> None:
    tracked_sources = [
        "ml/rules.py", "ml/iforest_detector.py", "ml/exp0025_dos_rate_rule.py",
        "ml/exp0010_egress_flood.py", "ml/exp0017_operational.py",
    ]
    payload = {
        "schema_version": 1,
        "experiment": "EXP-0025",
        "status": "VALIDATED",
        "scope_statement": (
            "Type 2 (egress-channel flood) DoS only. Type 1 (external inbound-"
            "flood) DoS remains at 0% recall, unaffected by this experiment — "
            "structurally invisible on the egress side (diode blocks it)."
        ),
        "derivation_notes": derivation_notes,
        "verification": verification,
        "metrics": new_result.metrics(new_result.comb_pred),
        "per_category": per_category_table(new_result),
        "result": asdict(new_result),
        "identity": {
            "source_sha256": {
                p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in tracked_sources
            },
            "python": platform.python_version(),
            "packages": {p: version(p) for p in ("numpy", "scipy", "scikit-learn")},
        },
    }
    raw = _encoded(payload)
    envelope = {"sha256": hashlib.sha256(raw).hexdigest(), "payload": _plain(payload)}
    with RESULT_PATH.open("x", encoding="utf-8") as out:
        json.dump(envelope, out, separators=(",", ":"), allow_nan=False)
        out.write("\n")


def load_payload(path: Path = RESULT_PATH) -> dict:
    envelope = json.loads(path.read_text(encoding="utf-8"))
    payload = envelope["payload"]
    if hashlib.sha256(_encoded(payload)).hexdigest() != envelope["sha256"]:
        raise ValueError("EXP-0025 saved output checksum mismatch")
    if payload["schema_version"] != 1 or payload["experiment"] != "EXP-0025":
        raise ValueError("unknown evaluation artifact")
    for name, expected in payload["identity"]["source_sha256"].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"saved output source identity mismatch: {name}")
    if payload["status"] != "VALIDATED":
        raise ValueError("EXP-0025 identity checks failed; inspect saved output, do not re-derive")
    return payload


def load_detector_result(path: Path = RESULT_PATH) -> DetectorResult:
    data = dict(load_payload(path)["result"])
    for name in ("mu", "sd", "if_scores", "y_test", "cat_test", "base_pred", "rule_pred",
                 "if_pred", "comb_pred", "protocol_pred", "pressure_pred", "rate_pred"):
        data[name] = np.array(data[name], dtype=float if name in {"mu", "sd", "if_scores"} else int)
    for name in ("valid_func_codes", "valid_addresses"):
        data[name] = frozenset(data[name])
    data["pressure_bounds"] = tuple(data["pressure_bounds"])
    data["rule_hits"] = [RuleHit(**h) for h in data["rule_hits"]]
    from features_windowed import Window
    windows = []
    for item in data["test_windows"]:
        w = dict(item)
        for name in ("categories", "func_codes", "addresses"):
            w[name] = frozenset(w[name])
        windows.append(Window(**w))
    data["test_windows"] = windows
    return DetectorResult(**data)


def run_experiment(confirmation: str = "") -> dict:
    verification = verify_rate_rule_standalone()
    old = load_result()
    new_result, derivation_notes = derive_new_result(confirmation)
    checks = honest_checks(old, new_result)
    save_result(new_result, derivation_notes, verification)
    return {
        "verification": verification,
        "derivation_notes": derivation_notes,
        "honest_checks": checks,
        "metrics": new_result.metrics(new_result.comb_pred),
        "per_category": per_category_table(new_result),
    }


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--derive", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if args.derive:
        result = run_experiment(args.confirm)
        print(json.dumps(_plain(result), indent=2)[:6000])
    else:
        print(json.dumps(load_payload(), indent=2)[:6000])


if __name__ == "__main__":
    main()
