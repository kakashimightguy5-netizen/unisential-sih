#!/usr/bin/env python3
"""
SUPERVISED DIAGNOSTIC — not the headline detector.

AGENTS.md's approved detection path is unsupervised (baseline -> Isolation Forest
-> autoencoder), trained normal-only. This script is a deliberately separate probe:
an XGBoost multiclass classifier trained WITH labels, to establish a ceiling for
"how much of each attack category is separable from the diode-observable frame
features at all". Its per-class recall is the honest upper bound the unsupervised
model will not beat.

Guardrails honoured here:
  * Contiguous time-block split (03-data-split-protocol.md) — NOT a random split.
  * `source` / `destination` are never features (source==2 == MITM rig == attack-only;
    the script prints the crosstab that proves the leak).
  * Command-payload process values (setpoint, gain, pump, solenoid, ...) are not in
    the feature set by construction — they are not in this file and would not be
    visible to a passive one-directional observer.

Run:  .venv/bin/python ml/xgb_txt_diagnostic.py
"""
from __future__ import annotations

import io
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix
from xgboost import XGBClassifier

from features_txt import FEATURE_COLUMNS, iter_records

CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]
GUARD_SECONDS = 2.0            # discarded band at the split boundary
TRAIN_FRACTION = 0.75
REPORT_PATH = Path(__file__).resolve().parent.parent / "data" / "experiments" / "xgb_txt_diagnostic_report.md"

SPECIFIC_NAMES = {
    **{i: "Setpoint/PID param" for i in range(1, 13)},
    13: "Pump state", 14: "Solenoid state", 15: "System mode",
    16: "Critical condition", 17: "Critical condition",
    18: "Bad CRC (DoS)", 19: "Clean registers", 20: "Device scan",
    21: "Force listen", 22: "Restart comms", 23: "Read device ID",
    24: "Function-code scan",
    25: "Rise/fall", 26: "Rise/fall", 27: "Slope", 28: "Slope",
    29: "Random value", 30: "Random value", 31: "Random value",
    32: "Negative pressure", 33: "Fast setpoint", 34: "Fast setpoint",
    35: "Slow setpoint",
}


def load():
    recs = list(iter_records())
    X = np.array([[getattr(r, c) for c in FEATURE_COLUMNS] for r in recs], dtype=float)
    y = np.array([r.categorized_attack for r in recs], dtype=int)
    spec = np.array([r.specific_attack for r in recs], dtype=int)
    src = np.array([r.source for r in recs], dtype=int)
    ts = np.array([r.timestamp for r in recs], dtype=float)
    order = np.argsort(ts, kind="stable")
    return X[order], y[order], spec[order], src[order], ts[order]


def contiguous_split(ts: np.ndarray):
    n = len(ts)
    cut_idx = int(n * TRAIN_FRACTION)
    cut_ts = ts[cut_idx]
    train_mask = ts < (cut_ts - GUARD_SECONDS / 2)
    test_mask = ts > (cut_ts + GUARD_SECONDS / 2)
    return train_mask, test_mask, cut_ts


def source_leak_crosstab(y: np.ndarray, src: np.ndarray) -> str:
    lines = ["source | " + " | ".join(f"{c:>6}" for c in CATEGORY_NAMES) + " |  total"]
    for s in sorted(set(src.tolist())):
        row = [int(((src == s) & (y == c)).sum()) for c in range(8)]
        tag = {1: " (master)", 2: " (MITM rig)", 3: " (slave)"}.get(s, "")
        lines.append(f"{s}{tag:<11}| " + " | ".join(f"{v:>6}" for v in row) + f" | {sum(row):>6}")
    return "\n".join(lines)


def main() -> None:
    X, y, spec, src, ts = load()
    tr, te, cut_ts = contiguous_split(ts)

    buf = io.StringIO()
    p = lambda *a: print(*a, file=buf)

    p("# XGBoost supervised diagnostic — Turnipseed gas-pipeline TXT (frame-level)\n")
    p("**This is a labels-available ceiling probe, not the project's detector.**")
    p("The approved detector is unsupervised Isolation Forest (AGENTS.md); its per-class")
    p("recall will be at or below what is shown here.\n")

    p("## Data & split\n")
    p(f"- Source: `data/raw/gas_pipeline_raw.txt` — {len(y):,} frames parsed "
      f"(lines with != 6 fields skipped).")
    p(f"- Features ({len(FEATURE_COLUMNS)}), all diode-observable: {', '.join(FEATURE_COLUMNS)}")
    p("- Excluded as label leakage / not wire-observable: `source`, `destination`, "
      "`specific_attack`, absolute `timestamp`.")
    p(f"- Split: **contiguous time-block**, train = earliest {TRAIN_FRACTION:.0%}, "
      f"test = latest {1 - TRAIN_FRACTION:.0%}, {GUARD_SECONDS}s guard band discarded "
      "at the boundary. Random splitting is forbidden (03-data-split-protocol.md).")
    p(f"- Boundary timestamp: {cut_ts:.3f}  "
      f"(train {int(tr.sum()):,} frames / test {int(te.sum()):,} frames / "
      f"{len(y) - int(tr.sum()) - int(te.sum())} discarded in guard band)\n")

    p("### Per-category counts, train / test")
    p("```")
    for c in range(8):
        p(f"{c} {CATEGORY_NAMES[c]:<7}: {int((y[tr] == c).sum()):>7} / {int((y[te] == c).sum()):>6}")
    p("```\n")

    p("## Label-leak audit — `categorized_attack` × `source` (why source is dropped)\n")
    p("```")
    p(source_leak_crosstab(y, src))
    p("```")
    p("`source == 2` (the lab MITM injection rig) carries **zero** Normal frames and "
      "`source == 1` (master) carries **only** Normal frames. Training on `source` would "
      "hand the model the label. It is also not something a diode observer can see.\n")

    clf = XGBClassifier(
        objective="multi:softprob", num_class=8,
        n_estimators=400, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        reg_lambda=1.0, random_state=0, n_jobs=-1, eval_metric="mlogloss",
    )
    clf.fit(X[tr], y[tr])
    pred = clf.predict(X[te])
    y_te, spec_te = y[te], spec[te]

    p("## Classification report (test block)\n")
    p("```")
    p(classification_report(y[te], pred, labels=list(range(8)),
                            target_names=CATEGORY_NAMES, digits=3, zero_division=0))
    p("```\n")

    p("## Confusion matrix (rows = true, cols = predicted)\n")
    cm = confusion_matrix(y[te], pred, labels=list(range(8)))
    p("```")
    p("true\\pred " + " ".join(f"{n:>7}" for n in CATEGORY_NAMES))
    for i, rowname in enumerate(CATEGORY_NAMES):
        p(f"{rowname:<9} " + " ".join(f"{v:>7}" for v in cm[i]))
    p("```\n")

    p("## Feature importances (gain)\n")
    imp = clf.feature_importances_
    p("```")
    for name, val in sorted(zip(FEATURE_COLUMNS, imp), key=lambda t: -t[1]):
        p(f"{name:<32} {val:.4f}")
    p("```\n")

    p("## Per-specific-attack recall in the weak categories\n")
    p("For every `specific_attack` id present in the test block, the fraction of its "
      "frames the model assigned to the *correct* parent category:\n")
    p("```")
    p("spec  parent  name                      test_n  recall")
    for s in sorted(set(spec_te.tolist())):
        if s == 0:
            continue
        m = spec_te == s
        if m.sum() == 0:
            continue
        parent = int(y_te[m][0])
        rec = float((pred[m] == parent).mean())
        p(f"{s:>3}   {CATEGORY_NAMES[parent]:<6}  {SPECIFIC_NAMES.get(s, '?'):<25} "
          f"{int(m.sum()):>6}  {rec:0.3f}")
    p("```")

    REPORT_PATH.write_text(buf.getvalue())
    print(buf.getvalue())
    print(f"\n[report written to {REPORT_PATH}]")


if __name__ == "__main__":
    main()
