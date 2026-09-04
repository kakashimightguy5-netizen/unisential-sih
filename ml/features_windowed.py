#!/usr/bin/env python3
"""
Windowed egress features for the unsupervised detector (05_FEATURE_ENGINEERING_SPEC.md).

Pipeline (order is fixed — 04_DATASET_PLAN.md):
  1. parse frames                       (ml/features_txt.py)
  2. direction filter: keep egress      (destination == 1 = slave->master = outbound
                                         telemetry = the diode's low-side view;
                                         BLOCKER 2, thesis-confirmed: egress == response)
  3. cut contiguous time blocks         (done by the caller / detector)
  4. compute 5-second tumbling-window features WITHIN a block
  5. select normal-only training windows (done by the detector)

`source` / `destination` are used ONLY as the direction filter, never as features
(source==2 is the MITM rig and leaks the label; a diode observer cannot see either).
A window is labelled attack if ANY frame in it is attack-labelled.

DoS note: in this dataset DoS (Bad-CRC, specific 18) lives entirely in the *inbound*
command direction. On the egress side the slave's replies during a DoS episode are
byte-identical to normal replies, and window rate / IAT are unchanged. Windowed
features therefore do NOT recover DoS from the one-directional view — this is a true
property of the threat model (a diode already blocks the inbound flood), not a
feature gap. See EXPERIMENT_LOG.md.
"""
from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from pathlib import Path

from features_txt import iter_records

WINDOW_SECONDS = 5.0
EGRESS_DESTINATION = 1
MIN_FRAMES_PER_WINDOW = 2          # windows with fewer frames are dropped (incomplete)
NORMAL_FUNC_CODES = frozenset({0x03, 0x10})

CATEGORY_NAMES = ["Normal", "NMRI", "CMRI", "MSCI", "MPCI", "MFCI", "DoS", "Recon"]

WINDOW_FEATURES = [
    "packet_count",
    "packets_per_sec",
    "bytes_per_sec",
    "mean_frame_len",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "frac_func_valid",
    "frac_func_read",       # 0x03
    "frac_func_write",      # 0x10
    "rare_func_rate",
    "distinct_frame_ratio",
    "repeat_frame_rate",
    "payload_entropy_mean",
    "payload_entropy_std",
]
# Entropy features: as of EXP-0002 these ARE headline IF inputs (pre-registration §2
# amended 2026-09-04 — the TXT is self-labelled, so entropy is evaluable vs labels).
ENTROPY_FEATURES = ["payload_entropy_mean", "payload_entropy_std"]

# Constant on normal traffic -> an Isolation Forest can never split on them. Computed
# for reporting, but NOT IF inputs; handled by the deterministic rule layer (ml/rules.py).
# (EXP-0001 audit / DECISION_LOG 2026-09-04.)
RULE_LAYER_FEATURES = ["frac_func_valid", "rare_func_rate"]

# The actual Isolation Forest input set (EXP-0002 headline).
IF_FEATURES = [f for f in WINDOW_FEATURES if f not in RULE_LAYER_FEATURES]


@dataclass
class Window:
    w_index: int
    t_start: float
    features: dict
    is_attack: int
    categories: frozenset      # all categorized_attack values seen (incl 0)
    func_codes: frozenset      # distinct function codes seen — for the deterministic rule layer
    addresses: frozenset       # distinct slave addresses seen — for the deterministic rule layer

    @property
    def dominant_attack_category(self) -> int:
        atk = [c for c in self.categories if c != 0]
        return min(atk) if atk else 0


def _entropy(values: list[int]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.pstdev(values)


def build_windows(path: Path | None = None) -> list[Window]:
    frames = [r for r in iter_records() if r.destination == EGRESS_DESTINATION]
    frames.sort(key=lambda r: r.timestamp)

    buckets: dict[int, list] = {}
    for r in frames:
        buckets.setdefault(math.floor(r.timestamp / WINDOW_SECONDS), []).append(r)

    windows: list[Window] = []
    for w_idx in sorted(buckets):
        fr = buckets[w_idx]
        if len(fr) < MIN_FRAMES_PER_WINDOW:
            continue
        fr.sort(key=lambda r: r.timestamp)
        n = len(fr)
        lens = [r.frame_len_bytes for r in fr]
        ents = [r.message_entropy_bits_per_byte for r in fr]
        iats = [fr[i].timestamp - fr[i - 1].timestamp for i in range(1, n)]
        fids = [r.frame_id for r in fr]
        repeats = sum(1 for i in range(1, n) if fids[i] == fids[i - 1])

        feats = {
            "packet_count": float(n),
            "packets_per_sec": n / WINDOW_SECONDS,
            "bytes_per_sec": sum(lens) / WINDOW_SECONDS,
            "mean_frame_len": statistics.mean(lens),
            "iat_mean": statistics.mean(iats) if iats else WINDOW_SECONDS,
            "iat_std": statistics.pstdev(iats) if len(iats) > 1 else 0.0,
            "iat_min": min(iats) if iats else WINDOW_SECONDS,
            "iat_max": max(iats) if iats else WINDOW_SECONDS,
            "frac_func_valid": sum(r.function_code in NORMAL_FUNC_CODES for r in fr) / n,
            "frac_func_read": sum(r.function_code == 0x03 for r in fr) / n,
            "frac_func_write": sum(r.function_code == 0x10 for r in fr) / n,
            "rare_func_rate": sum(r.rare_function_code for r in fr) / n,
            "distinct_frame_ratio": len(set(fids)) / n,
            "repeat_frame_rate": repeats / (n - 1) if n > 1 else 1.0,
            "payload_entropy_mean": statistics.mean(ents),
            "payload_entropy_std": statistics.pstdev(ents) if len(ents) > 1 else 0.0,
        }
        cats = frozenset(r.categorized_attack for r in fr)
        windows.append(Window(
            w_index=w_idx,
            t_start=w_idx * WINDOW_SECONDS,
            features=feats,
            is_attack=int(any(c != 0 for c in cats)),
            categories=cats,
            func_codes=frozenset(r.function_code for r in fr),
            addresses=frozenset(r.address for r in fr),
        ))
    return windows


if __name__ == "__main__":
    import csv
    ws = build_windows()
    out = Path(__file__).resolve().parent.parent / "data" / "experiments" / "txt_windowed_features.csv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["w_index", "t_start", *WINDOW_FEATURES, "is_attack", "dominant_category"])
        for win in ws:
            w.writerow([win.w_index, f"{win.t_start:.3f}",
                        *[f"{win.features[f]:.6f}" for f in WINDOW_FEATURES],
                        win.is_attack, win.dominant_attack_category])
    n_atk = sum(x.is_attack for x in ws)
    print(f"{len(ws)} windows -> {out}  ({n_atk} attack / {len(ws) - n_atk} normal)")
