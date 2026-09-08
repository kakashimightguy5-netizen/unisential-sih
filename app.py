from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
ML_DIR = ROOT / "ml"
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from explain import explain_alert
from features_windowed import CATEGORY_NAMES
from iforest_detector import run_detector

CAVEAT = (
    "Recall is category-dependent: protocol-violation attacks are well detected, "
    "value-manipulation attacks are weakly detected, and DoS is structurally "
    "invisible on egress by design."
)


@st.cache_resource(show_spinner="Running the validated EXP-0004 detector…")
def load_detector():
    return run_detector()


@st.cache_data
def count_dataset_rows() -> int:
    path = ROOT / "data" / "raw" / "gas_pipeline_raw.txt"
    with path.open("r", encoding="utf-8") as source:
        return sum(1 for _ in source)


def utc_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def firing_mechanism(result, test_index: int) -> str:
    if result.rule_pred[test_index] and result.if_pred[test_index]:
        return "Rule + IF"
    if result.rule_pred[test_index]:
        return "Rule"
    return "IF"


def metric_row(result, name: str, predictions: np.ndarray) -> dict:
    metrics = result.metrics(predictions)
    return {
        "Detector": name,
        "Precision": metrics["p"],
        "Recall": metrics["r"],
        "F1": metrics["f1"],
        "FPR": metrics["fpr"],
        "TN": int(metrics["tn"]),
        "FP": int(metrics["fp"]),
        "FN": int(metrics["fn"]),
        "TP": int(metrics["tp"]),
    }


st.set_page_config(page_title="SIH26145 — EXP-0004 Detector", layout="wide")
st.title("SIH26145 — EXP-0004 Egress Anomaly Detector")
st.caption("Single-page demo • 5-second windows • frozen TRAIN-normal baseline")
st.info(CAVEAT)

result = load_detector()
combined = result.metrics(result.comb_pred)

st.header("1. Validated dataset and headline results")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Raw dataset rows", f"{count_dataset_rows():,}")
c2.metric("Egress windows", f"{result.n_windows:,}")
c3.metric("TRAIN / VAL / TEST", f"{result.n_train:,} / {result.n_val:,} / {result.n_test:,}")
c4.metric("Precision", f"{combined['p']:.3%}")
c5.metric("Recall / F1 / FPR", f"{combined['r']:.3%} / {combined['f1']:.3%} / {combined['fpr']:.3%}")
st.caption(
    f"Model threshold: {result.threshold:.6f} • "
    f"TRAIN-normal fit windows: {result.n_train_normal:,}"
)

flagged_indices = np.flatnonzero(result.comb_pred).tolist()
timeline_rows = []
for test_index in flagged_indices:
    window = result.test_windows[test_index]
    timeline_rows.append({
        "alert": len(timeline_rows) + 1,
        "test_window_index": test_index,
        "timestamp_utc": utc_timestamp(window.t_start),
        "category": CATEGORY_NAMES[int(result.cat_test[test_index])],
        "mechanism": firing_mechanism(result, test_index),
        "if_score": float(result.if_scores[test_index]),
    })
timeline = pd.DataFrame(timeline_rows)

st.header("2. Alert timeline")
st.caption(f"{len(timeline):,} combined detector alerts in original TEST order.")
st.scatter_chart(
    timeline,
    x="timestamp_utc",
    y="if_score",
    color="mechanism",
    size=12,
    width="stretch",
)
st.dataframe(
    timeline,
    width="stretch",
    hide_index=True,
)

st.header("3. Per-alert explanation")
selected_test_index = st.selectbox(
    "Select an alert",
    flagged_indices,
    format_func=lambda i: (
        f"@{utc_timestamp(result.test_windows[i].t_start)} — "
        f"{CATEGORY_NAMES[int(result.cat_test[i])]} — {firing_mechanism(result, i)}"
    ),
)
top_k = st.slider("Features to show", min_value=3, max_value=5, value=5)
explanation = explain_alert(result, selected_test_index, top_k=top_k)

s1, s2, s3 = st.columns(3)
s1.metric("Fired by IF", "Yes" if explanation.fired_by_if else "No")
s2.metric("Fired by rule", "Yes" if explanation.fired_by_rule else "No")
s3.metric("TEST window index", f"{explanation.test_index:,}")

if explanation.rule_reasons:
    st.warning("Deterministic rule hit: " + "; ".join(explanation.rule_reasons))
else:
    st.caption("Deterministic rule: no hit.")
st.write(explanation.summary)

deviations = pd.DataFrame([{
    "Feature": deviation.feature,
    "Observed": deviation.observed,
    "TRAIN-normal mean": deviation.baseline_mean,
    "TRAIN-normal std": deviation.baseline_std,
    "z-score": deviation.z_score,
    "Direction": deviation.direction,
} for deviation in explanation.top_deviations])
st.dataframe(
    deviations.style.format({
        "Observed": "{:.6f}",
        "TRAIN-normal mean": "{:.6f}",
        "TRAIN-normal std": "{:.6f}",
        "z-score": "{:+.2f}",
    }),
    width="stretch",
    hide_index=True,
)
st.caption(
    "Z-scores show statistical unusualness relative to TRAIN-normal; they are not "
    "Isolation Forest attributions or root-cause claims."
)

st.header("4. Naive baseline vs. combined detector")
comparison = pd.DataFrame([
    metric_row(result, "Stage 0 naive baseline", result.base_pred),
    metric_row(result, "Combined rule OR IF", result.comb_pred),
])
formatted = comparison.copy()
for column in ("Precision", "Recall", "F1", "FPR"):
    formatted[column] = formatted[column].map("{:.3%}".format)
st.dataframe(formatted, width="stretch", hide_index=True)
st.caption(
    "All metrics and confusion counts above are recomputed from the current EXP-0004 TEST run."
)
