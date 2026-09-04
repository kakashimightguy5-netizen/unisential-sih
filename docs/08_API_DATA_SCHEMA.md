# 08 — API & Data Schema

All schemas JSON. Timestamps are Unix epoch seconds (float, microsecond precision) —
this maps to the dataset `time` attribute, which is fully populated and distinct on
every row (`docs/02-feature-schema.md`), so no ordinal fallback is needed. Tier tags
match `00_PROJECT_CHARTER.md`; all objects below are **[T1]** unless noted.

Field-naming: feature names in `feature_contributions` / `reasons` **must** come from
the Tier 1 feature list in `05_FEATURE_ENGINEERING_SPEC.md`.

---

## TrafficWindow

```json
{
  "window_id": "w_000123",
  "src_id": "src_synthetic_0",
  "t_start": 1418682163.170388,
  "t_end": 1418682168.170388,
  "window_seconds": 5.0,
  "packet_count": 42,
  "byte_total": 1791,
  "protocols": ["MODBUS"],
  "block_id": "TRAIN",
  "direction": "egress",
  "notes": "first-window incomplete-history flag, etc."
}
```
Notes: `src_id` is a **synthetic** per-source index for the gas-pipeline dataset
(`address` is near-constant — labelled synthetic on purpose). `block_id` is
`TRAIN|VALIDATION|TEST|null` (null for live/replay).

## FeatureVector

```json
{
  "window_id": "w_000123",
  "src_id": "src_synthetic_0",
  "t_start": 1418682163.170388,
  "features": {
    "packet_count": 42,
    "packets_per_sec": 8.4,
    "bytes_per_sec": 358.2,
    "iat_mean": 0.119,
    "iat_std": 0.031,
    "iat_min": 0.004,
    "iat_max": 0.240,
    "function_code_valid": 1.0,
    "function_code_dist": {"3": 0.62, "16": 0.38},
    "function_code_dist_divergence": 0.02,
    "payload_entropy_mean": 3.11,
    "payload_entropy_std": 0.18
  },
  "baseline_ref": "baseline_2026-09-10_expA",
  "tier2_features": {}
}
```
Notes: `payload_entropy_*` may be `null` when the input has no payload bytes (the
authoritative ARFF — BLOCKER 3); consumers must handle null. `tier2_features` is
empty in the MVP.

## ModelResult

```json
{
  "window_id": "w_000123",
  "if_score_raw": -0.02,
  "if_score_norm": 0.34,
  "model_available": true,
  "model_ref": "iforest_2026-09-10_expA",
  "baseline_fired": false,
  "baseline_rules": [
    {"rule": "iat_mean > 2x_train_mean", "fired": false,
     "observed": 0.119, "threshold": 0.240}
  ],
  "threshold_norm": 0.80,
  "threshold_source": "VALIDATION block, experiment expA, 99.5th pct normal"
}
```
Notes: `if_score_norm` in [0,1], higher = more anomalous. `threshold_source` is
**mandatory** and must name the split (`06_AI_MODEL_EVALUATION_PLAN.md`).

## Alert

```json
{
  "alert_id": "a_00007",
  "timestamp": "2014-12-19T02:40:11.512000Z",
  "window_id": "w_045912",
  "src_id": "src_synthetic_0",
  "protocol": "MODBUS",
  "anomaly_score": 0.91,
  "detector": "isolation_forest",
  "severity": "HIGH",
  "baseline_comparison": {
    "baseline_would_fire": false,
    "note": "naive IAT threshold did not trigger; ML flagged function-mix + rate"
  },
  "reasons": [
    {"feature": "packets_per_sec", "value": 71.2, "baseline": 8.4, "deviation": "8.5x"},
    {"feature": "function_code_dist_divergence", "value": 0.63, "baseline": 0.02,
     "deviation": "+30 sigma", "phrase": "unusual function-code mix (writes dominate)"},
    {"feature": "payload_entropy_mean", "value": 7.2, "baseline": 2.4,
     "deviation": "+12 sigma", "phrase": "payload entropy high (one signal among several)"}
  ],
  "explanation_confidence": "normal",
  "acknowledged": false
}
```
Notes: `detector` is `isolation_forest` for operational alerts; the naive baseline
never produces a standalone `Alert` — its verdict rides in `baseline_comparison`.
`explanation_confidence` is `"low"` when every contributing feature is an entropy
feature. `reasons` is never empty for a real alert (`FR-6.3`).

## SystemHealth

```json
{
  "timestamp": "2026-09-15T10:00:00Z",
  "state": "OK",
  "model_available": true,
  "model_ref": "iforest_2026-09-10_expA",
  "baseline_ref": "baseline_2026-09-10_expA",
  "ingest_source": "replay:normal_clip",
  "windows_processed": 1204,
  "windows_per_sec": 210.5,
  "inbound_discarded": 1198,
  "alerts_last_100_windows": 0,
  "degraded_reason": null
}
```
Notes: `state` is `OK|DEGRADED|ERROR`. `DEGRADED` + `degraded_reason:"model
unavailable — baseline only"` is the MODEL-unavailable path
(`09_TEST_VALIDATION_PLAN.md`).

## ReplaySession

```json
{
  "replay_id": "r_0003",
  "clip": "attack_clip_command_injection",
  "source_file": "data/processed/replay/attack_clip_command_injection.pcap",
  "speed": 1.0,
  "state": "RUNNING",
  "t_started": "2026-09-15T10:05:00Z",
  "cursor_ts": 1418957100.0,
  "windows_emitted": 87,
  "loop": false
}
```
Notes: `state` is `IDLE|RUNNING|PAUSED|DONE`. Replay clips are pre-cut, provenance
recorded; they are egress-filtered captures, labelled as simulation.

---

## Preliminary REST Endpoints (local, `127.0.0.1`, no auth for the offline MVP)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | latest `SystemHealth` |
| `GET` | `/alerts?since=&severity=&src_id=&limit=` | recent `Alert` list (newest first) |
| `GET` | `/alerts/{alert_id}` | full `Alert` incl. `reasons` |
| `GET` | `/windows?since=&src_id=&limit=` | recent `TrafficWindow` summaries + `if_score_norm` |
| `GET` | `/windows/{window_id}` | `TrafficWindow` + `FeatureVector` + `ModelResult` |
| `GET` | `/stats?since=` | rolling traffic stats for the dashboard (pps, Bps, window count, discard count) |
| `GET` | `/comparison?since=` | per-window baseline-fired vs ML-fired, for the comparison view |
| `POST` | `/replay` | start a replay: `{clip, speed, loop}` → `ReplaySession` |
| `POST` | `/replay/{replay_id}/pause` \| `/resume` \| `/stop` | control replay |
| `GET` | `/replay/{replay_id}` | `ReplaySession` status |
| `GET` | `/model` | current `model_ref` / `baseline_ref` / availability + `threshold_source` |

Tier 2/3 endpoints (per-source profiles, historical aggregation) are **not** in the
MVP surface.

---

## Persistence (SQLite, MVP)

Tables mirror the objects above: `traffic_windows`, `feature_vectors`,
`model_results`, `alerts`, `alert_reasons`, `replay_sessions`, `health_snapshots`.
Label data (for evaluation only) lives in a **separate** table `eval_labels` keyed by
`window_id` and is never joined into the feature/inference path.
