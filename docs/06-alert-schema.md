> **SUPERSEDED (2026-09-02) by `08_API_DATA_SCHEMA.md`.** The MVP now includes a
> minimal REST API + dashboard (see `DECISION_LOG.md`), and the alert object gains
> `severity` bands, `reasons`/`feature_contributions`, `baseline_comparison`, and
> dedup. The `08_*` `Alert` schema is authoritative. This file is kept only for the
> field-level reasoning below (timestamp/source_id fallbacks, `threat_class_guess`
> as a heuristic), which still applies. Per `02-feature-schema.md`, the project
> dataset does have a usable per-row `time` and needs a synthetic `source_id`.

# Alert Schema (CLI Output Contract — superseded)

P1 has no backend API or dashboard (`07-scope-and-cuts.md`). The only alert output
surface is CLI (stdout / JSON file). This schema is the contract for that output.

## Alert object

```json
{
  "timestamp": "[TBD - confirm against real dataset: exact source field and format, e.g. ISO 8601 vs epoch vs dataset-native]",
  "source_id": "[TBD - confirm against real dataset: identifier available — device/session/flow id, or index if nothing else exists]",
  "anomaly_score": 0.0,
  "is_alert": false,
  "threat_class_guess": "[TBD - one of: protocol_violation | payload_entropy | volume_frequency | unknown — depends on which classes are supported per 01-threat-model.md]",
  "feature_contributions": [
    {
      "feature_name": "[TBD - confirm against real dataset: actual feature names come from 02-feature-schema.md, not invented here]",
      "z_score": 0.0,
      "direction": "high | low"
    }
  ]
}
```

## Field notes

- `timestamp` — format depends on what the raw dataset provides. If no reliable
  per-record timestamp exists, this field is `null` and the record's ordinal
  position is used instead; this must be stated explicitly in output, not silently
  substituted.
- `source_id` — best-effort identifier for what emitted the traffic (device, IP,
  session). If the dataset has no such field, use a synthetic per-record index and
  label it as such — never claim identity information the data doesn't support.
- `anomaly_score` — raw Isolation Forest score (or a normalized transform of it,
  stated explicitly if applied).
- `is_alert` — boolean result of applying the validation-selected threshold
  (`04-model-and-threshold.md`) to `anomaly_score`.
- `threat_class_guess` — a best-effort label based on which feature(s) dominate the
  contribution list, not a separate classifier. Must be labeled clearly as a
  heuristic guess, not a verified classification, in any demo narration.
- `feature_contributions` — sorted descending by `abs(z_score)`. `direction` is
  `"high"` if the observed value is above the normal-only training mean, `"low"`
  if below.

## Explicit non-goals for P1

- No streaming/live alert delivery — batch CLI run over a dataset slice only.
- No alert deduplication, rate limiting, or severity tiers — flat list of alert
  objects is sufficient for the scripted demo.
