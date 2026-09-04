> **SUPERSEDED IN PART (2026-09-02).** The numbered engineering-spec set
> (`00_PROJECT_CHARTER.md` … `10_DEMO_SUCCESS_CRITERIA.md`) is now the authoritative
> scope layer. This document is retained for its verified reasoning. **The one
> substantive change:** a *minimal* backend REST API + SQLite alert store + minimal
> SOC dashboard are now **in** the MVP (Tier 1), reinstated for the demo — see
> `DECISION_LOG.md` entry "Reinstate a minimal backend API + SOC dashboard". Tiering
> terminology also changes: "P1" here == "Tier 1" in the numbered docs. Everything
> else below still holds.

# Scope and Cuts — P1

## Deadline

Prototype demo date: **2026-09-15**. Confirmed by user on 2026-09-01 — this gives a
**14-day** build window. All scope decisions below are sized against that window, not
against the fuller pipeline originally sketched in agent configs.

## Approved P1 pipeline (user-confirmed, do not deviate)

```
dataset ingestion
  -> supported feature extraction   (only features the real dataset's fields support)
  -> Isolation Forest, trained on normal-only data
  -> thresholding                   (selected on a validation split, never on test)
  -> per-feature z-score explainability
  -> CLI alert output
  -> scripted demo
  -> static plots, if useful
```

This is the entire P1 build. Nothing beyond this list is in scope without explicit
user approval, per direct instruction.

## Explicitly OUT for P1 (deferred, not cancelled)

- **Backend API service** — no live serving layer for P1. May become P2/P3 work after
  the prototype, if there is time and the user approves.
- **Web dashboard** — confirmed by user as not mandatory for judging. Replaced for
  P1 by CLI output plus static plots (matplotlib or equivalent).

These are deferred because the 14-day window does not support building and hardening
a service layer or a UI on top of an unvalidated detection pipeline. Cutting them
first — rather than on day 12 — was a deliberate, user-approved decision.

## Scope discipline

- Any expansion beyond the pipeline above (new pipeline stages, backend API, web
  dashboard, additional model types, additional threat classes beyond the three
  named in `01-threat-model.md`) requires **explicit user approval** before work
  starts. This applies to planner, builder, and any other agent.
- Feature extraction is bounded by what the real dataset supports — do not invent or
  simulate fields to complete a threat class. If a threat class's required fields are
  absent, that class is documented as unsupported for P1, not worked around.
- No performance numbers, dataset facts, or capability claims are to be stated as
  fact anywhere in docs or code until confirmed by actually running the ingestion /
  inspection step and recording real output.
