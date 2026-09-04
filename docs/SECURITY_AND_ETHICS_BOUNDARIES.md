# Security & Ethics Boundaries

Binding on all contributors and all agents working in this repository.

## Testing & Demonstration Environment

- All development, testing, and demonstration use **only**:
  - authorised datasets with documented provenance,
  - offline PCAP files,
  - synthetic / generated traffic,
  - isolated local lab environments with no route to any third-party network.
- **No third-party network scanning, probing, enumeration, or attack** of any kind.
- **No destructive payloads.** The project analyses traffic; it does not generate
  malicious traffic against real targets. Attack *examples* used for evaluation come
  from the published research dataset, replayed offline.
- The system is **passive and receive-only** by design — it consumes a one-way
  observer feed and never transmits onto a monitored network.
- **No outbound network connections** from any component at runtime (`NFR-5`,
  `NFR-6`). The pipeline runs air-gapped.

## Data Handling

- Dataset provenance, licence, and citation **must be documented** in
  `04_DATASET_PLAN.md` before any public demo or submission artifact. As of now the
  licence is **UNKNOWN — NEEDS DOCUMENTATION**; permissive terms are not assumed.
- Raw data (`data/raw/`) is read-only. Derived data goes only to `data/processed/`.
- Dataset label fields are used for evaluation only and never enter the feature or
  inference path.

## Honesty of Claims

- All simulated conditions are **labelled as simulations** — in every document, demo
  script, and slide. In particular: the unidirectional/diode constraint is
  **simulated** by direction-filtering a bidirectional dataset. These are **not real
  data-diode captures**, and no such public dataset exists.
- No performance number, dataset fact, or capability claim is stated as fact until a
  recorded experiment produces it (`EXPERIMENT_LOG.md`).
- `planned` / `implemented` / `tested` / `validated` are kept distinct.
- Tier 2 and Tier 3 items are never described as implemented.
- The novelty claim (`00_PROJECT_CHARTER.md`, `04_DATASET_PLAN.md`) is scoped to the
  team's knowledge of the literature and stated as such, not as an absolute.

## Threat-Framing Correctness

- The system is framed as **detecting signs of compromise / exfiltration in one-way
  outbound traffic**, not as "preventing malicious inflow". Inbound through a true
  data diode is physically impossible; claiming the system prevents it would be
  technically wrong (`03_THREAT_MODEL.md`).

## Status of the System

- This is a **research / prototype IDS**. It is **not** a certified production
  security appliance, has not undergone independent security assessment, and must not
  be represented as production-ready.

## Escalation

- Any proposed activity involving external data sources, network-facing tools, live
  capture beyond an isolated lab, or anything that could be construed as offensive
  must be reviewed against this document **before** work starts, and recorded in
  `DECISION_LOG.md`.
