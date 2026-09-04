# 00 — Project Charter

## Official Problem Statement

- **ID:** SIH26145
- **Organisation:** National Technical Research Organisation (NTRO)
- **Title:** AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
- **Event:** Smart India Hackathon 2026
- **Internal hackathon milestone (hard):** 2026-09-15

## Objective

Build and honestly validate a prototype intrusion-detection system that operates on
**unidirectional (one-way) IP traffic** — the traffic profile an observer sees on the
outbound side of a data diode in an OT/ICS environment — and that flags signs of
**compromise / data exfiltration / covert signalling originating from an
already-compromised device inside the protected network**.

The system is explicitly **not** a tool for preventing malicious inbound traffic:
through a true data diode, inbound flow into the protected network is *physically
impossible*. That problem is solved by the diode's hardware design. The residual,
real risk this project addresses is malicious **outbound** behaviour hidden inside
otherwise-legitimate egress traffic.

## Proposed Solution (one paragraph)

Traffic is ingested from offline PCAP (or an authorised offline capture), reduced to
**egress direction only** (all inbound discarded), and grouped into **5-second time
windows per source**. From each window we extract a small, defensible set of
behavioural features: packet/byte rates, inter-arrival-time (IAT) statistics,
protocol/function-code validity and frequency distribution, and Shannon payload
entropy (treated as one signal among several, never as a sole decision basis). An
**Isolation Forest** trained on labelled-normal egress traffic scores each window;
a deliberately simple **statistical threshold rule** is implemented alongside it
**purely as a comparison baseline** to demonstrate the value of the ML approach.
Every alert is **explainable**: it names the feature(s) that deviated most from the
learned normal baseline and shows the observed value against the baseline value.
Results are surfaced through a backend API and a minimal SOC dashboard for the demo.

## Target Users

- OT/ICS SOC analysts monitoring the low-side (unclassified/outbound) tap of a data
  diode.
- Critical-infrastructure operators (energy, water, gas, manufacturing) who use
  unidirectional gateways and currently have limited egress-anomaly visibility.
- NTRO / national-CERT-style teams assessing exfiltration risk from air-gapped or
  diode-isolated networks.

## Expected Impact

- Restores a layer of behavioural monitoring that is normally lost when
  request/response correlation is unavailable.
- Provides *explainable* egress alerts, so an analyst can triage in seconds rather
  than reverse-engineering an opaque anomaly score.
- Establishes a reproducible, leakage-controlled experimental methodology for
  one-way-traffic anomaly detection that later work can build on.

## Novelty Claim (stated as a genuine, citable contribution — not an overclaim)

Based on the research literature available to the team, **no published work has
reframed the Turnipseed / Mississippi State University SCADA gas-pipeline dataset as a
one-way / diode-observer anomaly-detection problem in which bidirectional
request-response correlation is unavailable by construction.** Existing work on this
dataset assumes full bidirectional visibility. Treating the dataset as the view of a
diode's outbound observer — and detecting compromise *without* reverse traffic — is
the original element of this submission. This claim is also recorded in
`04_DATASET_PLAN.md`.

We do **not** claim to have a real physical data-diode attack dataset. None exists
publicly. The unidirectional constraint is *simulated* by direction-filtering a
bidirectional dataset; this is labelled as a simulation everywhere it appears.

## Prototype Scope — Tiering (mandatory)

Scope is tiered. The three tiers are **not** equally in scope for the MVP.

| Tier | Meaning | Commitment |
|---|---|---|
| **Tier 1** | MVP. Must be implemented, tested and validated before 2026-09-15. | Committed |
| **Tier 2** | Stretch goals. Implemented **only** if Tier 1 is fully working and validated with days to spare. | Conditional |
| **Tier 3** | Future work. **Documented only. Not implemented in the MVP.** | Not in prototype |

### MVP = Tier 1 (this list is authoritative — it must match `02_REQUIREMENTS_SPEC.md`, `05_FEATURE_ENGINEERING_SPEC.md`, `06_AI_MODEL_EVALUATION_PLAN.md`, `07_SYSTEM_ARCHITECTURE.md`)

1. **Direction filtering** — keep egress-only traffic; discard all inbound.
2. **Time-windowed flows** — 5-second windows grouped per source.
3. **Tier 1 features only:**
   - packet count, packets/sec, bytes/sec
   - mean IAT, std-dev IAT, min IAT, max IAT
   - protocol / function-code validity + per-source frequency distribution
     (the dataset exposes Modbus-style function-code fields — see
     `05_FEATURE_ENGINEERING_SPEC.md`)
   - payload entropy (Shannon; mean + std-dev) — **documented explicitly as one
     signal among several, never the sole basis for a decision.** Entropy-only
     detection is a known weakness: an attacker can pad or fragment data to mimic
     normal entropy.
4. **Isolation Forest** trained on **normal-only** egress traffic; tested against
   labelled attacks.
5. **Naive statistical threshold baseline** (e.g. "IAT > 2× training mean")
   implemented **explicitly and only** as a comparison point to show the value of ML
   over a simple rule — never as the primary detector. Its known brittleness
   (evadable by adaptive covert channels that mimic normal timing distributions,
   e.g. IP time-replay channels) is documented in `06_AI_MODEL_EVALUATION_PLAN.md`.
6. **Basic explainability** — every alert reports which feature(s) deviated most from
   the learned normal baseline, with observed value vs baseline value.
7. **Delivery surface for the demo** — backend API, alert history store, and a
   **minimal Streamlit/Gradio dashboard** sufficient to run the
   `10_DEMO_SUCCESS_CRITERIA.md` script (green → red transition + baseline-vs-ML
   comparison view). **Hard gate:** dashboard work starts only after the core
   pipeline produces a validated `EXPERIMENT_LOG.md` entry; go/no-go **2026-09-11**;
   pre-agreed fallback is **CLI + matplotlib static plots** (`DECISION_LOG.md`).

### Tier 2 — stretch (attempt only if Tier 1 is fully validated early)

- IAT histogram distance to a learned "normal" histogram (chi-square or KS statistic)
- Per-source rolling behavioural profiles (typical IAT distribution, packet rate,
  function-code mix, payload entropy) with deviation scoring
- Frame-length anomaly detection (SCADA/Modbus frames are often fixed-length)
- Address/point distribution entropy (unique addresses/points accessed per window)
- Unauthorised device/source anomaly detection **may** be attempted here as a cheap
  bolt-on ("source identifier never seen in training") if Tier 1 finishes early;
  otherwise it defers to Tier 3.

### Explicitly OUT OF SCOPE for the prototype (Tier 3 — documented as future work only)

These appear in the documentation to show research depth. They are **not** to be
attempted in code for the MVP: each is individually complex to implement correctly,
and a subtly-wrong implementation is worse than an honest omission.

- epsilon-similarity between adjacent IATs
- multimodality indicators (number of peaks in the IAT distribution, estimated covert
  symbol count)
- approximate entropy (ApEn) of the IAT sequence
- Kolmogorov-complexity / compressibility estimate of the IAT sequence (e.g. zlib
  ratio)
- Autoencoder / LSTM-Autoencoder models
- Hybrid Isolation Forest + Autoencoder ensemble
- covert **storage** channel detection (hidden data in header/protocol fields)
- malformed / non-standard packet-structure and protocol-conformance checking
- replay / repetition anomaly detection
- unauthorised device/source anomaly detection (unless promoted per the Tier 2 note
  above)

## What Constitutes "MVP Done"

- Tier 1 pipeline runs end-to-end on the gas-pipeline dataset, offline, reproducibly.
- Isolation Forest trained on normal-only egress windows with a documented,
  leakage-controlled train/validation/test split (`04_DATASET_PLAN.md`).
- Per-attack-type detection rates reported honestly (`06_AI_MODEL_EVALUATION_PLAN.md`,
  `EXPERIMENT_LOG.md`) — including attack types the Tier 1 feature set *cannot*
  reasonably be expected to catch. Recall on this dataset is **structurally bimodal**
  (protocol-manipulation ~100 %; payload-manipulation ~0 % by egress-only design;
  see `06_AI_MODEL_EVALUATION_PLAN.md`); an aggregate recall number is never reported
  without that breakdown.
- Naive baseline implemented and compared against the model.
- Every alert carries a feature-level explanation.
- Demo script in `10_DEMO_SUCCESS_CRITERIA.md` runs green → red with explanation and
  a baseline-vs-ML comparison moment.

## Known Blockers Inherited From Dataset Reconnaissance

Recorded in full in `04_DATASET_PLAN.md` / `docs/00-dataset-provenance.md`
(resolution status as of 2026-09-03):

- **BLOCKER 1 — RESOLVED.** Label codebook transcribed from the Turnipseed (2015) MS
  thesis (§3.4–3.5, Tables 3.5–3.8) into `docs/00-dataset-provenance.md` with
  citations, and cross-checked exactly against the local ARFF `categorized × specific`
  cross-tab. `binary result` 0=normal/1=attack; `categorized result` 0..7 =
  Normal/NMRI/CMRI/MSCI/MPCI/MFCI/DoS/Recon; `specific result` 0=normal, 1–35 named
  attacks. **The metric gate is LIFTED** (label-based metrics permitted once the
  split + artifact audit pass and are recorded).
- **BLOCKER 2 — RESOLVED, CONFIRMED BY PRIMARY SOURCE.** Turnipseed (2015) §3.5.2
  p.34, verbatim: *"The value can either be a '0' for response or '1' for command."*
  `command response == 0` = response/telemetry = egress. This also matches the earlier
  data evidence (exception codes 128–142 exclusively under value 0; mean `length`
  30.9 vs 50.4). No caveat on results.
- **BLOCKER 3 — RESOLVED BY DECISION + 2026-09-04 correction.** No ARFF↔TXT join key;
  a fuzzy join is not attempted. **But the raw TXT is self-labelled**
  (`00-dataset-provenance.md` §CORRECTION), so on the TXT egress path payload entropy
  **is** evaluable against ground truth and **is a headline Isolation Forest feature**
  (pre-reg §2 amended 2026-09-04; `DECISION_LOG.md`; EXP-0002). On the ARFF path (no
  payload bytes) entropy stays a described-only mechanism.
- **BLOCKER 4 / LICENSE — PARTIALLY RESOLVED (open action item).** No explicit
  licence exists; authors request citation only. Mitigation active: raw data kept
  out of public repos; mandatory citation; team verifies terms before any public
  release. Does not block the internal demo.

Pipeline *code* can be written now. BLOCKER 1 and BLOCKER 2 are resolved (label-based
metrics permitted once the split + artifact audit pass; egress filter fixed at
`command response == 0`). BLOCKER 3 is designed around; BLOCKER 4 affects public
artifacts only.

## Status Legend (used across all docs)

`planned` → `implemented` → `tested` → `validated`. Nothing in this repository is
past `planned` as of the charter date.
