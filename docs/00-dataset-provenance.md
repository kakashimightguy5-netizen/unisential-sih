<!-- Companion to 04_DATASET_PLAN.md. This file is the AUTHORITATIVE source for
     measured dataset facts (hashes, counts, missingness, blockers). 04_DATASET_PLAN.md
     is authoritative for the dataset-plan narrative, simulation method, and pipeline. -->

# Dataset Provenance

All facts in this document come from `scripts/inspect_dataset.py` run on 2026-09-01,
recorded in `data/reconnaissance/2026-09-01-dataset-reconnaissance.md` and
`data/reconnaissance/dataset_inspection.json`. Nothing here is asserted from memory.

## What this data is — and is not

This project uses the **Mississippi State University SCADA Laboratory gas pipeline
dataset** (Morris et al. testbed family). We extract only the egress-direction
traffic to approximate what an observer sitting on the outbound side of a data diode
would see.

**This is a dataset-based unidirectional SIMULATION, NOT a physical data-diode
capture.** No public dataset of real physical data-diode attacks exists. Every doc,
demo script, slide and README statement must describe the substitution in these
terms. Claiming or implying that these are diode captures is a factual error, not a
presentational shortcut.

Consistent with `01-threat-model.md`: the diode blocks 100% of inbound traffic as a
hard hardware guarantee. This dataset is used only to exercise detection of anomalous
*outbound* behaviour.

## Attribution

From the ARFF header (`data/raw/IanArffDataset.arff`, lines 1-8, verbatim source):

- Mississippi State SCADA Lab — Gas Pipeline Dataset
- Author: Ian Turnipseed
- Advisor: Dr. Morris
- Header date: Fri Dec 19 09:53:19 2014

### Authoritative provenance source (obtained 2026-09-02)

The primary authoritative source for dataset semantics and provenance is the author's
thesis, held locally at **`docs/references/turnipseed-2015-scada-dataset-thesis.pdf`**
(do not modify):

> Turnipseed, Ian P. *A New SCADA Dataset for Intrusion Detection System Research.*
> M.S. thesis, Mississippi State University, August 2015. Theses and Dissertations,
> 209. Major Professor: Thomas H. Morris.
> https://scholarsjunction.msstate.edu/td/209

Companion paper (same taxonomy, cited by the thesis):

> Morris, T., Thornton, Z., Turnipseed, I. *Industrial Control System Simulation and
> Data Logging for Intrusion Detection System Research.* (2015).

The thesis is distributed by Scholars Junction as **"Graduate Thesis — Open Access …
brought to you for free and open access"** (thesis front matter). This covers the
*thesis document*; the *dataset* licence is handled separately under **BLOCKER 4**
below — no explicit dataset licence text has been located, and the mitigation there
(keep raw data out of public repos; mandatory citation; verify terms before public
release) stands.

All label-semantics facts in the "Open provenance blockers" section below that are
marked **RESOLVED (thesis, 2026-09-02)** were verified by direct extraction from this
PDF (`pdftotext -layout`), cross-checked against the local ARFF's observed label
domains, and are cited to thesis table / page.

## File inventory (verified)

| file | bytes | sha256 | status |
|---|---|---|---|
| `data/raw/IanArffDataset.arff` | 18340346 | `970a7bcd3949d09ac7baff11603538b142f214ee47ed70baf9efb3344f4af459` | **AUTHORITATIVE** |
| `data/raw/gas_pipeline_raw.txt` | 14234301 | `45de4266d75553c8e658113ec4d43967c1de3ddaf38bb7022ad0a135b635fbbd` | supporting only |
| `data/processed/gas_pipeline_ml_ready.csv` | 11349508 | `53d501c63362c25af3b3de702b1a99220af251d00d3afe93e5698ffdf2fc924d` | **DISCARD** |

Everything under `data/raw/` is read-only. Any regeneration writes to
`data/processed/` only.

## Authoritative file: `IanArffDataset.arff`

- ARFF relation name: `gas`
- `@data` begins at file line 31
- 20 attributes (full schema in `02-feature-schema.md`)
- **274,628 instances verified** by direct parse (re-verified 2026-09-02: 274,628
  data rows, 0 rows with a field count other than 20)
- Rows with a field count other than 20: **0** (no malformed records)
- Exact duplicate full rows: **0**

### Dataset-count discrepancy — thesis 274,627 vs local ARFF 274,628 (+1). DOCUMENTED, NOT NORMALISED.

- **Thesis statement (Turnipseed 2015, §3.5, p.27, verbatim):** *"There are a total
  of 274,627 instances in each dataset."* (The validation section, p.42, separately
  refers to *"275,000 instances"* as a round figure.)
- **Local `IanArffDataset.arff`:** **274,628** data rows — verified twice by
  independent parse, 0 malformed rows, 0 duplicate rows, 0 duplicate timestamps.
- **Difference: +1 row in the local file.**
- **Disposition:** this is a **dataset-version / artifact discrepancy**, recorded and
  left as-is. **No local ARFF row is removed or altered to force the thesis count.**
  The **local ARFF remains the implementation artifact**; the **thesis remains the
  semantics / provenance authority**. The one-row difference is immaterial to label
  semantics — every observed label domain is valid and complete (see
  "Local ARFF label-domain cross-check" below). Plausible causes (not asserted):
  an off-by-one in the thesis's stated count, a boundary/blank-line counting
  difference, or a minor revision of the distributed file after the thesis was
  written. Not resolvable without the dataset authors; not worth pursuing for the
  prototype. Mirror note kept in `EXPERIMENT_LOG.md`.

### Timestamps

- min `time`: 1418682163.170388 = 2014-12-15T22:22:43.170388Z
- max `time`: 1418957854.165377 = 2014-12-19T02:57:34.165377Z
- span: approximately 3.2 days of continuous capture
- strictly increasing in file order: **True**
- distinct timestamp strings: 274,628; duplicate timestamps: **0**

One row per distinct timestamp means file order is a true temporal order. This is
what makes the contiguous time-block split in `03-data-split-protocol.md` possible.

## The ARFF-vs-TXT discrepancy

`data/raw/gas_pipeline_raw.txt` is a **different schema** and is NOT a raw form of
the ARFF:

| | ARFF | TXT |
|---|---|---|
| schema | 20 named attributes | 6 comma-separated fields |
| rows | 274,628 | 209,668 data rows (+1 row with 1 field) |
| labels | yes (3 label fields) | **yes — 2 label fields (see correction below)** |
| payload bytes | **none** | yes (field 1, hex Modbus-style frame) |
| timestamp range | 1418682163.170388 .. 1418957854.165377 | 1418682163.170388 .. 1418892346.279671 |

The two files share a start timestamp and overlap in range, which suggests the same
testbed campaign — but they are **not row-aligned** (274,628 vs 209,668) and there is
**no documented join key**. Per-row correspondence has not been, and currently cannot
be, established.

### CORRECTION (2026-09-04): the TXT **is** labelled

The 2026-09-01 reconnaissance recorded the TXT as having "no labels". **That was
wrong.** The 6 fields are:

`<hexframe> , <categorized_attack 0-7> , <specific_attack 0-35> , <source> , <destination> , <timestamp>`

Verified 2026-09-04 by direct parse (`ml/features_txt.py`):
- Field 2 domain = `{0..7}`, field 3 domain = `{0..35}` with **no gaps**.
- The `categorized x specific` cross-tab from the TXT reproduces the thesis BLOCKER 1
  codebook **exactly** (NMRI<->{29-32}, CMRI<->{25-28,33-35}, MSCI<->{13-17},
  MPCI<->{1-12}, MFCI<->{19,21,22}, DoS<->{18}, Recon<->{20,23,24}). An **independent
  second confirmation** of the codebook from an artifact we did not know was labelled.
- Attack rate 22.0% (46,102 / 209,668) — matches the thesis's 21.9%.
- Rows are in **strict ascending-timestamp order** (0 out-of-order), so a contiguous
  time-block split is directly available on this file.
- `metadata_1..4_unverified` in `gas_pipeline_ml_ready.csv` are fields 2-5 of the TXT
  (labels + source + dest); the CSV **is row-aligned** to the TXT
  (`record_index` = line number). The converter just did not recognise them.

**Consequence:** payload entropy **can** be evaluated against labels using the TXT
alone — no ARFF join needed for that path, so **BLOCKER 3 does not gate a TXT-based
entropy evaluation**. BLOCKER 3 still stands for anything needing payload bytes joined
to the *ARFF's* 274,628-row label set.

**Caveats — TXT labels not yet promoted to authoritative:**
1. The TXT is a **smaller, different capture** than the ARFF (209,668 vs 274,628; TXT
   ends earlier). May be a subset or earlier revision; provenance chain thinner than
   the ARFF's even though its label semantics reproduce the thesis.
2. `source` / `destination` are **label-leaking lab artifacts, not wire-observable**:
   `source == 1` (master) is 100% Normal, `source == 2` (MITM injection rig) is 100%
   attack (0 Normal), `source == 3` (slave) is mixed. NMRI and CMRI frames **only**
   carry `source == 2`. Any model using `source` is cheating; a diode observer cannot
   see it.
3. The trailing 2 bytes do **not** validate as a standard Modbus RTU CRC-16 (~0% of
   *normal* frames pass), so no "bad CRC" flag can be derived — relevant because DoS
   here is the Bad-CRC attack (specific 18).

The TXT is still the **only** source of payload bytes in the repo. Mean per-frame
Shannon entropy across the 209,668 decoded frames is 3.1327 bits/byte. The ARFF
contains no raw payload bytes, so entropy is not recomputable from the authoritative
file (payload-entropy capability is PARTIALLY SUPPORTED for the ARFF path — see
`02-feature-schema.md`).

## Disposition of `data/processed/gas_pipeline_ml_ready.csv` — DISCARD

Decision: **discard and regenerate from the ARFF.** Reasons, all verified:

1. Wrong source of truth. It has 209,668 rows and is derived from the TXT (and an
   attached markdown paste, see `data/reconnaissance/conversion_report.txt`), not
   from the authoritative 274,628-row ARFF.
2. It carries **no label column**, so it cannot support any evaluation.
3. Four of its nine columns are named `metadata_1_unverified` ..
   `metadata_4_unverified` — the converter itself did not know their semantics.
4. It bakes in `interarrival_seconds` computed in raw record order, before any
   direction filtering or time-block split. Using it as-is risks leakage across the
   split boundary (`03-data-split-protocol.md`).

Do not build features on this file. It should not be deleted from history yet (it is
evidence of the recon finding), but it must not be an input to any pipeline stage.

## Open provenance blockers

Status as of **2026-09-02**: BLOCKER 1 and BLOCKER 2 **RESOLVED** from the Turnipseed
(2015) thesis (`docs/references/turnipseed-2015-scada-dataset-thesis.pdf`).
BLOCKER 3 resolved by decision. BLOCKER 4 partially resolved (open action item).

### BLOCKER 1 — Label codebook. RESOLVED (thesis, 2026-09-02).

Source: Turnipseed (2015), §3.4–3.5. Verified by `pdftotext -layout` extraction and
cross-checked against the local ARFF's observed label domains (see
"Local ARFF label-domain cross-check" below — the thesis `specific → category`
mapping matches the local ARFF `categorized × specific` cross-tab **exactly for all
35 attack IDs**).

#### `binary result` (thesis feature name: "binary attack")
- **0 = normal traffic**
- **1 = attack traffic**

Basis: the thesis types this feature as **"Label"** (Table 3.4, p.35) and states that
for *"a normal operation Modbus frame … [the label] features will report a zero"*
(§3.5.1, p.28). Table 3.11 (p.42) frames the dataset split as *"Percentage of Attack
Instances … Percentage of Normal Instances"* — **New Dataset: 21.9% attack / 78.1%
normal**, which matches the local ARFF exactly (`binary result` 1 = 60,048 =
21.86%; 0 = 214,580 = 78.14%). The thesis has no single one-sentence
"0 = normal / 1 = attack" definition, but the meaning is unambiguous from the feature
name, its Label type, the normal-is-zero convention, and the matching split. In the
local ARFF every `binary result == 0` row is also `categorized result == 0` (exact:
214,580 = 214,580).

#### `categorized result` (thesis feature name: "categorized attack") — Table 3.1 (p.24) / Table 3.5 (p.36)

| value | abbreviation | full category name | over-arching family (thesis §3.5, p.36) | threat type (Table 3.1) |
|---|---|---|---|---|
| **0** | Normal | Normal | — | N/A |
| **1** | NMRI | Naïve Malicious Response Injection | response injection | Modification/Fabrication |
| **2** | CMRI | Complex Malicious Response Injection | response injection | Modification/Fabrication |
| **3** | MSCI | Malicious State Command Injection | command injection | Modification/Fabrication |
| **4** | MPCI | Malicious Parameter Command Injection | command injection | Modification/Fabrication |
| **5** | MFCI | Malicious Function Code Injection | command injection | Modification/Fabrication |
| **6** | DoS | Denial of Service | denial of service | Interruption |
| **7** | Recon | Reconnaissance | reconnaissance | Interception |

Thesis descriptions (§3.5, pp.36–40, paraphrased from Gao [7]/[30]):
- **NMRI** — response-injection with *"sporadic and out of bounds behavior that would
  not be present in normal operation"*; attacker lacks physical-process knowledge.
- **CMRI** — response-injection that *"mimic[s] certain behaviors which occur within
  normal bounds"* to evade detection / hide state changes.
- **MSCI** — command-injection that modifies the *state* of the physical process
  (can force a critical state).
- **MPCI** — command-injection that modifies *parameters* (set point, PID config).
- **MFCI** — command-injection that *"inject[s] commands which exploit network
  protocol commands to change the behavior of the network."*
- **DoS** — *"attempt to disrupt communications between the control and the
  process."*
- **Recon** — *"designed to collect information about the system through some passive
  gathering, or by forcing information from a device"* (network info; device
  characteristics; supported function codes).

#### `specific result` (thesis feature name: "specific attack") — Tables 3.6 (p.37), 3.7 (pp.38–39), 3.8 (p.40)

`specific result == 0` = **normal traffic** (thesis §3.5.1, p.28: normal frames
report zero for both the category and specific-attack features). Values 1–35 are
individual attacks. Where the thesis lists a range (e.g. "1-2"), each number in the
range is a variant of the same named attack — typically one *outside* and one
*inside* the range of normal operation (per the Table 3.6 description wording); the
thesis does **not** further distinguish the individual numbers, so neither do we.

| specific | attack name (thesis) | parent category | thesis description (verbatim / near-verbatim) |
|---|---|---|---|
| 0 | (Normal) | Normal (0) | normal operation frame |
| 1–2 | Setpoint Attacks | MPCI (4) | "Changes the pressure set point outside and inside of the range of normal operation." |
| 3–4 | PID Gain Attacks | MPCI (4) | "Changes the gain outside and inside of the range of normal operation." |
| 5–6 | PID Reset Rate Attacks | MPCI (4) | "Changes the reset rate outside and inside of the range of normal operation." |
| 7–8 | PID Rate Attacks | MPCI (4) | "Changes the rate outside and inside of the range of normal operation." |
| 9–10 | PID Deadband Attacks | MPCI (4) | "Changes the dead band outside and inside of the range of normal operation." |
| 11–12 | PID Cycle Time Attacks | MPCI (4) | "Changes the cycle time outside and inside of the range of normal operation." |
| 13 | Pump Attack | MSCI (3) | "Randomly changes the state of the pump." |
| 14 | Solenoid Attack | MSCI (3) | "Randomly changes the state of the solenoid." |
| 15 | System Mode Attack | MSCI (3) | "Randomly changes the system mode." |
| 16–17 | Critical Condition Attacks | MSCI (3) | "Places the system in a Critical Condition. This condition is not included in normal activity." |
| 18 | Bad CRC Attack | DoS (6) | "Sends Modbus packets with incorrect CRC values. This can cause denial of service." |
| 19 | Clean Registers Attack | MFCI (5) | "Cleans registers in the slave device." |
| 20 | Device Scan Attack | Recon (7) | "Scan for all possible devices controlled by the master." |
| 21 | Force Listen Attack | MFCI (5) | "Forces the slave to only listen." |
| 22 | Restart Attack | MFCI (5) | "Restart communication on the device." |
| 23 | Read Id Attack | Recon (7) | "Read ID of slave device. The data about the device is not recorded, but is performed as if it were being recorded." |
| 24 | Function Code Scan Attack | Recon (7) | "Scans for possible functions that are being used on the system. The data … is not recorded, but is performed as if it were being recorded." |
| 25–26 | Rise/Fall Attacks | CMRI (2) | "Sends back pressure readings which create trends on the pressure reading's graph." |
| 27–28 | Slope Attacks | CMRI (2) | "Randomly increases/decreases pressure reading by a random slope." |
| 29–31 | Random Value Attacks | NMRI (1) | "Random pressure measurements are sent to the master." |
| 32 | Negative Pressure Attack | NMRI (1) | "Sends back a negative pressure reading from the slave." |
| 33–34 | Fast Attacks | CMRI (2) | "Sends back a high set point then a low setpoint which changes 'fast'." |
| 35 | Slow Attack | CMRI (2) | "Sends back a high setpoint then a low setpoint which changes 'slow'." |

**Cross-check (local ARFF `categorized × specific`, from reconnaissance §8):** every
specific-attack ID above falls under exactly the parent category the local ARFF
assigns it — NMRI(1)↔{29,30,31,32}; CMRI(2)↔{25,26,27,28,33,34,35};
MSCI(3)↔{13,14,15,16,17}; MPCI(4)↔{1..12}; MFCI(5)↔{19,21,22}; DoS(6)↔{18};
Recon(7)↔{20,23,24}. **No mismatch.** This mutual agreement between the thesis and
the independently-parsed local file is strong corroboration of the codebook.

**Effect:** the BLOCKER 1 metric gate in `05-evaluation-plan.md` /
`06_AI_MODEL_EVALUATION_PLAN.md` is **LIFTED**. Label-based metrics may be computed
once the split + artifact audit pass. `specific result` 0 and `categorized result` 0
and `binary result` 0 all denote normal; the normal-only training subset is
`binary result == 0` (equivalently `categorized result == 0`).

### BLOCKER 2 — Direction semantics of `command response`. RESOLVED — CONFIRMED BY PRIMARY SOURCE (thesis, 2026-09-02).

This is a verbatim primary-source definition, not an inference. It is recorded here
at a strictly higher confidence than the `binary result` mapping above (which is
very-high-confidence but not verbatim-quoted).

`command response` is nominal {0,1}, split near-evenly: **0 → 137,013, 1 → 137,615**
(local ARFF, re-verified 2026-09-02).

**Thesis definition — Turnipseed (2015), §3.5.2, p.34, feature 16, verbatim:**

> *"The sixteenth feature is provided to allow an IDS to learn the difference between
> commands and responses. The value can either be a '0' for response or '1' for
> command. This information is not parsed from the Modbus frame itself, but rather is
> provided to aid in the preprocessing step."*

Therefore, **authoritatively**:
- **`command response == 0` → RESPONSE frame** (slave → master; telemetry / sensor
  readings / acknowledgements)
- **`command response == 1` → COMMAND frame** (master → slave; polls / reads /
  writes)

The thesis also lists `command response` type = **"Network"** (Table 3.4, p.35).

This **confirms** the earlier data-driven inference: Modbus exception-response
function codes 128–142 (incl. 136) appear exclusively under value 0 in the local ARFF
cross-tab — consistent with value 0 being the response side.

**Direction chosen for the diode simulation.** Per `04_DATASET_PLAN.md`, the egress
stream is *"traffic leaving the protected OT network"* — i.e. the outbound telemetry
that a diode exports to the low side. In this testbed that is the **RESPONSE**
direction (RTU/slave sensor data flowing out toward the master/historian), so the
direction filter keeps **`command response == 0`** (~137,013 rows). This matches the
pre-registered constraint in `EXPERIMENT_LOG.md`. A labelled **`command response == 1`
sensitivity run** remains planned as a secondary check.

**Note:** actual production direction filtering is an implementation step and has
**not** been performed. Only the semantics and the plan's already-specified direction
are recorded here.

### BLOCKER 3 — TXT-to-ARFF linkage. RESOLVED BY DECISION (no join attempted), 2026-09-02.
No reliable join key exists between the **labelled ARFF** (274,628 rows, 20-attr
`gas` schema, timestamps to 2014-12-19T02:57:34Z) and the **payload-bearing raw
TXT** (`gas_pipeline_raw.txt`, 209,668 usable rows, different 6-field schema, no
labels, timestamps truncated earlier at ~2014-12-19T00:45Z). The files are not
row-aligned (~65k row difference), cover different time spans, and share no
documented key. Provenance of the TXT (how it was produced, meaning of its 4
unlabelled integer fields) is undocumented.

**Decision:** **do NOT attempt a fuzzy timestamp join.** A nearest-timestamp match
is fragile (unequal row counts, unequal coverage, no 1:1 guarantee) and any match
error would silently corrupt the entropy labels — worse than an honest omission.

**Consequence for the pipeline:**
- Payload entropy (`payload_entropy_mean`, `payload_entropy_std`) remains a **Tier 1
  mechanism**, computed and demonstrated on TXT frames and/or synthetic fixtures.
- It is **excluded from the headline precision / recall / F1 / PR-AUC / ROC-AUC**
  metrics computed against dataset labels. The Isolation Forest headline evaluation
  runs on the non-entropy Tier 1 features (rates, IAT statistics, function-code
  validity + distribution), all of which derive from the authoritative ARFF.
- Threat scenario **TS-5 (payload entropy anomaly)** appears in the per-attack-type
  table (`06_AI_MODEL_EVALUATION_PLAN.md`, `EXPERIMENT_LOG.md`) as:
  **"mechanism demonstrated on fixtures; not evaluable against dataset labels
  (BLOCKER 3)."**
- Regenerating a real key would require the original PCAPs from the dataset authors
  — out of scope for the Sep 15 timeline; recorded as future work.

### BLOCKER 4 — Dataset licence / redistribution terms. PARTIALLY RESOLVED — open action item, 2026-09-02.
**Findings (web check, 2026-09-02):**
- **No explicit licence text exists** for this dataset. Prof. Tommy Morris's official
  UAH ICS datasets page carries **no licence statement** — only a request to *cite
  the source paper*
  (`https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets`).
- The DHS/IMPACT mirror record (`impactcybertrust.org`, dataset id 1322,
  DOI `10.23721/100/1504364`) tags it "unrestricted access / commercial allowed" but
  **explicitly states it is a non-IMPACT record not controlled by IMPACT** and
  disclaims all warranties. This third-party tag is **not authoritative.**
- The dataset is widely redistributed in academic repos / GitHub / Kaggle with no
  known enforcement — but that is not a licence grant.

**Plain assessment:**
| Use | Verdict |
|---|---|
| (a) student hackathon prototype | Almost certainly permitted — created and published for open IDS research/education. |
| (b) derived/processed data in our repo | Probably OK, not explicitly granted. Mitigation below. |
| (c) public demo / submission of results | Permitted **with mandatory citation** + simulation disclosure. |

**Mitigation adopted (effective now):**
1. Raw dataset files (`data/raw/IanArffDataset.arff`, `data/raw/gas_pipeline_raw.txt`)
   are **kept OUT of any public repository.** A **download script + SHA-256
   checksums** is committed instead of the data itself.
2. Any public result, slide, video, or repo must **prominently cite**:
   - Turnipseed, I. (2015). *A New SCADA Dataset for Intrusion Detection System
     Research.* MS thesis, Mississippi State University.
   - Morris, T., Thornton, Z., Turnipseed, I. (2015). *Industrial Control System
     Simulation and Data Logging for Intrusion Detection System Research.*
   and disclose that the unidirectional/diode constraint is **simulated** by
   direction-filtering a bidirectional dataset.

**OPEN ACTION ITEM (does NOT block the 2026-09-15 internal demo):** before any
public submission or public repository push, a team member must personally open the
official UAH dataset page and Turnipseed's thesis, read the current stated
terms/citation request, and — if redistribution of the raw data is planned — email
Prof. Morris for written confirmation. Record the outcome here and add a
`CITATION.cff` / `DATASET_LICENSE.md` to the repo.

## Local ARFF label-domain cross-check (2026-09-02, non-destructive)

`data/raw/IanArffDataset.arff` was re-parsed **without modification** and its observed
domains for the four semantics-critical fields checked against the thesis:

| field | observed domain (value → count) | expected (thesis) | verdict |
|---|---|---|---|
| `command response` | `0 → 137,013`, `1 → 137,615` | {0,1}: 0=response, 1=command | ✅ domain matches; no unexpected values; 0 missing |
| `binary result` | `0 → 214,580`, `1 → 60,048` | {0,1}: 0=normal, 1=attack | ✅ domain matches; 0 missing; 21.86% attack ≈ thesis 21.9% |
| `categorized result` | `0→214,580 1→7,753 2→13,035 3→7,900 4→20,412 5→4,898 6→2,176 7→3,874` | {0..7} | ✅ all 8 values present; no value >7; 0 missing |
| `specific result` | 36 distinct values `0..35`, **no gaps**; `0 → 214,580`; 1–35 range 666–2,204 each | {0..35} | ✅ all 36 values present; none outside 0–35; 0 missing |

- **Data rows:** 274,628. **Rows with field count ≠ 20:** 0. **`?` (missing) in any of
  the four fields:** 0.
- **Internal consistency:** every `binary result == 0` row is also
  `categorized result == 0` (214,580 = 214,580). Every `specific result` 1–35 nests
  under exactly one `categorized result` 1–7, matching the thesis (see BLOCKER 1
  cross-check).
- **Unexpected values:** none.
- Note the +1-row count discrepancy vs the thesis (274,628 local vs 274,627 stated) —
  documented above under "Dataset-count discrepancy", not normalised.

No training, splitting, or direction selection was performed for this check.

## Related docs

`01-threat-model.md` (threat classes), `02-feature-schema.md` (attribute-level
usability), `03-data-split-protocol.md` (split), `05-evaluation-plan.md` (what may be
reported), `07-scope-and-cuts.md` (P1 boundary).
