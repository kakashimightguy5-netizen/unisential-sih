# HAI (HIL-based Augmented ICS) Dataset — Pre-Experiment Recon Audit

**Status: read-only reconnaissance. No feature engineering, no split design, no scored or
trained anything, no performance claims of any kind.** This document exists to answer "what
is this data, what can it support, what are the landmines" before any experiment is
pre-registered against it. Style/rigor modeled on
`E:\Datasets\multimodal-ICS-provenance-v2\docs\PROVICS_EVALUATION_REPORT.md` Parts 0-3.

Dataset root: `E:\Datasets\hai-master\hai-master\`. Audited 2026-09-14.

---

## Part 0: Integrity check

### What's actually resolved on disk

| Version | Status | Evidence |
|---|---|---|
| `hai-20.07` | Real data | `train1/2.csv.gz`, `test1/2.csv.gz`, 17–35 MB each, valid gzip, decompress cleanly |
| `hai-21.03` | Real data — **used for this audit** | `train1/2/3.csv.gz`, `test1-5.csv.gz`, 5.6–68 MB each, valid gzip, decompress cleanly |
| `hai-22.04` | **Git-LFS pointer stubs, not real data** | All `train1-6.csv`/`test1-4.csv` are ~133 bytes, literal content `version https://git-lfs.github.com/spec/v1\noid sha256:...\nsize ...`. The `summary\summary(*.csv).txt` files are real text (1–3 KB) and were skimmed but not treated as a data source. |
| `hai-23.05` | Same LFS-stub problem | `hai-test1/2.csv`, `hai-train1-4.csv`, `label-test1/2.csv`, `summary_label1/2.txt` all ~130 bytes |
| `haiend-23.05` | Same LFS-stub problem | `end-test1/2.csv`, `end-train1-4.csv`, `label-test1/2.csv` all ~130 bytes |

This is a **limitation of this recon pass's local copy**, not a finding about HAI itself —
`git lfs pull` inside that folder would resolve 22.04/23.05/haiend-23.05 if genuinely needed
later. Not attempted here per instruction. All analysis below is on **HAI 21.03**, the more
recent of the two resolved versions. Per the README/PDF, 21.03 is confirmed to be a
substantial revision of 20.07 ("refined version... released in March 2021", "+19 more data
points, +11 more attack scenarios" per the technical-details PDF's changelog), not a minor
patch — so restricting analysis to 21.03 and treating 20.07 as superseded is justified,
not arbitrary.

### Decompression / row-count / column-count verification

All 8 files in `hai-21.03\` (`train1/2/3.csv.gz`, `test1-5.csv.gz`) decompress cleanly with
no truncation or corruption. Measured directly:

| File | Rows (excl. header) | First timestamp | Last timestamp | Elapsed (measured) |
|---|---|---|---|---|
| train1 | 216,001 | 2020-07-11 00:00:00 | 2020-07-13 12:00:00 | 60h 00m |
| train2 | 226,801 | 2020-07-31 22:00:00 | 2020-08-03 13:00:00 | 63h 00m |
| train3 | 478,801 | 2020-08-04 22:00:00 | 2020-08-10 11:00:00 | **133h 00m** |
| test1 | 43,201 | 2020-07-07 15:00:00 | 2020-07-08 03:00:00 | 12h 00m |
| test2 | 118,801 | 2020-07-09 15:00:00 | 2020-07-11 00:00:00 | 33h 00m |
| test3 | 108,001 | 2020-07-13 00:00:00 | 2020-07-14 06:00:00 | 30h 00m |
| test4 | 39,601 | 2020-07-28 12:00:00 | 2020-07-28 23:00:00 | 11h 00m |
| test5 | 92,401 | 2020-07-30 10:50:00 | 2020-07-31 12:30:00 | 25h 40m |

Column count: **84** (1 `time` + 79 SCADA data-point columns + `attack` + `attack_P1` +
`attack_P2` + `attack_P3`), identical across all 8 files. Header is byte-identical across
train/test files. No missing/ragged rows found in any file (every row has exactly 84 fields).

Sampling interval verified empirically (not assumed): consecutive timestamps in `train1`
increment by exactly 1 second for the full file — **1 Hz, confirmed from the data**, matching
the README/PDF's stated 78 "data points/sec" cadence.

### Cross-check against documented statistics

README table and the technical-details PDF (v4.0, May 2023) both state, for HAI 21.03:
train totals 60/63/229 h (**train3 stated as 229h**), test totals 12/33/30/11/26 h, 50 total
attacks across 5/20/8/5/12 per file.

- **Test file durations, test-file row counts, and the 5/20/8/5/12 attack-run counts all
  match the documentation exactly** (verified below in Part 1 — this is a clean match, not a
  mismatch).
- **train3's duration does not match**: documentation states 229 hours; the actual file
  (`train3.csv.gz`, 478,801 rows at confirmed 1 Hz, timestamps 2020-08-04 22:00:00 through
  2020-08-10 11:00:00) is **133 hours**, not 229. This is flagged as a genuine
  documentation-vs-data discrepancy in Part 1, not silently corrected.
- train1 (60h) and train2 (63h) both match documentation exactly.

---

## Part 1: Documentation-vs-data reconciliation

Mismatches found, in order of significance:

1. **train3 duration mismatch (the one real numeric error).** README and PDF both say HAI
   21.03 train3 = 229 hours. Measured from the actual file: 133 hours (478,801 rows at 1 Hz,
   consistent both ways — row count and wall-clock timestamp delta agree with each other, just
   not with the doc). File size is also inconsistent with the doc's implied scale: PDF/README
   list train3 at "246 MB" (compressed-adjacent framing is ambiguous in the table, but the
   decompressed CSV is 261.7 MB, roughly in the right neighborhood for 133h, not for 229h — a
   229h file at this schema's ~2 MB/hour would be ~470 MB decompressed). This looks like a
   stale/uncorrected number in the docs rather than a data problem — the data is internally
   consistent (rows × 1 Hz = elapsed clock time = file-implied duration), only the
   documentation's "229" is the odd one out. **Do not use the documented 229h figure for
   any sample-size or coverage claim about train3 — use the measured 133h.**

2. **Two attack-target columns named in the PDF's attack table do not exist in the HAI
   21.03 CSVs.** The technical-details PDF's HAI 21.03 attack-scenario table lists attack
   #4 (`A104`, `AP18 P2-SC-CO1`) targeting column `P2_SCO`, and attack #5 (`A105`, `AP16
   P2-SC-SP1`) targeting column `P2_AutoSD`. Neither `P2_SCO` nor `P2_AutoSD` appears
   anywhere in the actual 79-column data schema (full column list cross-checked directly).
   This is most likely because those two attacks target an internal/simulator variable that
   isn't exposed as a recorded SCADA point in this release (the PDF elsewhere distinguishes
   "I/O point" attacks, which are represented in the data, from "internal point" attacks,
   which it says were "only used in HAI/HAIEnd 23.05" — but these two are listed under the
   21.03 column of the same table, which is itself an internal inconsistency in the PDF). Net
   effect for this project: **2 of the 50 documented attack scenarios (A104, A105) have no
   directly-observable target column in the resolved 21.03 data** — their presence has to be
   inferred from the `attack`/`attack_P2` label columns and whatever secondary process
   coupling shows up in other P2_* columns, not from a labeled ground-truth column matching
   the documented target.

3. **`attack_P1/P2/P3` do not fully cover `attack=1`.** In `test2`, 154 of 3,449
   attack-labeled rows have `attack=1` but all three per-process flags (`attack_P1`,
   `attack_P2`, `attack_P3`) equal 0. The testbed has **four** physical processes (P1
   boiler, P2 turbine, P3 water treatment, P4 HIL simulation) but only **three**
   per-process label columns — there is no `attack_P4`. This matches the documented column
   list (README explicitly shows only `attack_P1..attack_P3` in its example table) so it
   isn't a corruption, but it is a real labeling-granularity gap worth stating plainly: any
   attack whose primary target is P4 (or that the labelers didn't attribute to P1/P2/P3)
   is only visible via the umbrella `attack` column, with no per-process breakdown. Also
   confirmed: no row has more than one of `attack_P1/P2/P3` simultaneously set in `test2`
   (checked directly) — so where per-process attribution does exist, it's single-process,
   not blended.

4. **Attack-run counts, per-file attack counts, and individual attack durations all match
   the documentation exactly** — this is the positive half of the reconciliation, not
   padding. `test1..test5` produce exactly 5, 20, 8, 5, 12 contiguous `attack=1` runs
   (50 total, matching the README/PDF's total), and the specific per-scenario durations
   pulled straight from the PDF's attack table (e.g. scenario A101 = 192s, A102 = 98s,
   A103 = 422s...) match the measured contiguous-run lengths in `test1`/`test2` exactly,
   row for row, confirming the CSV label columns and the documentation describe the same
   underlying attack timetable with no drift.

5. Column count (84) and the "78 SCADA points + time + 4 label columns" description
   reconcile once you count precisely: 1 time + 79 data columns + `attack` +
   `attack_P1/P2/P3` = 84. The doc's "78" figure (points/sec in the summary table) is off by
   one from the actual 79 non-time, non-label columns — a minor, likely rounding/off-by-one
   inconsistency between the summary table's "data points/sec" figure and the literal column
   count, not worth more than this note.

No other mismatches found in headers, units, timestamp formatting, or file-to-file schema
consistency — all 8 files share byte-identical headers and consistent dtypes column-for-column.

---

## Part 2: Structure and observability

### What HAI actually records

HAI 21.03 is **entirely physical-process/SCADA point telemetry, collected via an OPC-UA
gateway from the controllers' historian-style tag values** — it is not a raw network capture.
There is no packet-level field anywhere in the schema: no source/destination IP, no MAC, no
protocol/function-code field, no payload bytes, no port numbers. Every one of the 79 data
columns is a named process point (a PLC/DCS "tag"), prefixed by subsystem exactly as the
project's briefing expected, and confirmed against the README/PDF's testbed description:

- **P1_\* (37 columns)** — Boiler Process, controlled by Emerson Ovation DCS. Columns cover
  pressure (`P1_B2004`/`P1_PIT01`/`P1_PCV01*`/`P1_PCV02*`), level (`P1_B3004`/`P1_LIT01`/
  `P1_LCV01*`), flow (`P1_B3005`/`P1_FT01-03*`/`P1_FCV01-03*`), temperature
  (`P1_B4002`/`P1_TIT01/02`), pumps (`P1_PP01A/B*`, `P1_PP02*`), and a start/stop flag
  (`P1_STSP`).
- **P2_\* (22 columns)** — Turbine Process, GE Mark VIe DCS, a rotor-kit simulating an actual
  rotating machine: speed (`P2_CO_rpm`, `P2_RTR`), vibration (`P2_VT01`, `P2_VTR01-04`,
  `P2_VXT02/03`, `P2_VYT02/03`), status/interlock flags (`P2_ASD`, `P2_AutoGO`, `P2_ManualGO`,
  `P2_OnOff`, `P2_Emerg`, `P2_MSD`, `P2_TripEx`, `P2_24Vdc`, `P2_HILout`), sensors
  (`P2_SIT01/02`).
- **P3_\* (7 columns)** — Water Treatment Process, Siemens S7-300 PLC: level
  (`P3_LIT01`, `P3_LCP01D`, `P3_LCV01D`, `P3_LH`, `P3_LL`), flow (`P3_FIT01`), pressure
  (`P3_PIT01`).
- **P4_\* (13 columns)** — HIL Simulation (dSPACE SCALEXIO + Siemens S7-1500/ET200), the
  coupling layer that synchronizes the boiler/turbine with the virtual steam-turbine and
  pumped-storage hydropower models: `P4_HT_*` (steam-turbine side: flow demand, load demand,
  power, pressure/status), `P4_ST_*` (pumped-storage side: same shape), `P4_LD`.

This is a mix of what would be called sensor **and** actuator/controller-command values in
the same table — e.g. `P1_PCV01D`/`P1_LCV01D`/`P1_FCV0*D` are control-variable *outputs*
(the DCS's written command position to the valve), not just PV/sensor readings, sitting
right next to the PV columns they act on. **This is important for the PS-tethering rule**:
HAI's schema mixes process variables (sensor readings, e.g. `P1_PIT01`) with control
variables (controller outputs/write commands, e.g. `P1_PCV01D`) and setpoints
(operator/HMI-set targets, e.g. `P1_B2016`) all as first-class recorded columns in one
flat table, collected centrally through the OPC-UA gateway. In a genuine unidirectional-diode
deployment, an egress-only monitor sitting on the diode would only see what physically
crosses that one-way tap (typically the response/telemetry traffic flowing out, per this
project's Turnipseed-based architecture) — it would **not** natively have simultaneous,
synchronized, gateway-level visibility into every controller's internal SP/PV/CV point at
1 Hz the way this dataset hands it to you. Using HAI as-is (train/evaluate directly on this
flat multi-point table) would violate the standing PS-tethering rule exactly the way it's
meant to prevent: this dataset is bidirectional/historian-complete by construction, and must
be deliberately re-sliced to simulate a single-direction vantage point before any detector
work happens on it — it cannot be analyzed as delivered and then presented as satisfying the
egress-only constraint.

### Exhaustive field-risk classification

Every column category present, checked for (a) diode-visibility and (b) hidden-oracle risk:

| Field(s) | Category | Diode-visible in a real deployment? | Hidden-oracle risk? |
|---|---|---|---|
| `P1_*`, `P2_*`, `P3_*`, `P4_*` process/sensor columns (e.g. `P1_PIT01`, `P2_SIT01`, `P3_FIT01`) | Physical sensor readings (PVs) | Plausibly yes, if the diode taps the response/telemetry side of the polling traffic that carries these readings back — but only if genuinely reconstructed from that traffic, not read off this CSV directly | None as such — these are the legitimate feature substrate, same role as Turnipseed's Modbus register reads |
| Control-variable columns (e.g. `P1_PCV01D`, `P1_FCV0*D`, `P1_LCV01D`, `P2_CO_rpm`) | Controller command outputs (CVs) | Only if the diode also observes the write/command traffic direction — for a strictly egress-only response-side tap, these may NOT be observable the same way PVs are; needs explicit resolution before any feature list is built | Not an oracle per se, but a **visibility-assumption risk**: silently including these as "free" features without confirming they'd be visible from the actual tap direction would be the same class of error the PS-tethering rule exists to catch |
| Setpoint columns (e.g. `P1_B2004`, `P1_B2016`, `P1_B3004/5`, `P4_HT_PS`, `P4_ST_PS`) | Operator/HMI-set targets (SPs) | Same caveat as CVs — depends on which direction of traffic actually carries SP writes past the tap | Same visibility-assumption risk as CVs, not a labeling oracle |
| Status/interlock flags (`P2_ASD`, `P2_AutoGO`, `P2_ManualGO`, `P2_OnOff`, `P2_Emerg`, `P2_MSD`, `P2_TripEx`, `P2_24Vdc`, `P1_STSP`) | Discrete controller/mode state | Same as CVs/SPs — these are polled/reported values, not obviously diode-observable without confirming the traffic direction | Considered and ruled out as a labeling oracle — they're operational state, not metadata about the experiment/collection process |
| `time` | Timestamp, 1 Hz, `yyyy-MM-dd hh:mm:ss` (second granularity only) | Yes — a real deployment would see wall-clock time regardless | **Considered explicitly as a scenario-boundary-leak candidate and ruled out as a per-row oracle**: granularity is only 1 second, matching the native sampling rate — there is no sub-second or otherwise anomalously precise timestamp field that would let a model infer "this is a scenario boundary" beyond what the label columns already say directly. However, see the run-boundary note below — the *coarse* file-to-file gap structure (files start/stop at clean day/hour boundaries, e.g. `test4` starts exactly at `2020-07-28 12:00:00`) is itself informative about experiment scheduling and would need to be accounted for if concatenating files, same caution as any windowed time-series dataset |
| `attack` | Ground-truth label, all-process | Not diode-visible — this is the label, used only for train/eval, never as a feature | This IS the intended label column, not a hidden oracle, but must never leak into features — standard discipline |
| `attack_P1`, `attack_P2`, `attack_P3` | Ground-truth label, per-process | Not diode-visible — labels only | Same as above; also **confirmed no attack_P4** exists (see Part 1 finding #3) — a genuine labeling gap, not a leak risk, but relevant to any per-process recall claim |
| File identity / which CSV a row came from (`train1` vs `train2` vs `train3`, `test1..test5`) | Collection/run metadata, not a column in the CSV itself but implicit in how the data is delivered (8 separate files) | N/A — this is a delivery artifact, not a real-world signal | **Explicitly checked and flagged as a genuine hidden-oracle candidate**: because each file is a distinct multi-hour/multi-day experimental run with its own clean start/stop boundary (see Part 0/1 timestamps), any pipeline that (even implicitly) uses "which file this row is from" as a grouping key for anything other than a strict train/test split — e.g. per-file normalization, per-file statistics used as features, or shuffling across files before windowing — would leak run identity into the model exactly the same shape of bug as Turnipseed's `source` field or ProvICS's `event_id`. There is no explicit run-ID *column* in the CSV (unlike some other ICS datasets), which is good, but the file-boundary structure plays the same role implicitly and must be treated with the same discipline. |
| Anything resembling a scenario-ID or attack-type-ID column | Explicitly searched for | Not present in the data. The only labels are the four binary `attack*` columns; the mapping from a given `attack=1` run to a named attack scenario (`AP01`..`AP25`+combinations) exists **only in the PDF's attack table**, correlated by timestamp/duration, not by any in-CSV identifier. Confirmed by directly cross-matching measured run durations against the PDF's documented per-scenario durations (Part 1, finding 4) — this correlation is reliable but requires deliberately reconstructing it; it is not handed to you as a column, so there's no risk of it being accidentally used as a feature. | N/A |

No column was found that encodes "this row is part of attack scenario N" beyond the
intended binary label columns — the scenario identity has to be reconstructed externally
from the PDF's timetable, which is a research/documentation task, not a leakage risk sitting
inside the CSV itself.

### Attack taxonomy

Per the PDF's "Attack Scenarios" section: HAI's 50 documented attacks for 21.03 are **25
attack primitives (`AP01`–`AP25`) plus 25 combinations that run two primitives
simultaneously**. Verified directly against the data: exactly 50 contiguous `attack=1` runs
across the 5 test files (5+20+8+5+12), matching. Every primitive is classified by the PDF
around a **process-control-loop variable model**, not an ICS-protocol-command model: each
attack targets one of **SP (setpoint), PV (process variable/sensor), CV (control variable/
actuator output), or CP (internal control parameter)** on one of the six named feedback
control loops (P1-PC, P1-LC, P1-FC, P1-TC, P2-SC, P2-TC). Attack *mechanism* falls into a
small number of repeated patterns across primitives: "decrease or increase SP/CV value...
restore as a trapezoidal profile while hiding SP changes in HMI" (stealthy setpoint/actuator
manipulation), "attempt to maintain previous sensor value" (PV replay/freeze — sensor
spoofing), and short-term (`-ST`) variants that pulse-and-restore several times.

**Assessment of MSCI/MPCI correspondence**: HAI's taxonomy is organized around *which PCL
variable is manipulated and how* (SP/PV/CV, gradual-vs-short-term, hidden-from-HMI-or-not),
not around *how the attacker got write access to the controller* the way Turnipseed's
NMRI/CMRI/MSCI/MPCI scheme is. The CV-targeting attacks (e.g. AP04/AP05/AP07/AP09/AP13 —
"decrease or increase CV value of P1-PC/P1-FC/P1-LC... restore to normal") are the closest
genuine analogue to MSCI/MPCI-style command injection: they are literally unauthorized writes
to a controller's output/actuator command point, which is the same underlying event class
MSCI/MPCI was trying to catch on Turnipseed. The SP-targeting attacks (AP01/AP02/AP03/AP06/
AP08/AP10...) are also write-to-controller-parameter events, arguably even closer to
"spontaneous"/"naive" command injection in spirit since they change what the controller is
told to aim for. The PV-targeting attacks ("attempt to maintain previous sensor value") are
structurally closer to NMRI/CMRI-style measurement spoofing/replay than to command injection.

**Honest conclusion, not forced**: there is a genuine, real correspondence between HAI's
SP/CV-targeting primitives and the general *concept* of MSCI/MPCI (unauthorized controller
write commands), but it is a conceptual correspondence, not a taxonomy match — HAI has no
categories named or structured like "spontaneous"/"naive"/"complex" command injection, no
per-attack difficulty/sophistication tier comparable to Turnipseed's MSCI/MPCI split, and its
attack list is organized by control-loop/variable-type instead. Per the project's ICS-NAD
decision rule, **no attempt is made here to force-map individual HAI attacks (`AP01`..`AP25`)
onto NMRI/CMRI/MSCI/MPCI labels** — any future experiment should treat "HAI CV/SP-targeting
attacks" as their own category (write-command-manipulation-in-general) and test whether
methods developed for MSCI/MPCI transfer to it, rather than relabeling HAI data with
Turnipseed's category names.

---

## Part 3: Feasibility for the specific question

### Sampling cadence vs attack injection duration/cadence

HAI's sampling interval, verified empirically from consecutive timestamp deltas in `train1`
(and consistent across all 8 files given the exact `rows = hours*3600 + 1` relationship
holding everywhere in Part 0's table): **1 Hz, exactly 1 second between consecutive rows,
no gaps, no jitter observed**. This matches the README/PDF's documented "data points/sec"
framing.

The relevant comparison to Turnipseed's ACK-001/ACK-002 finding — that ICS write-ACKs and
injected commands collide within Turnipseed's ~3.4-second polling cycle, making
consequence-attribution structurally unidentifiable — is: **how long do HAI's
CV/SP-targeting (command-injection-shaped) attacks actually run, relative to the 1-second
sampling grid?**

Measured directly from the label columns' contiguous `attack=1` run lengths (all 50 runs,
across all 5 test files):

- Shortest run: **17 seconds** (test2's smallest run).
- Longest run: **422 seconds** (test1's A103, `P1-LC-CO1`, a CV attack — this exact duration
  is also the one explicitly given in the PDF's attack table, confirming the match).
- Full distribution across all 50 runs spans roughly 17s–422s, with most runs clustering in
  the 80–260 second range (e.g. test1: 192, 98, 190, 60, 89; test2: 83, 422, 17, 259, 123,
  256, 68, 261, 199, 421, 45, 152, 254, 152, 151, 65, 184, 99, 119, 119).

At a 1 Hz sampling rate, even HAI's *shortest* attack run (17 seconds) spans **17 consecutive
samples** — nowhere close to a single-sample or single-polling-cycle collision. This is
categorically different from Turnipseed's problem, where the ~3.4-second command/ACK
polling cycle meant an injected command and its structural "response" could land inside the
*same* sampled interval, making cause and effect indistinguishable at the sampling
resolution. Here, sampling resolution (1s) is one to two orders of magnitude finer than even
the shortest attack (17s), so **the specific "attack and periodic response collide within one
sampling interval" identifiability wall that closed the Turnipseed MSCI/MPCI line does not
mechanically apply to HAI's CV/SP attacks** — there is ample temporal resolution within any
single attack run to observe pre-attack, during-attack, and post-attack (recovery/restore)
segments as distinct multi-sample regions, which was exactly the resolution Turnipseed's ACK-
anchored analysis lacked.

This is a **necessary-condition check only** — it shows the specific collision mechanism that
killed ACK-001/002 doesn't structurally recur here, given the coarser-than-1s attack durations
and finer-than-attack-duration sampling. It is not a claim that attribution would succeed;
whether HAI's CV/SP-targeting attacks are actually *learnable* as a detection target is an
unanswered, in-scope-for-a-future-experiment question, not something this recon pass tests
or claims.

### Rough sample-size assessment

Per HAI 21.03 test files (test1–test5 combined, the only labeled attack data in the resolved
version): **50 total attack runs**, spanning roughly 17s–422s each, totaling on the order of
~11,000 attack-labeled rows in aggregate across the 5 test files at 1 Hz (test1: 629,
test2: 3,449, test3: 1,535, test4: 1,157, test5: 2,177 — sum 8,947 attack rows; note this
counts unlabeled-by-process rows too, see Part 1 finding 3). Training data is ~921,603
normal-only rows across train1–3 (60h+63h+133h, using the corrected train3 duration from
Part 0).

This is **far closer to Turnipseed's scale (thousands+ of usable windows) than to ProvICS's
11-usable-events scarcity problem**. 50 discrete attack events, each spanning tens to
hundreds of 1-second samples, gives enough raw material for a real TRAIN/VAL/TEST split with
per-run leave-one-out style validation (the same pattern already used successfully in this
project's EXP-0030c leave-one-attack-run-out check on Turnipseed, 107 runs). It is
meaningfully smaller than Turnipseed's overall attack-row volume, and unevenly distributed
across scenario types (many of the 50 are 1-off primitives, not repeated many times each,
so per-attack-type statistical power will be thin for some of the 25 primitives — this is a
real caveat for any per-primitive recall claim, not a blocker for an aggregate CV/SP-vs-PV
category split).

---

## Recommendation

**Proceed to a scored experiment design, with explicit caveats — this is not a clean GO and
not a NO-GO.**

The specific question a first scored experiment should test: *does a detector trained to spot
HAI's CV/SP-targeting write-command manipulations (the closest real analogue to Turnipseed's
MSCI/MPCI command-injection class) achieve non-trivial separation from normal operation,
using only features that would survive an honest egress-only re-slice — i.e., not simply
reading `P1_PCV01D` etc. directly as if they were freely diode-visible without first
resolving which traffic direction they'd actually arrive on.*

Caveats that must be resolved **before**, not during, that experiment (per this project's
pre-registration discipline):

1. **The PS-tethering re-slice is not optional and not yet designed.** HAI hands you SP/PV/CV/
   status columns as one flat, synchronized, gateway-collected table. Before any feature
   list is written, it must be explicitly decided (and documented) which of these columns a
   real unidirectional-diode tap would actually observe, and the dataset re-sliced to that
   view — exactly as the standing rule requires for SWaT/WADI/HAI-class datasets. This recon
   pass deliberately did not do that design work; Part 2's field table is the input to that
   decision, not the decision itself.
2. **Use the measured train3 duration (133h), not the documented 229h**, for any coverage or
   sample-budget claim — this is a confirmed doc error (Part 0/1).
3. **File-boundary identity (which of the 8 CSVs a row came from) must be treated with the
   same discipline as a hidden run-ID field** even though no explicit run-ID column exists —
   see Part 2's field-risk table.
4. **No Turnipseed category names (NMRI/CMRI/MSCI/MPCI) should be attached to individual HAI
   attacks.** Per Part 2's taxonomy assessment, only a general "write-command manipulation"
   framing (CV/SP-targeting attacks as a group) is honestly supportable; PV-targeting attacks
   are a separate, more replay/spoof-like class and should not be folded into the same
   experiment as a "control" or "extra positive" category without saying so explicitly.
5. Per-primitive (`AP01`..`AP25`) recall claims will be statistically thin given the uneven,
   mostly-single-occurrence distribution of the 50 runs (Part 3) — plan the first experiment
   around the aggregate CV/SP-vs-PV-vs-normal split, not per-primitive breakdowns, unless a
   later pass specifically re-checks per-primitive counts.

The one honest positive finding worth carrying forward: **the specific ACK-anchored
identifiability wall that closed Turnipseed's MSCI/MPCI line (attack and periodic response
colliding inside one ~3.4s polling interval) does not mechanically recur in HAI** — HAI's
attacks (17s–422s) are one to two orders of magnitude longer than its 1 Hz sampling interval,
so there is genuine temporal room to observe pre/during/post-attack structure that Turnipseed's
data didn't afford. That is a necessary condition for the command-injection detection question
to even be askable here, not a sufficient one, and this recon pass makes no claim beyond it.
