#!/usr/bin/env python3
"""EXP-0013 — first genuinely TEST-blind frozen Type 1 DoS evaluation.

Built on the corrected split manifest ``verified-egress-5s-exp0008-pretest-v1``
after the boundary-construction flaw invalidated the TEST-adjacent results of
EXP-0008, EXP-0009, and EXP-0011. The frozen configuration is EXP-0011b's model
recipe (Borderline-SMOTE + Random Forest, threshold 0.50) retrained fresh on the
corrected manifest's TRAIN population and scored exactly once against the
manifest-derived guarded TEST population.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
from importlib.metadata import version
from pathlib import Path
from typing import Iterable, Mapping

import numpy as np

from exp0008_cadence import _cohort, _labels, _matrix, _test_block, binary_metrics
from exp0008_cadence_features import (
    EXPECTED_PRETEST_MEMBERSHIP_SHA256, EXPECTED_PRETEST_SPLIT_ID,
    build_scoring_windows, load_pretest_split, prepare_pretest_artifacts,
)
from exp0011_validation import FINAL_FINGERPRINT, fit_final_0011b, prepare_matrices
from features_txt import FrameRecord

RESULT_PATH = (
    Path(__file__).resolve().parent.parent / "data" / "experiments"
    / "exp0013_frozen_test.json"
)
FROZEN_TEST_CONFIRMATION = "SCORE-EXP-0013-FROZEN-TEST-ONCE"
PROBABILITY_THRESHOLD = 0.50
EXPECTED_SPLIT_ID = "verified-egress-5s-exp0008-pretest-v1"
EXPECTED_MEMBERSHIP_SHA256 = (
    "0e912e147d088aaed05e95bda04c6a46c72ed4dd16aafb6966c9e2aab26859e6"
)

# Historical numbers retained for the audit trail only. EXP-0008/0009/0011 all ran
# through the flawed ``partition_pretest_inputs()`` and are NOT constructionally
# TEST-blind; EXP-0005b is bidirectional and out of scope; EXP-0004 used a
# different cohort. None of these is comparable to the EXP-0013 result.
COMPARISON_CONTEXT = {
    "EXP-0004": {
        "status": "CONTEXT — egress-only Isolation Forest; different cohort",
        "scope": "egress-only; 136 dominant-DoS category row, not this DoS cohort",
        "precision": None, "recall_or_flag_rate": 0.0, "f1": None,
        "fpr": 0.007489,
    },
    "EXP-0005b": {
        "status": "OUT OF SCOPE — bidirectional traffic",
        "scope": "bidirectional; 193 DoS versus 4,931 Normal",
        "precision": 0.6302521008403361,
        "recall": 0.38860103626943004,
        "f1": 0.4807692307692308,
        "fpr": 0.008923139322652606,
        "tn": 4887, "fp": 44, "fn": 118, "tp": 75,
    },
    "EXP-0008-detector-a": {
        "status": (
            "INVALIDATED — boundary-construction flaw, not constructionally "
            "TEST-blind, retained for audit trail only"
        ),
        "scope": "egress-only CUSUM; historical TEST cohort",
        "precision": 0.0, "recall": 0.0, "f1": 0.0, "fpr": 0.0,
        "tn": 4807, "fp": 0, "fn": 193, "tp": 0,
    },
    "EXP-0008-detector-b": {
        "status": (
            "INVALIDATED — boundary-construction flaw, not constructionally "
            "TEST-blind, retained for audit trail only"
        ),
        "scope": "egress-only Random Forest; historical TEST cohort",
        "precision": 0.6341463414634146,
        "recall": 0.2694300518134715,
        "f1": 0.3781818181818182,
        "fpr": 0.006240898689411275,
        "tn": 4777, "fp": 30, "fn": 141, "tp": 52,
    },
    "EXP-0009b": {
        "status": (
            "INVALIDATED — boundary-construction flaw; VALIDATION-only, never "
            "frozen-TEST scored; retained for audit trail only"
        ),
        "scope": "VALIDATION only; threshold 0.60",
        "precision": 0.9298245614035088,
        "recall": 0.5221674876847291,
        "f1": 0.668769716088328,
        "fpr": 0.0016488046166529267,
    },
    "EXP-0011b": {
        "status": (
            "INVALIDATED — boundary-construction flaw, not constructionally "
            "TEST-blind, retained for audit trail only; the previously-reported "
            "26.9% / 91% frozen TEST result must NOT be cited, reused, or treated "
            "as final"
        ),
        "scope": "egress-only; historical TEST cohort 4,807 Normal / 193 DoS",
        "precision": 0.9122807017543859,
        "recall": 0.2694300518134715,
        "f1": 0.416,
        "fpr": 0.001040149781568546,
        "tn": 4802, "fp": 5, "fn": 141, "tp": 52,
    },
}


def _assert_frozen_configuration(configuration: Mapping) -> None:
    """Assert the exact EXP-0011b knobs. The semantic fingerprint is NOT gated here:
    EXP-0013 legitimately retrains a fresh forest under the corrected manifest and
    the rewritten cadence-feature pipeline, so its fingerprint differs from
    EXP-0011b's pre-correction value by design."""
    expected_sampler = {
        "sampling_strategy": "auto", "random_state": 0,
        "k_neighbors": 5, "m_neighbors": 10, "kind": "borderline-1",
    }
    actual_sampler = configuration["sampler_parameters"]
    if configuration["sampler"] != "BorderlineSMOTE" or any(
        actual_sampler.get(key) != value for key, value in expected_sampler.items()
    ):
        raise RuntimeError("EXP-0013 frozen Borderline-SMOTE configuration mismatch")
    expected_model = {
        "model": "RandomForestClassifier", "n_estimators": 300,
        "class_weight": None, "random_state": 0, "n_jobs": -1,
        "max_depth": None, "min_samples_leaf": 1,
    }
    if any(configuration.get(key) != value for key, value in expected_model.items()):
        raise RuntimeError("EXP-0013 frozen Random Forest configuration mismatch")


def _assert_corrected_manifest() -> None:
    """Fail closed unless the corrected, checksummed pre-TEST manifest is in force."""
    split = load_pretest_split()
    if (
        split.split_id != EXPECTED_SPLIT_ID
        or split.split_id != EXPECTED_PRETEST_SPLIT_ID
        or split.membership_sha256 != EXPECTED_MEMBERSHIP_SHA256
        or split.membership_sha256 != EXPECTED_PRETEST_MEMBERSHIP_SHA256
    ):
        raise RuntimeError(
            "EXP-0013 requires the corrected verified-egress-5s-exp0008-pretest-v1 "
            "manifest with its exact membership checksum"
        )


def score_frozen_test_once(
    confirmation: str, records: Iterable[FrameRecord] | None = None,
) -> dict:
    """Fit the frozen EXP-0011b recipe on corrected TRAIN, then score TEST once."""
    if confirmation != FROZEN_TEST_CONFIRMATION:
        raise PermissionError(
            "EXP-0013 frozen TEST scoring requires the exact explicit confirmation token"
        )
    _assert_corrected_manifest()
    materialized = None if records is None else tuple(records)

    artifacts = prepare_pretest_artifacts(materialized)
    if artifacts.inputs.split_id != EXPECTED_SPLIT_ID:
        raise RuntimeError("EXP-0013 pre-TEST artifacts are not on the corrected manifest")
    if artifacts.inputs.test_window_count is not None:
        raise RuntimeError("EXP-0013 pre-TEST construction must not enumerate TEST windows")

    data = prepare_matrices(artifacts)
    model, configuration, fingerprint = fit_final_0011b(data)
    _assert_frozen_configuration(configuration)

    test = _test_block(materialized)
    test_windows = build_scoring_windows(
        test, artifacts.type_map, artifacts.baselines, artifacts.thresholds,
    )
    cohort = _cohort(test_windows)
    labels = _labels(test_windows, cohort)
    matrix = _matrix(test_windows, artifacts.feature_names)[cohort]
    probabilities = model.predict_proba(matrix)[:, 1]
    predictions = (probabilities >= PROBABILITY_THRESHOLD).astype(int)
    metrics = binary_metrics(labels, predictions)

    return {
        "status": "VALIDATED — ONE TEST-BLIND FROZEN PASS; NO RERUN",
        "experiment": "EXP-0013",
        "purpose": (
            "First genuinely TEST-blind frozen evaluation for Type 1 DoS detection "
            "in this project, built on the corrected split manifest, following the "
            "invalidation of EXP-0008/0009/0011's TEST-adjacent results."
        ),
        "manifest": {
            "split_id": artifacts.inputs.split_id,
            "membership_sha256": artifacts.inputs.split_membership_sha256,
            "pretest_parsing": "stopped after final VALIDATION bucket; no TEST-tail read",
            "test_construction": (
                "egress windows after the frozen final VALIDATION bucket, first "
                "2 emitted windows discarded as guards, derived from the manifest "
                "boundary — not a full-capture recomputation"
            ),
        },
        "frozen_configuration": {
            "sampler": "BorderlineSMOTE",
            "sampling_strategy": "auto", "k_neighbors": 5,
            "m_neighbors": 10, "kind": "borderline-1", "sampler_random_state": 0,
            "model": "RandomForestClassifier", "n_estimators": 300,
            "class_weight": None, "random_state": 0, "n_jobs": -1,
            "max_depth": None, "min_samples_leaf": 1,
            "probability_threshold": PROBABILITY_THRESHOLD,
            "feature_count": len(artifacts.feature_names),
            "features": list(artifacts.feature_names),
            "payload_features": [],
            "lag_or_trend_features": [],
            "fit_details": configuration,
            "semantic_fingerprint_sha256": fingerprint,
            "exp0011b_precorrection_fingerprint_sha256": FINAL_FINGERPRINT,
            "fingerprint_matches_exp0011b": fingerprint == FINAL_FINGERPRINT,
            "fingerprint_note": (
                "A fresh forest is trained under the corrected manifest and the "
                "rewritten cadence-feature pipeline; the same knobs and identical "
                "TRAIN window counts (28,040 / 9,345) hold, but the semantic "
                "fingerprint differs from EXP-0011b's pre-correction value by design."
            ),
        },
        "scope": {
            "direction": "egress only", "destination": 1,
            "cohort": "DoS-containing versus pure-Normal five-second windows",
            "total_egress_frames_through_validation_end": artifacts.inputs.total_egress_frames,
            "pretest_emitted_windows": artifacts.inputs.total_emitted_windows,
            "split_window_counts": {
                "train": artifacts.inputs.train_window_count,
                "validation": artifacts.inputs.validation_window_count,
                "test": len(test_windows),
            },
        },
        "test_counts": {
            "windows": len(test_windows), "cohort": len(labels),
            "normal": int((labels == 0).sum()),
            "dos": int((labels == 1).sum()),
            "excluded_other_attack": len(test_windows) - len(labels),
        },
        "test_metrics": metrics,
        "comparison_context": COMPARISON_CONTEXT,
        "software": {
            "python": platform.python_version(),
            "numpy": version("numpy"),
            "scikit_learn": version("scikit-learn"),
            "imbalanced_learn": version("imbalanced-learn"),
        },
        "limitations": [
            "One labelled testbed cannot establish universal DoS detectability.",
            "The labelled attack is not established as a classic volumetric flood.",
            "Response type is an egress-visible proxy for an unseen query.",
            "The manifest freezes memberships EXP-0008 originally derived from "
            "full-capture eligibility; the prospective freeze removes future TEST-tail "
            "dependence but does not prove the historical source boundary was chosen "
            "independently of TEST.",
        ],
    }


def _json_ready(value):
    if isinstance(value, Mapping):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_ready(item) for item in value]
    if isinstance(value, np.generic):
        return _json_ready(value.item())
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def write_result_atomic(result: Mapping, path: Path = RESULT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(_json_ready(result), indent=2) + "\n", encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--score-frozen-test", action="store_true")
    parser.add_argument("--confirm", default="")
    args = parser.parse_args()
    if not args.score_frozen_test:
        if args.confirm:
            parser.error("--confirm is valid only with --score-frozen-test")
        parser.error(
            "EXP-0013 has one guarded action: "
            "--score-frozen-test --confirm SCORE-EXP-0013-FROZEN-TEST-ONCE"
        )
    result = score_frozen_test_once(args.confirm)
    write_result_atomic(result)
    print(json.dumps(_json_ready(result), indent=2))
    print(f"\n[result -> {RESULT_PATH}]")


if __name__ == "__main__":
    main()
