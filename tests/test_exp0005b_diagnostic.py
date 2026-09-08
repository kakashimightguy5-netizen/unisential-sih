"""Regression test for the separately logged EXP-0005b diagnostic."""

import pytest

from exp0005b_diagnostic import run_diagnostic


@pytest.fixture(scope="module")
def diagnostic_result():
    return run_diagnostic()


def test_exp0005b_uses_fixed_supervised_configuration(diagnostic_result):
    assert diagnostic_result["model"] == {
        "type": "RandomForestClassifier",
        "n_estimators": 300,
        "class_weight": "balanced",
        "random_state": 0,
        "probability_threshold": 0.5,
    }
    assert diagnostic_result["label_rule"] == (
        "positive if any categorized_attack == 6 frame is present"
    )


def test_exp0005b_reproduces_validated_test_result(diagnostic_result):
    assert diagnostic_result["counts"]["test_normal"] == 4931
    assert diagnostic_result["counts"]["test_dos"] == 193
    assert diagnostic_result["metrics"] == {
        "precision": pytest.approx(0.6302521008403361),
        "recall": pytest.approx(0.38860103626943004),
        "f1": pytest.approx(0.4807692307692308),
        "fpr": pytest.approx(0.008923139322652606),
        "tn": 4887,
        "fp": 44,
        "fn": 118,
        "tp": 75,
    }


def test_exp0005b_summarizes_every_feature_for_equal_groups(diagnostic_result):
    counts = diagnostic_result["counts"]
    assert counts["normal_summary_sample"] == counts["test_dos"] == 193
    assert len(diagnostic_result["feature_summaries"]) == 15
    for summary in diagnostic_result["feature_summaries"].values():
        assert set(summary) == {
            "dos_mean", "dos_std", "normal_sample_mean",
            "normal_sample_std",
        }
