"""T-02 (mechanism) — deterministic rule layer, unit level.

Fast synthetic-window tests of ml/rules.DeterministicRuleLayer: it must learn the
valid function-code / address sets from train-normal only, fire on any window
carrying an out-of-profile function code or a novel address, and stay silent on
in-profile traffic. The full-pipeline version of T-02 (rule fires on 100% of real
MFCI/Recon TEST windows, 0% of Normal) is in test_detector.py.
"""
from types import SimpleNamespace

import pytest

from rules import DeterministicRuleLayer


def win(w_index, func_codes, addresses=(4,)):
    return SimpleNamespace(
        w_index=w_index,
        func_codes=frozenset(func_codes),
        addresses=frozenset(addresses),
    )


# gas-pipeline normal profile: Modbus read (0x03) + write-multiple (0x10), one slave (addr 4)
NORMAL = [win(i, {0x03, 0x10}, {4}) for i in range(20)]


@pytest.fixture
def rule():
    return DeterministicRuleLayer().fit(NORMAL)


def test_profile_frozen_from_train_normal(rule):
    assert rule.valid_func_codes == frozenset({0x03, 0x10})
    assert rule.valid_addresses == frozenset({4})


def test_silent_on_in_profile_window(rule):
    hit = rule.evaluate(win(100, {0x03, 0x10}, {4}))
    assert hit.fired is False
    assert hit.reasons == []


def test_fires_on_invalid_function_code(rule):
    hit = rule.evaluate(win(101, {0x03, 0x88}, {4}))
    assert hit.fired is True
    assert any(r.startswith("invalid_function_code=") for r in hit.reasons)
    assert "0x88" in hit.reasons[0]


def test_fires_on_novel_address(rule):
    hit = rule.evaluate(win(102, {0x03}, {4, 7}))
    assert hit.fired is True
    assert any(r.startswith("novel_address=") for r in hit.reasons)
    assert "7" in "".join(hit.reasons)


def test_both_reasons_when_both_anomalous(rule):
    hit = rule.evaluate(win(103, {0x2B}, {9}))
    assert hit.fired is True
    kinds = {r.split("=")[0] for r in hit.reasons}
    assert kinds == {"invalid_function_code", "novel_address"}


def test_predict_is_vectorised_and_matches_evaluate(rule):
    windows = [
        win(200, {0x03, 0x10}, {4}),      # clean
        win(201, {0x10, 0x06}, {4}),      # bad func
        win(202, {0x03}, {4, 5}),         # novel addr
    ]
    assert rule.predict(windows) == [0, 1, 1]
    assert [int(rule.evaluate(w).fired) for w in windows] == [0, 1, 1]


def test_evaluate_before_fit_raises():
    with pytest.raises(RuntimeError):
        DeterministicRuleLayer().evaluate(win(0, {0x03}))


def test_multiple_bad_codes_are_all_reported(rule):
    hit = rule.evaluate(win(300, {0x03, 0x88, 0x2B}, {4}))
    reason = next(r for r in hit.reasons if r.startswith("invalid_function_code="))
    assert "0x2b" in reason and "0x88" in reason
