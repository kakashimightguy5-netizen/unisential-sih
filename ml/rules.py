#!/usr/bin/env python3
"""
Deterministic rule layer — runs ALONGSIDE the Isolation Forest, not as one of its inputs.

Rationale (EXP-0001 audit / DECISION_LOG 2026-09-04): `function_code_valid` and slave
`address` are *exactly constant* on normal traffic, so an Isolation Forest never draws
a split on them and cannot use them — yet an out-of-profile Modbus function code or a
never-before-seen slave address on the wire is an unambiguous protocol violation. That
is a membership test, not a statistical anomaly: handle it with a hard rule.

Profile (the "valid" sets) is frozen from the TRAIN-normal block only, same discipline
as the IF standardiser. The rule's verdict is OR-ed with the IF's.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RuleHit:
    fired: bool
    reasons: list[str]


class DeterministicRuleLayer:
    def __init__(self) -> None:
        self.valid_func_codes: frozenset[int] = frozenset()
        self.valid_addresses: frozenset[int] = frozenset()
        self._fitted = False

    def fit(self, train_normal_windows) -> "DeterministicRuleLayer":
        fcs: set[int] = set()
        addrs: set[int] = set()
        for w in train_normal_windows:
            fcs |= set(w.func_codes)
            addrs |= set(w.addresses)
        self.valid_func_codes = frozenset(fcs)
        self.valid_addresses = frozenset(addrs)
        self._fitted = True
        return self

    def evaluate(self, window) -> RuleHit:
        if not self._fitted:
            raise RuntimeError("fit() the rule layer on train-normal windows first")
        reasons: list[str] = []
        bad_fc = sorted(set(window.func_codes) - self.valid_func_codes)
        bad_ad = sorted(set(window.addresses) - self.valid_addresses)
        if bad_fc:
            reasons.append("invalid_function_code=" + ",".join(f"0x{c:02x}" for c in bad_fc))
        if bad_ad:
            reasons.append("novel_address=" + ",".join(str(a) for a in bad_ad))
        return RuleHit(fired=bool(reasons), reasons=reasons)

    def predict(self, windows) -> list[int]:
        return [int(self.evaluate(w).fired) for w in windows]
