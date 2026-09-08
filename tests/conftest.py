"""Shared fixtures.

`detector_result` runs the real EXP-0004 detector once per test session over the
verified TXT egress stream (274,628 frames -> 46,736 windows -> IF fit/score). Every
integration test reads from that one result rather than re-running the pipeline.
"""
import pytest


@pytest.fixture(scope="session")
def detector_result():
    from iforest_detector import run_detector
    return run_detector()
