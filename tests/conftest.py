"""EXP-0017: saved-output regression; pytest never scores the real TEST capture."""
import copy
import hashlib
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HISTORICAL = {
    "exp0010_egress_flood": "run_flood_test",
    "exp0014_cmd_injection_diag": "run_diagnostic",
    "exp0015_response_injection_diag": "run_diagnostic",
    "exp0016_pressure_bounds_rule": "run_experiment",
}


@pytest.fixture(autouse=True)
def saved_history_only(monkeypatch, request):
    """Replay approved summaries, keeping original historical assertions intact.

    This verifies saved artifacts, NOT execution of the historical experiments.
    Missing artifacts fail closed. Only replay for the relevant integration test.
    """
    module_name = request.node.module.__name__.removeprefix("test_")
    if module_name in HISTORICAL and request.node.get_closest_marker("slow"):
        path = ROOT / "data" / "experiments" / (module_name + ".json")
        raw = path.read_bytes()
        result = json.loads(raw)
        request.node.user_properties.append(("historical_artifact_sha256", hashlib.sha256(raw).hexdigest()))
        module = importlib.import_module(module_name)
        monkeypatch.setattr(module, HISTORICAL[module_name], lambda: copy.deepcopy(result))

    # Fail closed if a newly added test accidentally opens a real capture.
    # Synthetic files under tmp_path and saved experiment outputs remain available.
    import builtins
    import io
    raw_dir = (ROOT / "data" / "raw").resolve()
    def guarded(original):
        def checked(file, *args, **kwargs):
            if isinstance(file, (str, bytes, Path)):
                path = Path(file).resolve()
                if path.is_relative_to(raw_dir):
                    raise PermissionError("pytest must not read real raw data; use saved EXP-0017 output")
            return original(file, *args, **kwargs)
        return checked
    monkeypatch.setattr(builtins, "open", guarded(builtins.open))
    monkeypatch.setattr(io, "open", guarded(io.open))


@pytest.fixture(scope="session")
def detector_result():
    """EXP-0025 operational result: protocol OR pressure OR rate OR IF. Derived
    analytically from the frozen EXP-0017 arrays (no second TEST-scoring event);
    numerically identical to EXP-0017 on every metric because the rate rule fires
    zero times on real captured TEST data (see docs/EXP0025_RESULTS.md)."""
    path = ROOT / "data" / "experiments" / "exp0025_detector.json"
    if not path.exists():
        pytest.skip("No saved detector arrays: TEST scoring forbidden in pytest")
    from exp0025_dos_rate_rule import load_detector_result
    return load_detector_result(path)
