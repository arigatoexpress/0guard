from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "osint_steward_checklist.py"
_SPEC = spec_from_file_location("osint_steward_checklist", _SCRIPT_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
_MODULE = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)

ProbeResult = _MODULE.ProbeResult
_overall_ok = _MODULE._overall_ok


def _probe(path: str = "/api/readyz", status_code: int | None = 200) -> ProbeResult:
    return ProbeResult(
        path=path,
        status_code=status_code,
        elapsed_ms=10,
        content_type="application/json",
        snippet="{}",
    )


def test_overall_ok_includes_public_sapphire_and_silo_readbacks() -> None:
    assert _overall_ok(
        [_probe()],
        sapphire={
            "health": {"statusCode": 200},
            "progress": [{"statusCode": 200}, {"statusCode": 204}],
        },
        public={"urls": [{"statusCode": 200}, {"statusCode": 204}]},
        silo={"tho_healthz": {"statusCode": 200}},
    )


def test_overall_ok_rejects_failed_public_readback() -> None:
    assert not _overall_ok(
        [_probe()],
        sapphire={"health": {"statusCode": 200}, "progress": [{"statusCode": 200}]},
        public={"urls": [{"statusCode": 404}]},
        silo={"tho_healthz": {"statusCode": 200}},
    )


def test_overall_ok_allows_405_only_for_route_probes() -> None:
    assert _overall_ok([_probe("/api/native-preflight", 405)])
    assert not _overall_ok(
        [_probe()],
        sapphire={"health": {"statusCode": 405}, "progress": []},
    )
