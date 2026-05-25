from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "telegram_production_smoke.py"
_SPEC = spec_from_file_location("telegram_production_smoke", _SCRIPT_PATH)
assert _SPEC is not None
assert _SPEC.loader is not None
_MODULE = module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)


def test_base_url_candidates_include_live_sapphire_urls() -> None:
    candidates = _MODULE._base_url_candidates(
        "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
        sapphire_discovered_base_urls=[
            "https://candidate-live.example",
            "https://candidate-preview.example",
            "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
        ],
    )

    assert candidates == [
        "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
        "https://candidate-live.example",
        "https://candidate-preview.example",
    ]


def test_select_base_url_uses_live_candidate_when_requested_surface_fails(monkeypatch) -> None:
    monkeypatch.setattr(
        _MODULE,
        "_base_url_candidates",
        lambda requested, **_: [requested, "https://candidate-live.example"],
    )

    def fake_load_health(url: str, **_: object) -> tuple[str, dict[str, object]]:
        if "candidate-live" in url:
            return "/api/healthz", {"ok": True}
        raise _MODULE.requests.RequestException("stale host")

    monkeypatch.setattr(_MODULE, "_load_health", fake_load_health)

    selected = _MODULE._select_base_url(
        "https://guard0-miniapp-s77j6bxyra-uc.a.run.app",
        sapphire_discovered_base_urls=["https://candidate-live.example"],
        timeout=1.0,
        deadline=None,
    )

    assert selected == "https://candidate-live.example"
