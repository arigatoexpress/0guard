"""Regression checks for the public GitHub Pages surface."""

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_public_pages_demo_examples_match_real_routes_and_assets():
    html = (REPO_ROOT / "docs" / "index.html").read_text(encoding="utf-8")

    assert "https://0guard.example" not in html
    assert "docs/og-image.png" not in html
    assert "0guard-x-banner.png" in html
    assert "/api/hackathon/threat-passport" in html
    assert "/api/threat-case-file" in html
    assert "/api/experiments/frontier" in html
    assert "/api/readyz" in html
    assert "/api/reputation/shadow-cache" in html
    assert "/api/integrations/cross-chain" in html
    assert "/api/integrations/virtuals-facilitator" in html
    assert (
        REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "0guard-workbench-provenance.png"
    ).exists()
    assert (REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "0guard-x-banner.png").exists()
    assert "http://127.0.0.1:8109/api/evaluate" in html
    assert "http://127.0.0.1:8109/api/hack-check" in html
    assert "0guard</span> evaluate --intent-json" in html
    assert '"decision"</span>: <span class="string">"deny"' in html
    assert "matched_signatures" not in html
    assert "risk_score" not in html
    assert "Detector-Matched Incidents of 28" in html
    assert "Open Detector Gaps" in html
    assert "Research-Only Detector Gap" not in html
    assert "27/28" not in html


def test_hackquest_proof_page_exposes_current_evidence_baseline():
    html = (REPO_ROOT / "docs" / "hackathon-0g" / "index.html").read_text(encoding="utf-8")

    assert "assets/0guard-hackquest-demo-final.mp4" in html
    assert "28/28" in html
    assert "signature and detection coverage ratio" in html
    assert "1.0" in html
    assert "EIP-7702" in html
    assert "/api/readyz" in html
    assert "/api/reputation/shadow-cache" in html
    assert "reports hard gates" in html
    assert "storage-node peer depth" in html
    assert "Professional repo posture" in html
    assert "Media archive" in html
    assert "assets/README.md" in html
    assert "0xBaC59b1571b7c7195915c5B36D8A719Ed7182abc" in html
    assert "No signing. No broadcasts." in html
    assert ("Latest media refresh:" in html) or ("Last video/proof-page baseline:" in html)
    assert (
        REPO_ROOT / "docs" / "hackathon-0g" / "veo3-flow-production-prompt.md"
    ).exists()
    assert (REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "README.md").exists()
