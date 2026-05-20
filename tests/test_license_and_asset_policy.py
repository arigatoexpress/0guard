"""Repository licensing, source-rights, and media-policy regressions."""

import json
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_project_license_metadata_is_apache_2():
    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    public_page = (REPO_ROOT / "docs" / "index.html").read_text(encoding="utf-8")

    assert "Apache License" in license_text
    assert "Version 2.0" in license_text
    assert 'license = {text = "Apache-2.0"}' in pyproject
    assert "License :: OSI Approved :: Apache Software License" in pyproject
    assert "Apache-2.0" in readme
    assert "Apache-2.0 License" in public_page
    assert "MIT License" not in public_page


def test_solidity_sources_use_project_spdx_license():
    solidity_sources = [
        REPO_ROOT / "contracts" / "PolicyReceiptAnchor.sol",
        REPO_ROOT / "contracts" / "PolicyReceiptAnchorV2.sol",
        REPO_ROOT / "foundry" / "src" / "PolicyReceiptAnchor.sol",
    ]

    for source_path in solidity_sources:
        source = source_path.read_text(encoding="utf-8")
        assert source.startswith("// SPDX-License-Identifier: Apache-2.0")

    artifact = json.loads(
        (REPO_ROOT / "contracts" / "PolicyReceiptAnchor.json").read_text(
            encoding="utf-8"
        )
    )
    assert (
        artifact["metadata"]["sources"]["contracts/PolicyReceiptAnchor.sol"]["license"]
        == "Apache-2.0"
    )


def test_notice_and_policy_keep_source_rights_clear():
    notice = (REPO_ROOT / "NOTICE").read_text(encoding="utf-8")
    policy = (REPO_ROOT / "docs" / "LEGAL_AND_ASSET_POLICY.md").read_text(
        encoding="utf-8"
    )

    assert "raw upstream payload resale" in notice
    assert "Generated media" in notice
    assert "derived-analysis-first" in policy
    assert "do not resell, mirror, or expose raw upstream payloads" in policy
    assert "live_read_only" in policy
    assert "preview_only" in policy
    assert "operator_controlled" in policy


def test_docker_image_includes_repo_professionalization_artifacts():
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY NOTICE ./" in dockerfile
    assert "COPY foundry/src/" in dockerfile
    assert "COPY docs/LEGAL_AND_ASSET_POLICY.md" in dockerfile
    assert "COPY docs/hackathon-0g/README.md" in dockerfile
    assert "COPY docs/hackathon-0g/assets/README.md" in dockerfile
    assert "COPY docs/hackathon-0g/hackquest-submission-proof.json" in dockerfile
    assert "COPY docs/hackathon-0g/veo3-flow-production-prompt.md" in dockerfile
    assert "RUN mkdir -p ./content" in dockerfile
    assert "COPY content/" not in dockerfile


def test_public_asset_registry_covers_tracked_media():
    registry = (
        REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "README.md"
    ).read_text(encoding="utf-8")

    tracked_media = {
        "docs/hackathon-0g/assets/0guard-hackquest-demo-final.mp4",
        "docs/hackathon-0g/assets/0guard-logo.png",
        "docs/hackathon-0g/assets/0guard-workbench-provenance.png",
        "docs/hackathon-0g/assets/0guard-x-banner.png",
        "src/guard0/static/0guard-logo.png",
    }

    for media_path in tracked_media:
        assert (REPO_ROOT / media_path).exists()
        assert Path(media_path).name in registry

    assert "private keys" in registry
    assert "unreviewed generation outputs" in registry


def test_archived_generated_media_packet_is_grounded_in_real_product_behavior():
    packet = (
        REPO_ROOT / "docs" / "hackathon-0g" / "veo3-flow-production-prompt.md"
    ).read_text(encoding="utf-8")
    registry = (
        REPO_ROOT / "docs" / "hackathon-0g" / "assets" / "README.md"
    ).read_text(encoding="utf-8")

    assert "Veo 3.1 Quality" in packet
    assert "16:9 landscape" in packet
    assert "8-second clip" in packet
    assert "real screen capture" in packet
    assert "/api/reputation/shadow-cache" in packet
    assert "/api/readyz" in packet
    assert "telegram_send=false" in packet
    assert "rawPayloadsReturned=false" in packet
    assert "fake wallet approvals" in packet
    assert "0G mainnet PolicyReceiptAnchor" in packet
    assert "submitted-archive" in registry
    assert "Mainnet proof links and API readbacks are canonical" in registry
