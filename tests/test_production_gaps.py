"""Tests for the production gap matrix and model-training roadmap."""

from guard0.production_gaps import (
    build_model_training_roadmap,
    build_production_gap_matrix,
)


def test_production_gap_matrix_classifies_real_local_pending_and_mock_lanes():
    matrix = build_production_gap_matrix()

    assert matrix["schema"] == "0guard.production_gap_matrix.v1"
    assert matrix["productionReady"] is False
    assert matrix["mode"] == "local_snapshot_and_manifest_no_side_effects"
    assert matrix["safety"]["transactionSigningEnabled"] is False
    assert matrix["safety"]["telegramSendsEnabled"] is False
    assert matrix["safety"]["moneyMovementEnabled"] is False

    counts = matrix["classificationSummary"]["counts"]
    assert counts["live_real_data"] >= 3
    assert counts["local_only"] >= 2
    assert counts["source_ready_live_pending"] >= 6
    assert counts["mock_fixture_only"] >= 1

    by_id = {gap["id"]: gap for gap in matrix["gaps"]}
    assert by_id["data.incident_corpus"]["currentStatus"] == "live_real_data"
    assert by_id["data.historical_feature_store"]["currentEvidence"]["featureCount"] >= 29
    assert by_id["data.historical_feature_store"]["currentEvidence"]["featureStoreReceiptHash"]
    assert "scheduled_backfill_runner" in by_id["data.historical_feature_store"]["blockedBy"]
    assert "/api/data/historical-feature-store" in by_id["data.historical_feature_store"]["routes"]
    assert "firstOpenFeedLatestRunExists" in by_id["data.live_reputation_feeds"]["currentEvidence"]
    assert "/api/reputation/backfill/status" in by_id["data.live_reputation_feeds"]["routes"]
    assert by_id["onchain.0g_storage_upload_readback"]["currentStatus"] == (
        "source_ready_live_pending"
    )
    assert by_id["onchain.0g_storage_upload_readback"]["currentEvidence"]["bundleFileCount"] >= 1
    assert "/api/0g/storage-upload/manifest" in by_id["onchain.0g_storage_upload_readback"]["routes"]
    assert by_id["onchain.x402_settlement"]["currentEvidence"]["dryRunHttpStatus"] == 402
    assert "/api/x402/dry-run/wallet-preflight" in by_id["onchain.x402_settlement"]["routes"]
    assert by_id["wallet.provider_guard"]["currentStatus"] == "source_ready_live_pending"
    assert by_id["wallet.provider_guard"]["currentEvidence"]["demoDecision"] == "deny"
    assert by_id["wallet.provider_guard"]["currentEvidence"]["providerCallAllowed"] is False
    assert by_id["wallet.provider_guard"]["currentEvidence"]["rawParamsReturned"] is False
    assert "/api/wallet/provider-guard" in by_id["wallet.provider_guard"]["routes"]
    assert by_id["node.0g_storage_soak"]["unsafeToDoNow"].startswith(
        "Do not send the large 0G transfer"
    )
    assert "connectedPeers" in by_id["node.0g_storage_soak"]["currentEvidence"]
    assert by_id["model.0g_private_computer"]["currentEvidence"]["paidInferenceEnabled"] is False
    assert by_id["model.0g_private_computer"]["currentEvidence"]["smokeInferenceExecuted"] is False
    assert "/api/0g/private-computer/smoke-preview" in by_id["model.0g_private_computer"]["routes"]
    assert by_id["mock.demo_fixtures"]["currentStatus"] == "mock_fixture_only"


def test_model_training_roadmap_preserves_authority_and_source_rights():
    roadmap = build_model_training_roadmap()

    assert roadmap["schema"] == "0guard.model_training_roadmap.v1"
    assert roadmap["mode"] == "rights_aware_eval_plan_no_training_run"
    assert "may not approve transactions" in roadmap["authorityBoundary"]
    assert roadmap["safety"]["paidInferenceEnabled"] is False
    assert roadmap["safety"]["trainingRunStarted"] is False

    by_id = {dataset["id"]: dataset for dataset in roadmap["datasets"]}
    assert by_id["incident_detector_eval_set"]["status"] == "live_real_data"
    assert by_id["incident_detector_eval_set"]["currentScale"]["incidents"] == 28
    assert by_id["reputation_shadow_features"]["rights"].startswith("derived labels")
    assert by_id["node_soak_telemetry"]["status"] == "local_only"
    assert by_id["peer_outreach_draft_eval"]["status"] == "mock_fixture_only"
    assert "raw paid feeds" in by_id["x402_receipt_and_usage_metadata"]["doNotTrainOn"]
