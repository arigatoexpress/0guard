"""Browser smoke for the 0guard workbench.

The smoke starts the local Flask app, clicks the safe browser controls, and
readbacks the external-action contract. It never signs transactions, broadcasts
raw calls, posts to X, sends Telegram messages, deploys contracts, or exposes
secrets.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

PORT = int(os.environ.get("ZEROGUARD_BROWSER_SMOKE_PORT", "8139"))
BASE_URL = f"http://127.0.0.1:{PORT}"
EXTERNAL_DAPP_PORT = int(os.environ.get("ZEROGUARD_EXTERNAL_DAPP_PORT", "8142"))
EXTERNAL_DAPP_URL = f"http://127.0.0.1:{EXTERNAL_DAPP_PORT}"
REPO_ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    env = {**os.environ, "PORT": str(PORT)}
    with run_server(env):
        run_browser_smoke()
    return 0


@contextmanager
def run_server(env: dict[str, str]) -> Iterator[None]:
    process = subprocess.Popen(
        [sys.executable, "-m", "guard0.app"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_health(process)
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_for_health(process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    last_error = "server did not start"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"server exited early with {process.returncode}: {output}")
        try:
            with urllib.request.urlopen(f"{BASE_URL}/api/health", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for {BASE_URL}/api/health: {last_error}")


@contextmanager
def run_external_dapp_server() -> Iterator[None]:
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "http.server",
            str(EXTERNAL_DAPP_PORT),
            "--bind",
            "127.0.0.1",
            "--directory",
            str(REPO_ROOT / "examples" / "wallet_provider_guard" / "external_dapp"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        wait_for_external_dapp(process)
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def wait_for_external_dapp(process: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 20
    last_error = "server did not start"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(f"external dapp server exited early: {output}")
        try:
            with urllib.request.urlopen(f"{EXTERNAL_DAPP_URL}/", timeout=1) as response:
                if response.status == 200:
                    return
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = str(exc)
        time.sleep(0.2)
    raise TimeoutError(f"Timed out waiting for {EXTERNAL_DAPP_URL}: {last_error}")


def run_browser_smoke() -> None:
    console_errors: list[str] = []

    def record_console_error(message) -> None:
        if message.type == "error":
            console_errors.append(message.text)

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.on("console", record_console_error)
        page.on("pageerror", lambda exc: console_errors.append(str(exc)))
        try:
            exercise_workbench(page)
            exercise_wallet_provider_demo(page)
            with run_external_dapp_server():
                exercise_external_wallet_provider_dapp(page)
            mobile_page = browser.new_page(
                viewport={"width": 390, "height": 844},
                is_mobile=True,
            )
            mobile_page.on("console", record_console_error)
            mobile_page.on("pageerror", lambda exc: console_errors.append(str(exc)))
            exercise_workbench_mobile(mobile_page)
            mobile_page.close()
            exercise_telegram_miniapp(page)
        finally:
            browser.close()
    if console_errors:
        raise AssertionError(f"browser console/page errors: {console_errors}")


def exercise_workbench(page: Page) -> None:
    page.goto(BASE_URL)

    expect(page).to_have_title("0guard Workbench")
    expect(page.locator("body")).to_contain_text("0G Hack Guard")
    expect(page.locator("body")).to_contain_text(
        "What happens before an AI agent touches a wallet?"
    )
    expect(page.locator("#plain-explanation")).to_contain_text("Safe simulations pass")
    expect(page.locator("#flow-canvas")).to_have_attribute("data-state", "idle")
    assert_flow_packet_clear_of_node_labels(page)
    expect(page.locator("body")).to_contain_text("Intent Firewall")
    expect(page.locator("body")).to_contain_text("Hack Signature Check")
    expect(page.locator("body")).to_contain_text("Domain Guard")
    expect(page.locator("#mode-pill")).to_contain_text("no signing")
    expect(page.locator("#send-pill")).to_contain_text("external sends blocked")
    expect(page.locator("#contract-output")).to_contain_text("workbenchCanTriggerLiveActions")
    expect(page.locator("#contract-output")).to_contain_text('"livePostingEnabled": false')
    expect(page.locator("#contract-output")).to_contain_text('"telegramSendsEnabled": false')
    expect(page.locator("#zg-status-output")).to_contain_text(
        "0guard.0g_status.v1", timeout=15000
    )
    expect(page.locator("#zg-status-output")).to_contain_text('"privateKeyRequired": false')
    expect(page.locator("#zg-status-output")).to_contain_text('"signingEnabled": false')
    page.locator("#verify-receipt").click()
    expect(page.locator("#zg-status-output")).to_contain_text("0guard.0g_receipt_verifier.v1")
    expect(page.locator("#zg-status-output")).to_contain_text('"verified": false')
    expect(page.locator("#zg-status-output")).to_contain_text('"readOnly": true')
    expect(page.locator("#zg-status-output")).to_contain_text('"signingEnabled": false')
    expect(page.locator("#data-flow-output")).to_contain_text("0guard.incident_summary.v1")
    expect(page.locator("#data-flow-output")).to_contain_text('"incidentCount": 28')
    expect(page.locator("#osint-output")).to_contain_text("0guard.osint_source_registry.v1")
    expect(page.locator("#osint-output")).to_contain_text('"rawPayloadResaleAllowed": false')
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard.crosschain_catalog.v1")
    expect(page.locator("#cross-chain-output")).to_contain_text('"moneyMovementEnabled": false')
    expect(page.locator("#telegram-register-output")).to_contain_text(
        "0guard.telegram_mira_status.v1"
    )
    expect(page.locator("#telegram-register-output")).to_contain_text(
        '"telegramSendsEnabled": false'
    )
    expect(page.locator("body")).to_contain_text("Wallet Alert Preview")
    expect(page.locator("body")).to_contain_text("Wallet Provider Guard")
    expect(page.locator("body")).to_contain_text("Local Inference")
    expect(page.locator("body")).to_contain_text("Backfill plan")
    expect(page.locator("body")).to_contain_text("x402 products")

    page.locator("#load-deny-sample").click()
    page.locator("#run-evaluate").click()
    expect(page.locator("#decision-pill")).to_contain_text("deny")
    expect(page.locator("#flow-canvas")).to_have_attribute("data-state", "deny")
    expect(page.locator("#wallet-state")).to_contain_text("not asked to sign")
    expect(page.locator("#risk-list")).to_contain_text("wallet signature")
    expect(page.locator("#result-output")).to_contain_text('"decision": "deny"')
    expect(page.locator("#result-output")).to_contain_text("Intent requires a wallet signature")

    page.locator("#run-bridge-scenario").click()
    expect(page.locator("#plain-explanation")).to_contain_text("bridge funds")
    expect(page.locator("#technical-output")).to_contain_text("Decision: deny")
    expect(page.locator("#risk-list")).to_contain_text("bridge")
    assert_flow_packet_clear_of_node_labels(page)

    page.locator("#load-allow-sample").click()
    page.locator("#run-evaluate").click()
    expect(page.locator("#decision-pill")).to_contain_text("allow")
    expect(page.locator("#flow-canvas")).to_have_attribute("data-state", "allow")
    expect(page.locator("#wallet-state")).to_contain_text("simulation only")
    expect(page.locator("#result-output")).to_contain_text('"decision": "allow"')
    expect(page.locator("#result-output")).to_contain_text('"mode": "simulation"')

    page.locator("#load-deny-sample").click()
    page.locator("#run-threat-case-file").click()
    expect(page.locator("#case-file-output")).to_contain_text("0guard.threat_case_file.v1")
    expect(page.locator("#case-file-output")).to_contain_text("policy_engine")
    expect(page.locator("#case-file-output")).to_contain_text('"rawPayloadsReturned": false')

    page.locator("#run-hack-check").click()
    expect(page.locator("#result-output")).to_contain_text("Unlimited ERC-20 approval")

    page.locator("#domain-input").fill("https://untrusted.example/phish")
    page.locator("#run-domain-check").click()
    expect(page.locator("#result-output")).to_contain_text('"decision": "review"')
    expect(page.locator("#result-output")).to_contain_text("Domain not in curated allowlist")

    page.locator("#load-detection-coverage").click()
    expect(page.locator("#data-flow-output")).to_contain_text("0guard.detection_coverage.v1")
    expect(page.locator("#data-flow-output")).to_contain_text('"coverageRatio"')
    page.locator("#load-provenance-matrix").click()
    expect(page.locator("#data-flow-output")).to_contain_text(
        "0guard.incident_provenance_matrix.v1"
    )
    expect(page.locator("#provenance-summary")).to_contain_text("28/28")
    expect(page.locator("#provenance-summary")).to_contain_text("cached")
    page.locator("#load-signature-map").click()
    expect(page.locator("#data-flow-output")).to_contain_text("0guard.signature_map.v1")
    expect(page.locator("#data-flow-output")).to_contain_text('"gapCount"')
    page.locator("#load-historical-backfill-plan").click()
    expect(page.locator("#data-flow-output")).to_contain_text(
        "0guard.historical_backfill_plan.v1"
    )
    expect(page.locator("#data-flow-output")).to_contain_text('"rawPayloadsReturned": false')

    page.locator("#load-osint-readiness").click()
    expect(page.locator("#osint-output")).to_contain_text("0guard.osint_readiness.v1")
    expect(page.locator("#osint-output")).to_contain_text('"rawPayloadsReturned": false')
    page.locator("#load-evolving-intel").click()
    expect(page.locator("#osint-output")).to_contain_text(
        "0guard.evolving_threat_intelligence.v1"
    )
    expect(page.locator("#osint-output")).to_contain_text("preview_no_send_read_only")
    page.locator("#load-x402-data-products").click()
    expect(page.locator("#osint-output")).to_contain_text("0guard.x402_data_products.v1")
    expect(page.locator("#osint-output")).to_contain_text('"x402SettlementEnabled": false')
    page.locator("#load-product-brief").click()
    expect(page.locator("#osint-output")).to_contain_text("0guard.product_brief.v1")
    page.locator("#load-production-readiness").click()
    expect(page.locator("#osint-output")).to_contain_text("0guard.readyz.v1")
    expect(page.locator("#osint-output")).to_contain_text('"transactionSigningEnabled": false')
    page.locator("#load-frontier-experiments").click()
    expect(page.locator("#osint-output")).to_contain_text("0guard.frontier_experiments.v1")
    expect(page.locator("#osint-output")).to_contain_text("zero_g_storage_receipt_readback")
    page.locator("#load-submission-brief").click()
    expect(page.locator("#osint-output")).to_contain_text(
        "0guard.hackathon_submission_brief.v1"
    )
    expect(page.locator("#osint-output")).to_contain_text("2026-05-16T23:59:00+08:00")
    page.locator("#load-submission-packet").click()
    expect(page.locator("#osint-output")).to_contain_text(
        "0guard.hackquest_submission_packet.v1"
    )
    expect(page.locator("#osint-output")).to_contain_text("0guard-hackquest-demo-final.mp4")
    page.locator("#load-submission-readiness").click()
    expect(page.locator("#osint-output")).to_contain_text(
        "0guard.hackquest_readiness_audit.v1"
    )
    expect(page.locator("#osint-output")).to_contain_text('"submittableNow": true')
    page.locator("#load-cross-chain-readiness").click()
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard.crosschain_catalog.v1")
    expect(page.locator("#cross-chain-output")).to_contain_text('"readOnly": true')
    page.locator("#load-virtuals-facilitator").click()
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "0guard.virtuals_facilitator_manifest.v1"
    )
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard Facilitator")
    page.locator("#load-ika-integration").click()
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "0guard.ika_integration_manifest.v1"
    )
    expect(page.locator("#cross-chain-output")).to_contain_text("Ikavery")
    expect(page.locator("#cross-chain-output")).to_contain_text('"transactionSigningEnabled": false')
    page.locator("#run-reputation-probe").click()
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard.reputation_probe.v1")
    expect(page.locator("#cross-chain-output")).to_contain_text('"decision": "deny"')
    expect(page.locator("#cross-chain-output")).to_contain_text('"rawPayloadsReturned": false')
    page.locator("#load-reputation-adapters").click()
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "0guard.reputation_adapter_catalog.v1"
    )
    expect(page.locator("#cross-chain-output")).to_contain_text('"networkCalls": false')
    page.locator("#load-reputation-shadow-cache").click()
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "0guard.reputation_shadow_cache.v1"
    )
    expect(page.locator("#cross-chain-output")).to_contain_text('"rawPayloadsReturned": false')
    page.locator("#run-native-preflight").click()
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard.native_preflight.v1")
    expect(page.locator("#cross-chain-output")).to_contain_text('"decision": "deny"')
    page.locator("#load-hackathon-strategy").click()
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard.hackathon_strategy.v1")
    expect(page.locator("#cross-chain-output")).to_contain_text("0g_apac_final_review")
    page.locator("#load-developer-kit").click()
    expect(page.locator("#cross-chain-output")).to_contain_text("0guard.developer_kit.v1")
    expect(page.locator("#cross-chain-output")).to_contain_text("agentkit_turnkey_safe_evm")
    expect(page.locator("#cross-chain-output")).to_contain_text('"transactionSigningEnabled": false')
    page.locator("#load-external-guardrails").click()
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "0guard.external_guardrail_catalog.v1"
    )
    page.locator("#run-external-guardrail-check").click()
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "0guard.external_guardrail_evaluation.v1"
    )
    expect(page.locator("#cross-chain-output")).to_contain_text(
        "layerzero_single_dvn_denied"
    )

    page.locator("#telegram-user-label").fill("browser-smoke")
    page.locator("#create-telegram-registration").click()
    expect(page.locator("#telegram-register-output")).to_contain_text(
        "0guard.telegram_registration_challenge.v1"
    )
    expect(page.locator("#telegram-register-output")).to_contain_text('"telegram_send": false')
    page.locator("#complete-telegram-opt-in").click()
    expect(page.locator("#telegram-register-output")).to_contain_text(
        "0guard.telegram_opt_in_response.v1"
    )
    expect(page.locator("#telegram-register-output")).to_contain_text('"status": "opted_in"')

    page.locator("#run-mira-preview").click()
    expect(page.locator("#mira-output")).to_contain_text("0guard.mira_preview.v1")
    expect(page.locator("#mira-output")).to_contain_text("preview_no_send")
    expect(page.locator("#mira-output")).to_contain_text('"telegram_send": false')

    page.locator("#run-wallet-alert-preview").click()
    expect(page.locator("#wallet-alert-output")).to_contain_text(
        "0guard.wallet_alert_preview.v1"
    )
    expect(page.locator("#wallet-alert-output")).to_contain_text("preview_no_send")
    expect(page.locator("#wallet-alert-output")).to_contain_text('"telegramSendEnabled": false')
    page.locator("#run-telegram-wallet-alert-preview").click()
    expect(page.locator("#wallet-alert-output")).to_contain_text(
        "0guard.telegram_wallet_alert_preview.v1"
    )
    expect(page.locator("#wallet-alert-output")).to_contain_text('"telegram_send": false')
    page.locator("#run-wallet-provider-guard").click()
    expect(page.locator("#wallet-alert-output")).to_contain_text(
        "0guard.wallet_provider_guard.v1"
    )
    expect(page.locator("#wallet-alert-output")).to_contain_text("block_before_wallet_prompt")
    expect(page.locator("#wallet-alert-output")).to_contain_text(
        '"providerCallAllowed": false'
    )

    health = page.request.get(f"{BASE_URL}/api/health")
    assert health.ok
    health_body = health.json()
    assert health_body["safety_flags"]["wallet_signatures_blocked"] is True
    assert health_body["safety_flags"]["external_sends_blocked_from_workbench"] is True
    assert health_body["safety_flags"]["live_posting_enabled"] is False
    assert health_body["safety_flags"]["telegram_sends_enabled"] is False
    assert health_body["safety_flags"]["money_movement_enabled"] is False
    assert health_body["telegram_mira"]["safety"]["telegramSendsEnabled"] is False

    frontend_contract = page.request.get(f"{BASE_URL}/api/frontend-contract")
    assert frontend_contract.ok
    frontend_body = frontend_contract.json()
    assert frontend_body["schema"] == "0guard.frontend_contract.v1"
    assert frontend_body["mode"] == "read_only_pre_wallet"
    assert frontend_body["safety"]["workbenchCanTriggerLiveActions"] is False
    assert frontend_body["safety"]["transactionSigningEnabled"] is False
    assert frontend_body["safety"]["moneyMovementEnabled"] is False
    assert "/api/0g/status" in frontend_body["apiRoutes"]
    assert "/api/0g/receipt" in frontend_body["apiRoutes"]
    assert "/api/data/summary" in frontend_body["apiRoutes"]
    assert "/api/data/provenance" in frontend_body["apiRoutes"]
    assert "/api/osint/sources" in frontend_body["apiRoutes"]
    assert "/api/intelligence/evolving" in frontend_body["apiRoutes"]
    assert "/api/local-inference/status" in frontend_body["apiRoutes"]
    assert "/api/telegram/local-inference-preview" in frontend_body["apiRoutes"]
    assert "/api/data/backfill-plan" in frontend_body["apiRoutes"]
    assert "/api/x402/data-products" in frontend_body["apiRoutes"]
    assert "/api/product/brief" in frontend_body["apiRoutes"]
    assert "/api/readyz" in frontend_body["apiRoutes"]
    assert "/api/wallet/alert-preview" in frontend_body["apiRoutes"]
    assert "/api/wallet/provider-guard" in frontend_body["apiRoutes"]
    assert "/api/threat-case-file" in frontend_body["apiRoutes"]
    assert "/api/experiments/frontier" in frontend_body["apiRoutes"]
    assert "/api/experiments/run" in frontend_body["apiRoutes"]
    assert "/api/hackathon/submission-brief" in frontend_body["apiRoutes"]
    assert "/api/hackathon/submission-packet" in frontend_body["apiRoutes"]
    assert "/api/hackathon/readiness" in frontend_body["apiRoutes"]
    assert "/api/hackathon/threat-passport" in frontend_body["apiRoutes"]
    assert "/api/integrations/cross-chain" in frontend_body["apiRoutes"]
    assert "/api/integrations/cross-chain/readiness" in frontend_body["apiRoutes"]
    assert "/api/integrations/virtuals-facilitator" in frontend_body["apiRoutes"]
    assert "/api/integrations/external-guardrails" in frontend_body["apiRoutes"]
    assert "/api/integrations/external-guardrails/evaluate" in frontend_body["apiRoutes"]
    assert "/api/reputation/adapters" in frontend_body["apiRoutes"]
    assert "/api/reputation/adapters/normalize" in frontend_body["apiRoutes"]
    assert "/api/reputation/shadow-cache" in frontend_body["apiRoutes"]
    assert "/api/telegram/status" in frontend_body["apiRoutes"]
    assert "/api/telegram/wallet-alert-preview" in frontend_body["apiRoutes"]
    assert "#provenance-summary" in frontend_body["requiredSelectors"]
    assert "#load-evolving-intel" in frontend_body["requiredSelectors"]
    assert "#load-local-inference" in frontend_body["requiredSelectors"]
    assert "#run-telegram-local-inference-preview" in frontend_body["requiredSelectors"]
    assert "#load-historical-backfill-plan" in frontend_body["requiredSelectors"]
    assert "#load-x402-data-products" in frontend_body["requiredSelectors"]
    assert "#load-live-provenance" in frontend_body["requiredSelectors"]
    assert "#load-product-brief" in frontend_body["requiredSelectors"]
    assert "#load-production-readiness" in frontend_body["requiredSelectors"]
    assert "#load-submission-packet" in frontend_body["requiredSelectors"]
    assert "#load-submission-readiness" in frontend_body["requiredSelectors"]
    assert "#load-threat-passport" in frontend_body["requiredSelectors"]
    assert "#load-cross-chain-catalog" in frontend_body["requiredSelectors"]
    assert "#load-cross-chain-readiness" in frontend_body["requiredSelectors"]
    assert "#load-virtuals-facilitator" in frontend_body["requiredSelectors"]
    assert "#load-external-guardrails" in frontend_body["requiredSelectors"]
    assert "#run-external-guardrail-check" in frontend_body["requiredSelectors"]
    assert "#run-wallet-alert-preview" in frontend_body["requiredSelectors"]
    assert "#run-telegram-wallet-alert-preview" in frontend_body["requiredSelectors"]
    assert "#run-wallet-provider-guard" in frontend_body["requiredSelectors"]
    assert "#run-threat-case-file" in frontend_body["requiredSelectors"]
    assert "#load-frontier-experiments" in frontend_body["requiredSelectors"]
    assert "#load-reputation-adapters" in frontend_body["requiredSelectors"]
    assert "#load-reputation-shadow-cache" in frontend_body["requiredSelectors"]

    external_contract = page.request.get(f"{BASE_URL}/api/external-action-contracts")
    assert external_contract.ok
    external_body = external_contract.json()
    assert external_body["defaultMode"] == "dry_run"
    assert external_body["livePostingEnabled"] is False
    assert external_body["telegramSendsEnabled"] is False
    assert external_body["transactionSigningEnabled"] is False
    assert external_body["workbenchCanTriggerLiveActions"] is False
    assert "X/Telegram posting from the browser" in external_body["blockedCapabilities"]

    telegram_status = page.request.get(f"{BASE_URL}/api/telegram/status")
    assert telegram_status.ok
    telegram_body = telegram_status.json()
    assert telegram_body["schema"] == "0guard.telegram_mira_status.v1"
    assert telegram_body["safety"]["telegramSendsEnabled"] is False
    assert telegram_body["safety"]["networkCalls"] is False

    data_summary = page.request.get(f"{BASE_URL}/api/data/summary")
    assert data_summary.ok
    data_summary_body = data_summary.json()
    assert data_summary_body["schema"] == "0guard.incident_summary.v1"
    assert data_summary_body["validation"]["ok"] is True

    detection = page.request.get(f"{BASE_URL}/api/data/detection-coverage")
    assert detection.ok
    detection_body = detection.json()
    assert detection_body["schema"] == "0guard.detection_coverage.v1"
    assert detection_body["coveredCount"] >= 12

    provenance = page.request.get(f"{BASE_URL}/api/data/provenance")
    assert provenance.ok
    provenance_body = provenance.json()
    assert provenance_body["schema"] == "0guard.incident_provenance_matrix.v1"
    assert provenance_body["coverage"]["incidentCount"] == 28
    assert provenance_body["coverage"]["withMatchedEvidence"] >= 20
    assert provenance_body["sourceStatus"]["evidenceMode"] == "canonical_dataset_evidence"
    assert provenance_body["safety"]["rawPayloadsReturned"] is False

    signature_readback = page.request.get(f"{BASE_URL}/api/data/signature-map")
    assert signature_readback.ok
    signature_body = signature_readback.json()
    assert signature_body["schema"] == "0guard.signature_map.v1"
    assert signature_body["gapCount"] == 0
    assert signature_body["matchedCount"] == 28

    osint_sources = page.request.get(f"{BASE_URL}/api/osint/sources")
    assert osint_sources.ok
    osint_body = osint_sources.json()
    assert osint_body["schema"] == "0guard.osint_source_registry.v1"
    assert osint_body["rightsPolicy"]["rawPayloadResaleAllowed"] is False

    osint_readiness = page.request.get(f"{BASE_URL}/api/osint/readiness")
    assert osint_readiness.ok
    readiness_body = osint_readiness.json()
    assert readiness_body["schema"] == "0guard.osint_readiness.v1"
    assert readiness_body["live"] is False
    assert readiness_body["safety"]["readOnly"] is True

    local_inference = page.request.get(f"{BASE_URL}/api/local-inference/status")
    assert local_inference.ok
    local_inference_body = local_inference.json()
    assert local_inference_body["schema"] == "0guard.local_inference_mesh.v1"
    assert local_inference_body["safety"]["promptExecutionEnabled"] is False
    assert local_inference_body["safety"]["telegramSendsEnabled"] is False

    local_digest = page.request.get(f"{BASE_URL}/api/telegram/local-inference-preview")
    assert local_digest.ok
    local_digest_body = local_digest.json()
    assert local_digest_body["schema"] == "0guard.telegram_local_inference_preview.v1"
    assert local_digest_body["telegram_send"] is False

    backfill = page.request.get(f"{BASE_URL}/api/data/backfill-plan")
    assert backfill.ok
    backfill_body = backfill.json()
    assert backfill_body["schema"] == "0guard.historical_backfill_plan.v1"
    assert backfill_body["safety"]["rawPayloadsReturned"] is False

    x402_products = page.request.get(f"{BASE_URL}/api/x402/data-products")
    assert x402_products.ok
    x402_body = x402_products.json()
    assert x402_body["schema"] == "0guard.x402_data_products.v1"
    assert x402_body["safety"]["x402SettlementEnabled"] is False

    frontier = page.request.get(f"{BASE_URL}/api/experiments/frontier")
    assert frontier.ok
    frontier_body = frontier.json()
    assert frontier_body["schema"] == "0guard.frontier_experiments.v1"
    assert frontier_body["safety"]["networkCalls"] is False

    frontier_preview = page.request.post(
        f"{BASE_URL}/api/experiments/run",
        data=json.dumps({"experimentId": "zero_g_storage_receipt_readback"}),
        headers={"content-type": "application/json"},
    )
    assert frontier_preview.ok
    frontier_preview_body = frontier_preview.json()
    assert frontier_preview_body["schema"] == "0guard.frontier_experiment_preview.v1"
    assert frontier_preview_body["preview"]["storageReceipt"]["stored"] is False
    assert frontier_preview_body["safety"]["liveStorageUpload"] is False

    crosschain = page.request.get(f"{BASE_URL}/api/integrations/cross-chain")
    assert crosschain.ok
    crosschain_body = crosschain.json()
    assert crosschain_body["schema"] == "0guard.crosschain_catalog.v1"
    assert crosschain_body["x402"]["mode"] == "prepared_not_live"
    assert crosschain_body["safety"]["bridgingEnabled"] is False

    crosschain_readiness = page.request.get(
        f"{BASE_URL}/api/integrations/cross-chain/readiness"
    )
    assert crosschain_readiness.ok
    crosschain_readiness_body = crosschain_readiness.json()
    assert crosschain_readiness_body["schema"] == "0guard.crosschain_readiness.v1"
    assert crosschain_readiness_body["live"] is False
    assert crosschain_readiness_body["paymentReadiness"]["x402Ready"] is False

    virtuals = page.request.get(f"{BASE_URL}/api/integrations/virtuals-facilitator")
    assert virtuals.ok
    virtuals_body = virtuals.json()
    assert virtuals_body["schema"] == "0guard.virtuals_facilitator_manifest.v1"
    assert virtuals_body["agent"]["launchStatus"] == "prepared_operator_required"

    guardrails = page.request.get(f"{BASE_URL}/api/integrations/external-guardrails")
    assert guardrails.ok
    guardrails_body = guardrails.json()
    assert guardrails_body["schema"] == "0guard.external_guardrail_catalog.v1"
    assert guardrails_body["safety"]["moneyMovementEnabled"] is False

    guardrail_eval = page.request.post(
        f"{BASE_URL}/api/integrations/external-guardrails/evaluate",
        data=json.dumps(
            {
                "target_id": "layerzero_v2",
                "action": "bridge_release",
                "config": {
                    "requiredDVNCount": 1,
                    "sendReceiveConfigSymmetric": False,
                    "nonceReplayProtection": False,
                },
            }
        ),
        headers={"content-type": "application/json"},
    )
    assert guardrail_eval.ok
    guardrail_eval_body = guardrail_eval.json()
    assert guardrail_eval_body["schema"] == "0guard.external_guardrail_evaluation.v1"
    assert guardrail_eval_body["decision"] == "deny"

    adapter_catalog = page.request.get(f"{BASE_URL}/api/reputation/adapters")
    assert adapter_catalog.ok
    adapter_catalog_body = adapter_catalog.json()
    assert adapter_catalog_body["schema"] == "0guard.reputation_adapter_catalog.v1"
    assert adapter_catalog_body["safety"]["networkCalls"] is False

    adapter_preview = page.request.post(
        f"{BASE_URL}/api/reputation/adapters/normalize",
        data=json.dumps(
            {
                "sourceId": "chainabuse",
                "subject": {
                    "url": "https://docs.0g.ai.evil.example/claim",
                    "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
                    "chain": "eip155:1",
                },
                "payload": {
                    "reports": [
                        {
                            "checked": True,
                            "confidence_score": 91,
                            "category": "phishing",
                            "reportUrl": "https://chainabuse.example/report/1",
                        }
                    ]
                },
            }
        ),
        headers={"content-type": "application/json"},
    )
    assert adapter_preview.ok
    adapter_preview_body = adapter_preview.json()
    assert adapter_preview_body["schema"] == "0guard.reputation_adapter_preview.v1"
    assert adapter_preview_body["rawPayloadReturned"] is False
    assert adapter_preview_body["reputationPreview"]["decision"]["decision"] == "deny"

    shadow_cache = page.request.get(f"{BASE_URL}/api/reputation/shadow-cache")
    assert shadow_cache.ok
    shadow_cache_body = shadow_cache.json()
    assert shadow_cache_body["schema"] == "0guard.reputation_shadow_cache.v1"
    assert shadow_cache_body["probePreview"]["decision"]["decision"] == "deny"
    assert shadow_cache_body["safety"]["networkCalls"] is False
    assert "docs.0g.ai.evil.example/claim" not in json.dumps(shadow_cache_body)

    readiness = page.request.get(f"{BASE_URL}/api/readyz")
    assert readiness.ok
    readiness_body = readiness.json()
    assert readiness_body["schema"] == "0guard.readyz.v1"
    assert readiness_body["safety"]["networkCalls"] is False
    assert readiness_body["safety"]["transactionSigningEnabled"] is False

    submission = page.request.get(f"{BASE_URL}/api/hackathon/submission-brief")
    assert submission.ok
    submission_body = submission.json()
    assert submission_body["schema"] == "0guard.hackathon_submission_brief.v1"
    assert submission_body["project"]["name"] == "0guard"
    assert submission_body["submissionRequirements"]["publicXPost"]["mandatory"] is True

    packet = page.request.get(f"{BASE_URL}/api/hackathon/submission-packet")
    assert packet.ok
    packet_body = packet.json()
    assert packet_body["schema"] == "0guard.hackquest_submission_packet.v1"
    assert packet_body["formFields"]["xPostUrl"] == "https://x.com/rariwrldd/status/2054779961425461542"

    readiness = page.request.get(f"{BASE_URL}/api/hackathon/readiness")
    assert readiness.ok
    readiness_body = readiness.json()
    assert readiness_body["schema"] == "0guard.hackquest_readiness_audit.v1"
    assert readiness_body["mainnetRequirement"]["chainId"] == 16661
    assert readiness_body["submittableNow"] is True

    passport = page.request.get(f"{BASE_URL}/api/hackathon/threat-passport")
    assert passport.ok
    passport_body = passport.json()
    assert passport_body["schema"] == "0guard.threat_receipt_passport.v1"
    assert passport_body["receipt"]["decision"] == "deny"
    assert passport_body["receipt"]["zeroG"]["chain_anchor"]["status"] == "preflight"
    assert passport_body["provenance"]["coverage"]["withMatchedEvidence"] == 28
    assert passport_body["signatureCoverage"]["gapCount"] == 0
    assert passport_body["safety"]["rawPayloadsReturned"] is False

    zg_status = page.request.get(f"{BASE_URL}/api/0g/status")
    assert zg_status.ok
    zg_body = zg_status.json()
    assert zg_body["schema"] == "0guard.0g_status.v1"
    assert zg_body["readMode"] == "live_rpc_read_only"
    assert zg_body["safety"]["privateKeyRequired"] is False
    assert zg_body["safety"]["signingEnabled"] is False
    assert zg_body["safety"]["broadcastingEnabled"] is False

    receipt = page.request.get(f"{BASE_URL}/api/0g/receipt?receipt_hash=0x{'a' * 64}")
    assert receipt.ok
    receipt_body = receipt.json()
    assert receipt_body["schema"] == "0guard.0g_receipt_verifier.v1"
    assert receipt_body["status"] in {"contract_not_configured", "not_found"}
    assert receipt_body["verified"] is False
    assert receipt_body["safety"]["signingEnabled"] is False

    evaluate = page.request.post(
        f"{BASE_URL}/api/evaluate",
        data=json.dumps(
            {
                "intent": {
                    "action": "send_eth",
                    "mode": "live_transaction",
                    "requires_signature": True,
                    "value_eth": 0.01,
                }
            }
        ),
        headers={"content-type": "application/json"},
    )
    assert evaluate.ok
    evaluate_body = evaluate.json()
    assert evaluate_body["decision"] == "deny"
    assert any("wallet signature" in blocker.lower() for blocker in evaluate_body["blockers"])

    provider_guard = page.request.post(
        f"{BASE_URL}/api/wallet/provider-guard",
        data=json.dumps(
            {
                "origin": "https://claim-drop.evil.example",
                "method": "eth_sendTransaction",
                "params": [
                    {
                        "chainId": "0x1",
                        "to": "0x000000000000000000000000000000000000dEaD",
                        "data": (
                            "0x095ea7b3"
                            "ffffffffffffffffffffffffffffffff"
                            "ffffffffffffffffffffffffffffffff"
                        ),
                        "value": "0x0",
                    }
                ],
            }
        ),
        headers={"content-type": "application/json"},
    )
    assert provider_guard.ok
    provider_guard_body = provider_guard.json()
    assert provider_guard_body["schema"] == "0guard.wallet_provider_guard.v1"
    assert provider_guard_body["decision"] == "deny"
    assert provider_guard_body["enforcement"]["providerCallAllowed"] is False
    assert provider_guard_body["safety"]["providerForwardingPerformedBy0guard"] is False


def exercise_wallet_provider_demo(page: Page) -> None:
    page.goto(f"{BASE_URL}/demo/wallet-provider-guard")

    expect(page).to_have_title("0guard Wallet Provider Demo")
    expect(page.locator("body")).to_contain_text("Wallet Provider Guard")
    expect(page.locator("#provider-demo-call-count")).to_contain_text("0")

    page.locator("#demo-read-chain").click()
    expect(page.locator("#provider-demo-decision")).to_contain_text("allow")
    expect(page.locator("#provider-demo-forwarded")).to_contain_text("yes")
    expect(page.locator("#provider-demo-call-count")).to_contain_text("1")
    expect(page.locator("#provider-demo-output")).to_contain_text('"forwardedToProvider": true')
    expect(page.locator("#provider-demo-log")).to_contain_text("eth_chainId")

    page.locator("#demo-switch-chain").click()
    expect(page.locator("#provider-demo-decision")).to_contain_text("review")
    expect(page.locator("#provider-demo-forwarded")).to_contain_text("no")
    expect(page.locator("#provider-demo-call-count")).to_contain_text("1")
    expect(page.locator("#provider-demo-output")).to_contain_text(
        "show_review_before_wallet_prompt"
    )

    page.locator("#demo-unlimited-approval").click()
    expect(page.locator("#provider-demo-decision")).to_contain_text("deny")
    expect(page.locator("#provider-demo-forwarded")).to_contain_text("no")
    expect(page.locator("#provider-demo-call-count")).to_contain_text("1")
    expect(page.locator("#provider-demo-output")).to_contain_text(
        "block_before_wallet_prompt"
    )
    expect(page.locator("#provider-demo-log")).not_to_contain_text("eth_sendTransaction")


def exercise_external_wallet_provider_dapp(page: Page) -> None:
    page.add_init_script(
        """
        window.ethereum = {
          async request(request) {
            window.__externalProviderCalls = window.__externalProviderCalls || [];
            window.__externalProviderCalls.push({
              method: request.method,
              params: request.params || []
            });
            if (request.method === 'eth_chainId') {
              return '0x1';
            }
            return { forwarded: true, method: request.method };
          }
        };
        """
    )
    page.goto(EXTERNAL_DAPP_URL)

    expect(page).to_have_title("0guard External Wallet Demo")
    expect(page.locator("body")).to_contain_text("0guard before")
    page.locator("#guard-base-url").fill(BASE_URL)

    page.locator("#run-read-chain").click()
    expect(page.locator("#decision-pill")).to_contain_text("allow")
    expect(page.locator("#result-output")).to_contain_text('"forwardedToProvider": true')
    expect(page.locator("#result-output")).to_contain_text('"providerCallCount": 1')
    expect(page.locator("#provider-log")).to_contain_text("eth_chainId")

    page.locator("#run-switch-chain").click()
    expect(page.locator("#decision-pill")).to_contain_text("review")
    expect(page.locator("#result-output")).to_contain_text(
        '"forwardedToProvider": false'
    )
    expect(page.locator("#result-output")).to_contain_text('"providerCallCount": 1')
    expect(page.locator("#result-output")).to_contain_text(
        "show_review_before_wallet_prompt"
    )

    page.locator("#run-unlimited-approval").click()
    expect(page.locator("#decision-pill")).to_contain_text("deny")
    expect(page.locator("#result-output")).to_contain_text(
        '"forwardedToProvider": false'
    )
    expect(page.locator("#result-output")).to_contain_text('"providerCallCount": 1')
    expect(page.locator("#result-output")).to_contain_text("block_before_wallet_prompt")
    expect(page.locator("#provider-log")).not_to_contain_text("eth_sendTransaction")


def exercise_workbench_mobile(page: Page) -> None:
    page.goto(BASE_URL)

    expect(page).to_have_title("0guard Workbench")
    expect(page.locator("body")).to_contain_text("0G Hack Guard")
    expect(page.locator("#plain-explanation")).to_contain_text("Safe simulations pass")
    expect(page.locator("#flow-line")).not_to_be_visible()
    expect(page.locator("#flow-packet")).not_to_be_visible()

    page.locator("#run-safe-scenario").click()
    expect(page.locator("#decision-pill")).to_contain_text("allow")
    expect(page.locator("#wallet-state")).to_contain_text("simulation only")
    expect(page.locator("#result-output")).to_contain_text('"decision": "allow"')

    overflow_px = page.evaluate(
        "() => document.documentElement.scrollWidth - document.documentElement.clientWidth"
    )
    assert overflow_px <= 2


def exercise_telegram_miniapp(page: Page) -> None:
    page.route(
        "https://telegram.org/js/telegram-web-app.js",
        lambda route: route.fulfill(
            status=200,
            content_type="application/javascript",
            body=(
                "window.Telegram={WebApp:{initData:'',themeParams:{},"
                "ready(){},expand(){},MainButton:{setText(){},onClick(){},show(){}}}};"
            ),
        ),
    )
    page.set_viewport_size({"width": 390, "height": 844})
    page.goto(f"{BASE_URL}/telegram")

    expect(page).to_have_title("0guard Telegram Mini App")
    expect(page.locator("body")).to_contain_text("0guard Mini App")
    expect(page.locator("body")).to_contain_text("Wallet alert")
    expect(page.locator("body")).to_contain_text("Mira add-on")
    expect(page.locator("#miniapp-mode")).to_contain_text("browser preview")
    expect(page.locator("#miniapp-auth-status")).to_contain_text("local preview")
    expect(page.locator("#miniapp-session-output")).to_contain_text(
        "0guard.telegram_miniapp_session.v1"
    )
    expect(page.locator("#miniapp-session-output")).to_contain_text('"sendDataUsed": false')
    expect(page.locator("#miniapp-quality-output")).to_contain_text(
        '"telegramSendEnabled": false'
    )

    page.locator("#miniapp-preview-alert").click()
    expect(page.locator("#miniapp-output")).to_contain_text(
        "0guard.telegram_miniapp_preview.v1"
    )
    expect(page.locator("#miniapp-output")).to_contain_text('"telegram_send": false')
    expect(page.locator("#miniapp-output")).to_contain_text("0guard.reputation_probe.v1")
    expect(page.locator("#miniapp-output")).to_contain_text('"rawPayloadsReturned": false')
    expect(page.locator("#miniapp-output")).to_contain_text('"decision": "deny"')
    expect(page.locator("#miniapp-alert-message")).to_contain_text(
        "no Telegram message sent"
    )
    expect(page.locator("#miniapp-evidence-verdict")).to_contain_text("deny")
    expect(page.locator("#miniapp-evidence-boundary")).to_contain_text("raw payload hidden")
    expect(page.locator("#miniapp-evidence-receipt")).not_to_contain_text("pending")
    expect(page.locator("#miniapp-mira-output")).to_contain_text("0guard.mira_preview.v1")
    expect(page.locator("#miniapp-flow")).to_have_attribute("data-verdict", "deny")

    page.locator("#miniapp-run-mira").click()
    expect(page.locator("#miniapp-mira-output")).to_contain_text('"telegram_send": false')

    contract = page.request.get(f"{BASE_URL}/api/telegram/miniapp/contract")
    assert contract.ok
    contract_body = contract.json()
    assert contract_body["schema"] == "0guard.telegram_miniapp_contract.v1"
    assert contract_body["route"] == "/telegram"
    assert contract_body["telegramApi"]["usesTelegramWebAppJs"] is True
    assert contract_body["telegramApi"]["serverSideValidationRequired"] is True
    assert contract_body["telegramApi"]["sendDataUsed"] is False
    assert contract_body["safety"]["telegramSendsEnabled"] is False
    assert "/api/telegram/miniapp/session" in contract_body["apiRoutes"]
    assert "/api/telegram/miniapp/preview" in contract_body["apiRoutes"]


def assert_flow_packet_clear_of_node_labels(page: Page) -> None:
    packet = page.locator("#flow-packet").bounding_box()
    assert packet is not None
    for selector in ("#agent-state", "#wallet-state", "#receipt-state"):
        label = page.locator(selector).bounding_box()
        assert label is not None
        assert not boxes_overlap(packet, label), f"{selector} overlaps the flow packet"


def boxes_overlap(first: dict[str, float], second: dict[str, float]) -> bool:
    return not (
        first["x"] + first["width"] <= second["x"]
        or second["x"] + second["width"] <= first["x"]
        or first["y"] + first["height"] <= second["y"]
        or second["y"] + second["height"] <= first["y"]
    )


if __name__ == "__main__":
    raise SystemExit(main())
