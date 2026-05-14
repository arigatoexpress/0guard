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

from playwright.sync_api import Page, expect, sync_playwright

PORT = int(os.environ.get("ZEROGUARD_BROWSER_SMOKE_PORT", "8139"))
BASE_URL = f"http://127.0.0.1:{PORT}"


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
    expect(page.locator("body")).to_contain_text("Intent Firewall")
    expect(page.locator("body")).to_contain_text("Hack Signature Check")
    expect(page.locator("body")).to_contain_text("Domain Guard")
    expect(page.locator("#mode-pill")).to_contain_text("no signing")
    expect(page.locator("#send-pill")).to_contain_text("external sends blocked")
    expect(page.locator("#contract-output")).to_contain_text("workbenchCanTriggerLiveActions")
    expect(page.locator("#contract-output")).to_contain_text('"livePostingEnabled": false')
    expect(page.locator("#contract-output")).to_contain_text('"telegramSendsEnabled": false')
    expect(page.locator("#zg-status-output")).to_contain_text("0guard.0g_status.v1")
    expect(page.locator("#zg-status-output")).to_contain_text('"privateKeyRequired": false')
    expect(page.locator("#zg-status-output")).to_contain_text('"signingEnabled": false')
    page.locator("#verify-receipt").click()
    expect(page.locator("#zg-status-output")).to_contain_text("0guard.0g_receipt_verifier.v1")
    expect(page.locator("#zg-status-output")).to_contain_text("contract_not_configured")
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

    page.locator("#load-allow-sample").click()
    page.locator("#run-evaluate").click()
    expect(page.locator("#decision-pill")).to_contain_text("allow")
    expect(page.locator("#flow-canvas")).to_have_attribute("data-state", "allow")
    expect(page.locator("#wallet-state")).to_contain_text("simulation only")
    expect(page.locator("#result-output")).to_contain_text('"decision": "allow"')
    expect(page.locator("#result-output")).to_contain_text('"mode": "simulation"')

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
    expect(page.locator("#provenance-summary")).to_contain_text("26/28")
    expect(page.locator("#provenance-summary")).to_contain_text("cached")
    page.locator("#load-signature-map").click()
    expect(page.locator("#data-flow-output")).to_contain_text("0guard.signature_map.v1")
    expect(page.locator("#data-flow-output")).to_contain_text('"gapCount"')

    page.locator("#load-osint-readiness").click()
    expect(page.locator("#osint-output")).to_contain_text("0guard.osint_readiness.v1")
    expect(page.locator("#osint-output")).to_contain_text('"rawPayloadsReturned": false')
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
    assert "/api/hackathon/submission-brief" in frontend_body["apiRoutes"]
    assert "/api/hackathon/submission-packet" in frontend_body["apiRoutes"]
    assert "/api/hackathon/readiness" in frontend_body["apiRoutes"]
    assert "/api/hackathon/threat-passport" in frontend_body["apiRoutes"]
    assert "/api/integrations/cross-chain" in frontend_body["apiRoutes"]
    assert "/api/integrations/cross-chain/readiness" in frontend_body["apiRoutes"]
    assert "/api/integrations/virtuals-facilitator" in frontend_body["apiRoutes"]
    assert "/api/telegram/status" in frontend_body["apiRoutes"]
    assert "#provenance-summary" in frontend_body["requiredSelectors"]
    assert "#load-live-provenance" in frontend_body["requiredSelectors"]
    assert "#load-submission-packet" in frontend_body["requiredSelectors"]
    assert "#load-submission-readiness" in frontend_body["requiredSelectors"]
    assert "#load-threat-passport" in frontend_body["requiredSelectors"]
    assert "#load-cross-chain-catalog" in frontend_body["requiredSelectors"]
    assert "#load-cross-chain-readiness" in frontend_body["requiredSelectors"]
    assert "#load-virtuals-facilitator" in frontend_body["requiredSelectors"]

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
    assert signature_body["gapCount"] >= 1

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
    assert passport_body["provenance"]["coverage"]["withMatchedEvidence"] == 26
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
    assert receipt_body["status"] == "contract_not_configured"
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


if __name__ == "__main__":
    raise SystemExit(main())
