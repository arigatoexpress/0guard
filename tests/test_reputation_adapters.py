"""Tests for no-network external reputation adapter normalization."""

from guard0.reputation_adapters import (
    normalize_reputation_adapters_from_payload,
    normalize_reputation_adapter_payload,
    reputation_adapter_catalog,
)


def test_reputation_adapter_catalog_is_no_network_and_rights_safe():
    catalog = reputation_adapter_catalog()

    assert catalog["schema"] == "0guard.reputation_adapter_catalog.v1"
    assert catalog["mode"] == "adapter_contracts_no_network_calls"
    assert catalog["adapterCount"] >= 11
    assert catalog["activationOrder"][:3] == [
        "phishdestroy_destroylist",
        "scamsniffer_blacklist",
        "cryptoscamdb",
    ]
    assert catalog["safety"]["networkCalls"] is False
    assert catalog["safety"]["rawPayloadsReturned"] is False
    assert catalog["rightsPolicy"]["rawPayloadResaleAllowed"] is False


def test_reputation_adapter_normalize_accepts_source_alias_for_source_id():
    result = normalize_reputation_adapter_payload(
        {
            "source": "cryptoscamdb",
            "payload": {
                "urls": [
                    {
                        "url": "https://wallet-help.example/0g",
                        "category": "phishing",
                        "updated": "2026-05-15T00:00:00Z",
                    }
                ]
            },
        }
    )

    assert result["sourceId"] == "cryptoscamdb"
    assert result["rawPayloadReturned"] is False


def test_phishdestroy_payload_normalizes_active_domain_without_raw_url_echo():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "phishdestroy_destroylist",
            "subject": {"url": "https://docs.0g.ai.evil.example/claim"},
            "payload": {
                "active_domains": [
                    {
                        "domain": "docs.0g.ai.evil.example",
                        "site_status": "alive",
                        "target_brand": "0G",
                        "drainer_type": "approval_drainer",
                        "url": "https://docs.0g.ai.evil.example/claim",
                    }
                ]
            },
        }
    )

    assert result["sourceId"] == "phishdestroy_destroylist"
    assert result["derivedEvidence"][0]["sourceId"] == "phishdestroy_destroylist"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["reputationPreview"]["decision"]["decision"] == "deny"
    assert "docs.0g.ai.evil.example/claim" not in str(result)


def test_phishdestroy_active_domains_string_implies_active_and_denies():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "phishdestroy_destroylist",
            "payload": {"active_domains": ["bad-example-phish-site.test"]},
        }
    )

    assert result["sourceId"] == "phishdestroy_destroylist"
    assert result["derivedEvidence"][0]["sourceId"] == "phishdestroy_destroylist"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["reputationPreview"]["decision"]["decision"] == "deny"


def test_cryptoscamdb_payload_normalizes_reported_rows_without_raw_url_echo():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "cryptoscamdb",
            "subject": {
                "url": "https://wallet-help.example/0g",
                "address": "0x885b0892D241Cb5033C9995e09cA521d54f936b5",
            },
            "payload": {
                "urls": [
                    {
                        "url": "https://wallet-help.example/0g",
                        "category": "phishing",
                        "updated": "2026-05-15T00:00:00Z",
                    }
                ]
            },
        }
    )

    assert result["sourceId"] == "cryptoscamdb"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["derivedEvidence"][0]["confidence"] == 0.72
    assert result["reputationPreview"]["decision"]["decision"] == "review"
    assert "wallet-help.example/0g" not in str(result)


def test_forta_labelled_dataset_payload_normalizes_offline_labels():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "forta_labelled_datasets",
            "subject": {
                "address": "0x885b0892D241Cb5033C9995e09cA521d54f936b5",
                "chain": "eip155:1",
            },
            "payload": {
                "labels": [
                    {
                        "label": "attacker",
                        "confidence": 0.83,
                        "sourceUrl": "https://github.com/forta-network/labelled-datasets",
                    }
                ]
            },
        }
    )

    assert result["sourceId"] == "forta_labelled_datasets"
    assert result["derivedEvidence"][0]["sourceId"] == "forta_labelled_datasets"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["reputationPreview"]["decision"]["decision"] == "deny"


def test_goplus_payload_normalizes_to_deny_without_raw_payload_echo():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "goplus_security",
            "subject": {
                "url": "https://docs.0g.ai.evil.example/claim",
                "address": "0x02228b0afcdbEdf8180D96Fc181Da3AF5DD1d1ab",
                "chain": "eip155:1",
            },
            "payload": {
                "result": {
                    "0x02228b0afcdbeDf8180d96fc181da3af5dd1d1ab": {
                        "blacklist_doubt": "1",
                        "phishing_activities": "1",
                        "url": "https://scanner.example/private-report",
                    }
                }
            },
        }
    )

    assert result["schema"] == "0guard.reputation_adapter_preview.v1"
    assert result["sourceId"] == "goplus_security"
    assert result["rawPayloadReturned"] is False
    assert result["rawPayloadHash"]
    assert result["subject"]["addressRedacted"] == "0x0222...D1d1ab"
    assert result["derivedEvidenceCount"] == 1
    assert result["derivedEvidence"][0]["sourceId"] == "goplus_security"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["derivedEvidence"][0]["referenceUrlHash"]
    assert "scanner.example" not in str(result)
    assert result["reputationPreview"]["decision"]["decision"] == "deny"
    assert result["reputationPreview"]["rawPayloadsReturned"] is False
    assert result["safety"]["networkCalls"] is False


def test_new_open_source_adapter_payloads_normalize_without_live_fetches():
    scam = normalize_reputation_adapter_payload(
        {
            "sourceId": "scamsniffer_blacklist",
            "payload": {
                "domains": [
                    {
                        "domain": "wallet-drainer.example",
                        "list_type": "drainer",
                        "delay_days": 7,
                    }
                ]
            },
        }
    )
    ofac = normalize_reputation_adapter_payload(
        {
            "sourceId": "ofac_sanctions_sls",
            "payload": {
                "matches": [
                    {
                        "digital_currency_address": "0x1111111111111111111111111111111111111111",
                        "program": "SDN",
                        "sdn_id": "123",
                    }
                ]
            },
        }
    )
    evm = normalize_reputation_adapter_payload(
        {
            "sourceId": "evm_event_index",
            "payload": {
                "approvals": [
                    {
                        "method": "approve",
                        "spender": "0x2222222222222222222222222222222222222222",
                        "value": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    }
                ]
            },
        }
    )

    assert scam["derivedEvidence"][0]["verdict"] == "malicious"
    assert ofac["derivedEvidence"][0]["verdict"] == "malicious"
    assert evm["derivedEvidence"][0]["verdict"] == "malicious"
    assert all(item["safety"]["networkCalls"] is False for item in (scam, ofac, evm))


def test_chainabuse_payload_normalizes_checked_reports_to_deny():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "chainabuse",
            "subject": {
                "url": "https://wallet-help.example/0g",
                "address": "0x885b0892D241Cb5033C9995e09cA521d54f936b5",
                "chain": "eip155:1",
            },
            "payload": {
                "reports": [
                    {
                        "checked": True,
                        "confidence_score": 92,
                        "category": "phishing",
                        "reportUrl": "https://chainabuse.example/report/123",
                    }
                ]
            },
        }
    )

    assert result["sourceId"] == "chainabuse"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["derivedEvidence"][0]["confidence"] == 0.92
    assert result["reputationPreview"]["decision"]["decision"] == "deny"
    assert "chainabuse.example" not in str(result)


def test_forta_payload_normalizes_alerts_and_labels_without_fetching():
    result = normalize_reputation_adapter_payload(
        {
            "sourceId": "forta_graphql_api",
            "subject": {
                "address": "0x885b0892D241Cb5033C9995e09cA521d54f936b5",
                "chain": "eip155:1",
            },
            "payload": {
                "alerts": [
                    {
                        "severity": "High",
                        "name": "Exploit-stage approval drain",
                        "botId": "0xforta-bot",
                        "sourceUrl": "https://forta.example/alert/abc",
                    }
                ],
                "labels": [{"label": "attacker", "confidence": 0.77}],
            },
        }
    )

    assert result["sourceId"] == "forta_graphql_api"
    assert result["derivedEvidence"][0]["verdict"] == "malicious"
    assert result["derivedEvidenceCount"] == 2
    assert result["reputationPreview"]["decision"]["decision"] == "deny"
    assert result["safety"]["liveConnectorFetch"] is False
    assert result["rightsPolicy"]["sourceLinksOrHashesOnly"] is True


def test_reputation_adapter_normalizer_rejects_unknown_source():
    try:
        normalize_reputation_adapter_payload({"sourceId": "unknown", "payload": {}})
    except ValueError as exc:
        assert "unsupported sourceId" in str(exc)
    else:
        raise AssertionError("unknown sourceId should be rejected")


def test_embedded_adapter_payloads_normalize_as_a_batch():
    previews = normalize_reputation_adapters_from_payload(
        {
            "reputationAdapters": [
                {
                    "sourceId": "chainabuse",
                    "subject": {"url": "https://wallet-help.example"},
                    "payload": {"reported_count": 2},
                },
                {
                    "sourceId": "goplus_security",
                    "subject": {"address": "0x885b0892D241Cb5033C9995e09cA521d54f936b5"},
                    "payload": {"result": {"is_blacklisted": "0"}},
                },
            ]
        }
    )

    assert [preview["sourceId"] for preview in previews] == ["chainabuse", "goplus_security"]
    assert all(preview["rawPayloadReturned"] is False for preview in previews)
    assert previews[0]["derivedEvidence"][0]["verdict"] == "suspicious"
    assert previews[1]["derivedEvidence"][0]["verdict"] == "unknown"
