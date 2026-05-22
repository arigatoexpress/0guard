const GUARD_BASE_DEFAULT = 'https://guard0-miniapp-s77j6bxyra-uc.a.run.app';
const PROOF_OUTPUT_PATH = 'docs/hackathon-0g/wallet-provider-external-proof.json';

const scenarios = {
  read: {
    label: 'Read chain',
    request: { method: 'eth_chainId', params: [] },
    expectedDecision: 'allow',
    mayForward: true
  },
  switch: {
    label: 'Switch chain',
    request: { method: 'wallet_switchEthereumChain', params: [{ chainId: '0xa4b1' }] },
    expectedDecision: 'review',
    mayForward: false
  },
  approval: {
    label: 'Unlimited approval',
    request: {
      method: 'eth_sendTransaction',
      params: [
        {
          chainId: '0x1',
          to: '0x000000000000000000000000000000000000dEaD',
          data: '0x095ea7b3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
          value: '0x0'
        }
      ]
    },
    expectedDecision: 'deny',
    mayForward: false
  }
};

const forwardedCalls = [];
const proofScenarios = {};

function el(id) {
  return document.getElementById(id);
}

function provider() {
  return window.ethereum;
}

function writeJson(id, payload) {
  el(id).textContent = JSON.stringify(payload, null, 2);
}

function setDecision(decision) {
  const status = decision || 'review';
  const pill = el('provider-status');
  pill.classList.remove('allow', 'review', 'deny');
  pill.classList.add(status);
  pill.textContent = decision ? `decision: ${decision}` : 'checking provider';
  el('decision-value').textContent = decision || 'waiting';
}

function renderProviderState() {
  const hasProvider = Boolean(provider()?.request);
  const pill = el('provider-status');
  if (!hasProvider) {
    pill.classList.remove('allow', 'review', 'deny');
    pill.classList.add('deny');
    pill.textContent = 'window.ethereum unavailable';
  } else if (!el('decision-value').textContent || el('decision-value').textContent === 'waiting') {
    pill.classList.remove('deny', 'review');
    pill.classList.add('allow');
    pill.textContent = 'window.ethereum detected';
  }
  el('origin-value').textContent = window.location.origin;
  el('provider-call-count').textContent = String(forwardedCalls.length);
  writeJson('provider-log', forwardedCalls);
}

async function guardRequest(request) {
  const baseUrl = (el('guard-base-url').value || GUARD_BASE_DEFAULT).replace(/\/$/, '');
  const response = await fetch(`${baseUrl}/api/wallet/provider-guard`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      origin: window.location.origin,
      method: request.method,
      params: request.params || [],
      sourceProject: 'github_pages_wallet_provider_proof_capture',
      surface: 'metamask_wallet'
    })
  });
  if (!response.ok) {
    throw new Error(`0guard returned HTTP ${response.status}`);
  }
  return await response.json();
}

async function run(kind) {
  const scenario = scenarios[kind];
  if (!scenario) {
    throw new Error(`Unknown scenario: ${kind}`);
  }
  setBusy(true);
  try {
    let providerResult = null;
    let forwarded = false;
    const verdict = await guardRequest(scenario.request);
    setDecision(verdict.decision);

    if (scenario.mayForward && verdict.enforcement?.providerCallAllowed) {
      if (!provider()?.request) {
        throw new Error('window.ethereum is unavailable. Open this page in a wallet-enabled browser.');
      }
      forwardedCalls.push({
        method: scenario.request.method,
        at: new Date().toISOString()
      });
      providerResult = await provider().request(scenario.request);
      forwarded = true;
    } else if (!scenario.mayForward && verdict.enforcement?.providerCallAllowed) {
      providerResult = 'unexpected_allow_refused_by_capture_page';
    }

    proofScenarios[kind] = proofScenario(kind, scenario, verdict, forwarded);
    writeJson('result-output', {
      scenario: scenario.label,
      expectedDecision: scenario.expectedDecision,
      forwardedToProvider: forwarded,
      providerResult,
      providerCallCount: forwardedCalls.length,
      verdict: publicVerdict(verdict)
    });
    writeProofPreview();
  } catch (error) {
    setDecision('deny');
    writeJson('result-output', { error: String(error.message || error) });
  } finally {
    renderProviderState();
    setBusy(false);
  }
}

function proofScenario(kind, scenario, verdict, forwarded) {
  return {
    kind,
    method: scenario.request.method,
    decision: verdict.decision,
    expectedDecision: scenario.expectedDecision,
    forwardedToProvider: forwarded,
    walletPromptShown: false,
    providerCallCount: forwardedCalls.length,
    receiptHash: verdict.receipt?.hash || ''
  };
}

function publicVerdict(verdict) {
  return {
    schema: verdict.schema,
    decision: verdict.decision,
    providerMethod: verdict.providerMethod,
    enforcement: verdict.enforcement,
    safety: verdict.safety,
    receipt: verdict.receipt,
    request: verdict.request
  };
}

async function sha256Hex(value) {
  const encoded = new TextEncoder().encode(String(value || '').trim().toLowerCase());
  const digest = await crypto.subtle.digest('SHA-256', encoded);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function buildProofDraft() {
  const rawAddress = el('throwaway-wallet-address').value.trim();
  const missing = [];
  for (const key of ['read', 'switch', 'approval']) {
    if (!proofScenarios[key]?.receiptHash) {
      missing.push(key);
    }
  }
  if (!rawAddress) {
    missing.push('throwaway_wallet_address_for_hashing');
  }
  if (!provider()?.request) {
    missing.push('window_ethereum');
  }
  if (!el('real-extension-check').checked) {
    missing.push('real_wallet_extension_operator_check');
  }
  if (!el('empty-wallet-check').checked) {
    missing.push('throwaway_empty_wallet_operator_check');
  }
  if (!el('operator-reviewed-check').checked) {
    missing.push('operator_review');
  }

  if (missing.length) {
    writeJson('proof-output', {
      schema: '0guard.wallet_provider_external_proof_draft.v1',
      status: 'incomplete',
      missing,
      rawWalletAddressStored: false,
      rawParamsStored: false
    });
    return;
  }

  const walletAddressHash = await sha256Hex(rawAddress);
  const guardBaseUrl = (el('guard-base-url').value || GUARD_BASE_DEFAULT).replace(/\/$/, '');
  const draft = {
    schema: '0guard.wallet_provider_external_proof_draft.v1',
    generatedAt: new Date().toISOString(),
    status: 'ready_for_operator_review',
    externalDappOrigin: window.location.origin,
    guardBaseUrl,
    windowEthereumPresent: Boolean(provider()?.request),
    walletAddressHash,
    proofOutputPath: PROOF_OUTPUT_PATH,
    rawWalletAddressStored: false,
    rawParamsStored: false,
    recorderCommand: [
      'PYTHONPATH=src .venv/bin/python scripts/record_wallet_provider_external_proof.py',
      `--external-dapp-origin ${shellQuote(window.location.origin)}`,
      `--guard-base-url ${shellQuote(guardBaseUrl)}`,
      `--wallet-address-hash ${walletAddressHash}`,
      `--read-receipt-hash ${proofScenarios.read.receiptHash}`,
      `--review-receipt-hash ${proofScenarios.switch.receiptHash}`,
      `--deny-receipt-hash ${proofScenarios.approval.receiptHash}`,
      `--out ${shellQuote(PROOF_OUTPUT_PATH)}`,
      '--real-wallet-extension',
      '--window-ethereum-present',
      '--throwaway-empty-wallet',
      '--operator-reviewed'
    ].join(' \\\n  '),
    scenarioEvidence: {
      readOnlyRequest: proofScenarios.read,
      reviewRequest: proofScenarios.switch,
      denyRequest: proofScenarios.approval
    },
    operatorChecks: [
      'The provider was a real browser wallet extension, not an injected mock.',
      'The selected account was a throwaway wallet with no funds or assets.',
      'Switch chain and unlimited approval did not open a wallet prompt.',
      'No private key, mnemonic, raw params, or raw wallet address is stored in the proof.'
    ]
  };
  writeJson('proof-output', draft);
}

function writeProofPreview() {
  const completed = Object.keys(proofScenarios).sort();
  writeJson('proof-output', {
    schema: '0guard.wallet_provider_external_proof_draft.v1',
    status: completed.length === 3 ? 'needs_wallet_hash_and_operator_checks' : 'collecting_scenarios',
    completed,
    rawWalletAddressStored: false,
    rawParamsStored: false
  });
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function setBusy(isBusy) {
  for (const button of document.querySelectorAll('button')) {
    button.disabled = isBusy;
  }
}

el('run-read-chain').addEventListener('click', () => run('read'));
el('run-switch-chain').addEventListener('click', () => run('switch'));
el('run-unlimited-approval').addEventListener('click', () => run('approval'));
el('build-proof-draft').addEventListener('click', () => {
  buildProofDraft().catch((error) => {
    writeJson('proof-output', { error: String(error.message || error) });
  });
});

el('guard-base-url').value = GUARD_BASE_DEFAULT;
writeJson('result-output', {
  status: 'ready',
  origin: window.location.origin,
  boundary: 'Only eth_chainId may reach window.ethereum.request from this capture page.'
});
renderProviderState();
