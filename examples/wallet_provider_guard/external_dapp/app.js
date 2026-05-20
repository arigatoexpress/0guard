const scenarios = {
  read: {
    label: 'Read chain',
    request: {method: 'eth_chainId', params: []}
  },
  switch: {
    label: 'Switch chain',
    request: {method: 'wallet_switchEthereumChain', params: [{chainId: '0xa4b1'}]}
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
    }
  }
};

const forwardedCalls = [];
const proofScenarios = {};

function el(id) {
  return document.getElementById(id);
}

function writeJson(id, payload) {
  el(id).textContent = JSON.stringify(payload, null, 2);
}

function setDecision(decision) {
  const pill = el('decision-pill');
  pill.classList.remove('allow', 'review', 'deny');
  pill.classList.add(decision || 'review');
  pill.textContent = decision || 'waiting';
}

function provider() {
  return window.ethereum;
}

async function guardRequest(request) {
  const baseUrl = el('guard-base-url').value.replace(/\/$/, '');
  const response = await fetch(`${baseUrl}/api/wallet/provider-guard`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      origin: window.location.origin,
      method: request.method,
      params: request.params || [],
      sourceProject: 'external_wallet_provider_demo',
      surface: 'metamask_wallet'
    })
  });
  if(!response.ok){
    throw new Error(`0guard returned HTTP ${response.status}`);
  }
  return await response.json();
}

async function guardedProviderRequest(request) {
  const verdict = await guardRequest(request);
  setDecision(verdict.decision);
  if(!verdict.enforcement.providerCallAllowed){
    const error = new Error(verdict.enforcement.message);
    error.verdict = verdict;
    throw error;
  }
  if(!provider()?.request){
    throw new Error('window.ethereum is not available. Open this page in a wallet-enabled browser.');
  }
  forwardedCalls.push({method: request.method, at: new Date().toISOString()});
  return await provider().request(request);
}

async function run(kind) {
  const scenario = scenarios[kind];
  setBusy(true);
  try{
    let providerResult = null;
    let forwarded = false;
    const verdict = await guardRequest(scenario.request);
    setDecision(verdict.decision);
    if(verdict.enforcement.providerCallAllowed){
      if(!provider()?.request){
        throw new Error('window.ethereum is not available. Open this page in a wallet-enabled browser.');
      }
      forwardedCalls.push({method: scenario.request.method, at: new Date().toISOString()});
      providerResult = await provider().request(scenario.request);
      forwarded = true;
    }
    proofScenarios[kind] = proofScenario(kind, scenario, verdict, forwarded);
    writeJson('result-output', {
      scenario: scenario.label,
      forwardedToProvider: forwarded,
      providerResult,
      verdict: publicVerdict(verdict),
      providerCallCount: forwardedCalls.length
    });
    writeProofPreview();
  }catch(error){
    setDecision('deny');
    writeJson('result-output', {error: String(error.message || error)});
  }finally{
    writeJson('provider-log', forwardedCalls);
    setBusy(false);
  }
}

function proofScenario(kind, scenario, verdict, forwarded) {
  return {
    kind,
    method: scenario.request.method,
    decision: verdict.decision,
    forwardedToProvider: forwarded,
    walletPromptShown: false,
    providerCallCount: forwardedCalls.length,
    receiptHash: verdict.receipt?.hash || ''
  };
}

function publicVerdict(verdict) {
  if(!verdict){
    return null;
  }
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
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}

async function buildProofDraft() {
  const rawAddress = el('throwaway-wallet-address').value.trim();
  const missing = [];
  for(const key of ['read', 'switch', 'approval']){
    if(!proofScenarios[key]?.receiptHash){
      missing.push(key);
    }
  }
  if(!rawAddress){
    missing.push('throwaway_wallet_address_for_hashing');
  }
  if(missing.length){
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
  const guardBaseUrl = el('guard-base-url').value.replace(/\/$/, '');
  const draft = {
    schema: '0guard.wallet_provider_external_proof_draft.v1',
    generatedAt: new Date().toISOString(),
    status: 'ready_for_operator_review',
    externalDappOrigin: window.location.origin,
    guardBaseUrl,
    windowEthereumPresent: Boolean(provider()?.request),
    walletAddressHash,
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
      'The browser provider was a real wallet extension, not an injected test provider.',
      'The account was a throwaway empty wallet.',
      'Switch chain and unlimited approval did not open a wallet prompt.'
    ]
  };
  writeJson('proof-output', draft);
}

function writeProofPreview() {
  const completed = Object.keys(proofScenarios).sort();
  writeJson('proof-output', {
    schema: '0guard.wallet_provider_external_proof_draft.v1',
    status: completed.length === 3 ? 'needs_throwaway_wallet_hash' : 'collecting_scenarios',
    completed,
    rawWalletAddressStored: false,
    rawParamsStored: false
  });
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\\\\''")}'`;
}

function setBusy(isBusy) {
  for(const button of document.querySelectorAll('button')){
    button.disabled = isBusy;
  }
}

el('run-read-chain').addEventListener('click', () => run('read'));
el('run-switch-chain').addEventListener('click', () => run('switch'));
el('run-unlimited-approval').addEventListener('click', () => run('approval'));
el('build-proof-draft').addEventListener('click', () => {
  buildProofDraft().catch(error => {
    writeJson('proof-output', {error: String(error.message || error)});
  });
});

writeJson('result-output', {
  status: 'ready',
  origin: window.location.origin,
  boundary: 'Only allow verdicts reach window.ethereum.request.'
});
writeJson('provider-log', forwardedCalls);
