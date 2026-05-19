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
    let verdict = null;
    let forwarded = false;
    try{
      providerResult = await guardedProviderRequest(scenario.request);
      forwarded = true;
    }catch(error){
      verdict = error.verdict || null;
      if(!verdict){
        throw error;
      }
    }
    writeJson('result-output', {
      scenario: scenario.label,
      forwardedToProvider: forwarded,
      providerResult,
      verdict: publicVerdict(verdict),
      providerCallCount: forwardedCalls.length
    });
  }catch(error){
    setDecision('deny');
    writeJson('result-output', {error: String(error.message || error)});
  }finally{
    writeJson('provider-log', forwardedCalls);
    setBusy(false);
  }
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

function setBusy(isBusy) {
  for(const button of document.querySelectorAll('button')){
    button.disabled = isBusy;
  }
}

el('run-read-chain').addEventListener('click', () => run('read'));
el('run-switch-chain').addEventListener('click', () => run('switch'));
el('run-unlimited-approval').addEventListener('click', () => run('approval'));

writeJson('result-output', {
  status: 'ready',
  origin: window.location.origin,
  boundary: 'Only allow verdicts reach window.ethereum.request.'
});
writeJson('provider-log', forwardedCalls);
