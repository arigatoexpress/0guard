import { WalletGuardBlockedError, create0guardProvider } from './wallet-provider-guard-client.js';

const requests = {
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

const providerCalls = [];
const fakeProvider = {
  async request(request) {
    providerCalls.push({
      method: request.method,
      at: new Date().toISOString()
    });
    if(request.method === 'eth_chainId'){
      return '0x1';
    }
    return {forwarded: true, method: request.method};
  }
};

let latestVerdict = null;
const guardedProvider = create0guardProvider(fakeProvider, {
  origin: window.location.origin,
  sourceProject: 'wallet_provider_demo',
  surface: 'metamask_wallet',
  onVerdict: (verdict) => {
    latestVerdict = verdict;
    renderVerdict(verdict);
  }
});

function el(id) {
  return document.getElementById(id);
}

function writeJson(id, payload) {
  el(id).textContent = JSON.stringify(payload, null, 2);
}

function setPill(decision) {
  const pill = el('provider-demo-decision');
  pill.classList.remove('allow', 'review', 'deny');
  pill.classList.add(decision || 'review');
  pill.textContent = decision || 'waiting';
}

function renderVerdict(verdict) {
  setPill(verdict.decision);
  el('provider-demo-action').textContent = verdict.enforcement.action;
  el('provider-demo-forwarded').textContent = verdict.enforcement.providerCallAllowed ? 'yes' : 'no';
}

function renderProviderLog() {
  el('provider-demo-call-count').textContent = String(providerCalls.length);
  writeJson('provider-demo-log', providerCalls);
}

async function runScenario(kind) {
  const scenario = requests[kind];
  if(!scenario){
    throw new Error(`Unknown scenario: ${kind}`);
  }
  setBusy(true);
  try{
    let providerResult = null;
    let verdict = null;
    let forwarded = false;
    try{
      providerResult = await guardedProvider.request(scenario.request);
      forwarded = true;
    }catch(error){
      if(error instanceof WalletGuardBlockedError){
        verdict = error.verdict;
      }else{
        throw error;
      }
    }
    if(!verdict){
      verdict = latestVerdict;
    }
    const payload = {
      scenario: scenario.label,
      forwardedToProvider: forwarded,
      providerResult,
      providerCallCount: providerCalls.length,
      verdict: verdict ? publicVerdict(verdict) : null
    };
    writeJson('provider-demo-output', payload);
    renderProviderLog();
  }catch(error){
    setPill('deny');
    writeJson('provider-demo-output', {error: String(error.message || error)});
  }finally{
    setBusy(false);
  }
}

function publicVerdict(verdict) {
  return {
    schema: verdict.schema,
    decision: verdict.decision,
    providerMethod: verdict.providerMethod,
    enforcement: verdict.enforcement,
    request: verdict.request,
    receipt: verdict.receipt,
    safety: verdict.safety
  };
}

function setBusy(isBusy) {
  for(const button of document.querySelectorAll('[data-provider-scenario]')){
    button.disabled = isBusy;
  }
}

for(const button of document.querySelectorAll('[data-provider-scenario]')){
  button.addEventListener('click', () => runScenario(button.dataset.providerScenario));
}

renderProviderLog();
writeJson('provider-demo-output', {
  status: 'ready',
  providerCalls: 0,
  boundary: 'Only allow verdicts reach the provider.'
});
