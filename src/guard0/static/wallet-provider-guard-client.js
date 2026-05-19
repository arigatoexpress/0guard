export class WalletGuardBlockedError extends Error {
  constructor(verdict) {
    super(`0guard blocked ${verdict.providerMethod}: ${verdict.decision} ${verdict.receipt?.hash || ''}`.trim());
    this.name = 'WalletGuardBlockedError';
    this.verdict = verdict;
  }
}

export async function walletProviderGuard(request, config = {}) {
  const baseUrl = (config.baseUrl || '').replace(/\/$/, '');
  const fetcher = config.fetch || globalThis.fetch.bind(globalThis);
  const response = await fetcher(`${baseUrl}/api/wallet/provider-guard`, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      method: request.method,
      params: request.params || [],
      origin: config.origin || globalThis.location?.origin || '',
      sourceProject: config.sourceProject || 'browser_dapp',
      surface: config.surface || 'metamask_wallet'
    })
  });
  if(!response.ok){
    throw new Error(`0guard wallet-provider guard failed with HTTP ${response.status}`);
  }
  return await response.json();
}

export async function guardedWalletRequest(provider, request, config = {}) {
  const verdict = await walletProviderGuard(request, config);
  config.onVerdict?.(verdict);
  if(!verdict.enforcement.providerCallAllowed){
    throw new WalletGuardBlockedError(verdict);
  }
  return await provider.request(request);
}

export function create0guardProvider(provider, config = {}) {
  return {
    request(request) {
      return guardedWalletRequest(provider, request, config);
    }
  };
}
