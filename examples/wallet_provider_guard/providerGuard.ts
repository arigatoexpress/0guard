export type WalletProviderGuardDecision = "allow" | "review" | "deny";

export type Eip1193Request = {
  method: string;
  params?: unknown[] | Record<string, unknown>;
};

export type Eip1193Provider = {
  request<T = unknown>(request: Eip1193Request): Promise<T>;
};

export type WalletProviderGuardConfig = {
  baseUrl: string;
  origin?: string;
  sourceProject?: string;
  surface?: string;
  onVerdict?: (verdict: WalletProviderGuardResult) => void;
};

export type WalletProviderGuardResult = {
  schema: "0guard.wallet_provider_guard.v1";
  decision: WalletProviderGuardDecision;
  providerMethod: string;
  enforcement: {
    action: string;
    providerCallAllowed: boolean;
    walletPromptBlocked: boolean;
    message: string;
  };
  receipt?: {
    hash?: string;
    algorithm?: string;
  };
  request?: {
    method: string;
    chain: string;
    targetRedacted: string;
    selector: string;
    valueEth: number;
    paramCount: number;
  };
  preflight?: {
    recommendedNextStep?: string;
  };
};

export class WalletGuardBlockedError extends Error {
  readonly verdict: WalletProviderGuardResult;

  constructor(verdict: WalletProviderGuardResult) {
    super(
      `0guard blocked ${verdict.providerMethod}: ${verdict.decision} ${
        verdict.receipt?.hash ?? ""
      }`,
    );
    this.name = "WalletGuardBlockedError";
    this.verdict = verdict;
  }
}

export async function walletProviderGuard(
  request: Eip1193Request,
  config: WalletProviderGuardConfig,
): Promise<WalletProviderGuardResult> {
  const response = await fetch(`${config.baseUrl.replace(/\/$/, "")}/api/wallet/provider-guard`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      method: request.method,
      params: request.params ?? [],
      origin: config.origin,
      sourceProject: config.sourceProject ?? "browser_dapp",
      surface: config.surface ?? "metamask_wallet",
    }),
  });
  if (!response.ok) {
    throw new Error(`0guard wallet-provider guard failed with HTTP ${response.status}`);
  }
  return (await response.json()) as WalletProviderGuardResult;
}

export async function guardedWalletRequest<T = unknown>(
  provider: Eip1193Provider,
  request: Eip1193Request,
  config: WalletProviderGuardConfig,
): Promise<T> {
  const verdict = await walletProviderGuard(request, config);
  config.onVerdict?.(verdict);
  if (!verdict.enforcement.providerCallAllowed) {
    throw new WalletGuardBlockedError(verdict);
  }
  return provider.request<T>(request);
}

export function create0guardProvider(
  provider: Eip1193Provider,
  config: WalletProviderGuardConfig,
): Eip1193Provider {
  return {
    request<T = unknown>(request: Eip1193Request): Promise<T> {
      return guardedWalletRequest<T>(provider, request, config);
    },
  };
}
