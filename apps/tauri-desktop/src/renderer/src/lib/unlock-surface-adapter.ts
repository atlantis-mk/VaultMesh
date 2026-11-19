export type UnlockSurfaceKind = 'desktop' | 'browser-session' | 'browser-reprompt' | 'agent';

export type BrowserUnlockSource = 'popup' | 'autofill' | 'passkey';

export interface AgentUnlockRequest {
  kind: 'agent';
  unlockRef: string;
  clientId: string;
  clientKey: string;
  createdAt: number;
  expiresAt: number;
}

export interface BrowserUnlockRequest {
  kind: 'browser-session' | 'browser-autofill';
  source?: BrowserUnlockSource;
  unlockRef: string;
  origin: string;
  itemTitle: string;
  itemKind: 'login' | 'card' | 'identity' | 'secret' | 'ssh' | string;
  masterPasswordReprompt: boolean;
  createdAt: number;
  expiresAt: number;
}

export type UnlockWindowRequest =
  | { kind: 'desktop' }
  | AgentUnlockRequest
  | BrowserUnlockRequest;

export interface UnlockSurfaceDescriptionContext {
  pinPreferred: boolean;
  pinLocked: boolean;
  pinRemainingAttempts?: number;
  biometricEnabled: boolean;
  request?: UnlockWindowRequest | null;
  unlockScope?: 'connection' | 'client';
}

export interface UnlockSurfaceUiAdapter {
  readonly kind: UnlockSurfaceKind;
  readonly title: string;
  readonly pinLabel: string;
  readonly forceMasterPassword: boolean;
  readonly showAgentScopeSwitch: boolean;
  readonly showCancelAction: boolean;
  readonly showSetupWhenVaultMissing: boolean;
  readonly hasCountdown: boolean;
  readonly countdownAriaLabel: string;
  readonly usesErrorBanner: boolean;
  readonly centerPinLabel: boolean;
  readonly vaultMissingDescription: string;
  readonly formId: string;
  readonly pinInputId: string;
  readonly passwordInputId: string;
  pinSwitchLabel(pinPreferred: boolean, pinLocked: boolean): string;
  submitLabel(busy: boolean): string;
  buildDescription(ctx: UnlockSurfaceDescriptionContext): string;
  buildTouchIdHint(pinPreferred: boolean): string;
}

function browserRequestMeta(request?: UnlockWindowRequest | null): BrowserUnlockRequest | null {
  if (!request) return null;
  return request.kind === 'browser-session' || request.kind === 'browser-autofill'
    ? request
    : null;
}

function formatBrowserSource(request?: UnlockWindowRequest | null): string {
  const browser = browserRequestMeta(request);
  if (!browser) return '';
  return [browser.origin.trim(), browser.itemTitle.trim()].filter(Boolean).join(' · ');
}

export class DesktopUnlockSurfaceAdapter implements UnlockSurfaceUiAdapter {
  readonly kind: UnlockSurfaceKind = 'desktop';
  readonly title = '解锁 VaultMesh';
  readonly pinLabel = '6 位 PIN';
  readonly forceMasterPassword = false;
  readonly showAgentScopeSwitch = false;
  readonly showCancelAction = false;
  readonly showSetupWhenVaultMissing = true;
  readonly hasCountdown = false;
  readonly countdownAriaLabel = '';
  readonly usesErrorBanner = true;
  readonly centerPinLabel = false;
  readonly vaultMissingDescription = '尚未在当前位置找到本地保险库，可先创建一个新保险库。';
  readonly formId = 'unlock-vault';
  readonly pinInputId = 'unlock-pin';
  readonly passwordInputId = 'unlock-password';

  pinSwitchLabel(pinPreferred: boolean, pinLocked: boolean): string {
    if (pinPreferred) return '改用主密码';
    return pinLocked ? 'PIN 已锁定' : '改用 PIN';
  }

  submitLabel(busy: boolean): string {
    return busy ? '正在解锁…' : '使用主密码解锁';
  }

  buildDescription(ctx: UnlockSurfaceDescriptionContext): string {
    if (ctx.pinPreferred) {
      return `输入 6 位 PIN 后自动解锁，还可尝试 ${ctx.pinRemainingAttempts ?? 0} 次。`;
    }
    if (ctx.pinLocked) {
      return 'PIN 已锁定，请先使用主密码解锁以恢复尝试次数。';
    }
    return ctx.biometricEnabled
      ? '使用 Touch ID 或主密码在本地解锁保险库。'
      : '使用主密码在本地解锁保险库。';
  }

  buildTouchIdHint(pinPreferred: boolean): string {
    return pinPreferred
      ? '触碰 Touch ID 解锁，或输入下方 PIN'
      : '触碰 Touch ID 解锁，或输入下方主密码';
  }
}

export class BrowserSessionUnlockSurfaceAdapter implements UnlockSurfaceUiAdapter {
  readonly kind: UnlockSurfaceKind = 'browser-session';
  readonly title = '解锁 VaultMesh 浏览器插件';
  readonly pinLabel = '浏览器插件 PIN';
  readonly forceMasterPassword = false;
  readonly showAgentScopeSwitch = false;
  readonly showCancelAction = true;
  readonly showSetupWhenVaultMissing = false;
  readonly hasCountdown = true;
  readonly countdownAriaLabel = '本次浏览器插件解锁剩余时间';
  readonly usesErrorBanner = false;
  readonly centerPinLabel = true;
  readonly vaultMissingDescription = '请先在 VaultMesh 主窗口创建保险库。';
  readonly formId = 'agent-unlock-form';
  readonly pinInputId = 'agent-unlock-pin';
  readonly passwordInputId = 'agent-unlock-password';

  pinSwitchLabel(pinPreferred: boolean, pinLocked: boolean): string {
    if (pinPreferred) return '改用主密码';
    return pinLocked ? 'PIN 已锁定' : '改用浏览器插件 PIN';
  }

  submitLabel(busy: boolean): string {
    return busy ? '正在解锁…' : '解锁浏览器插件';
  }

  buildDescription(ctx: UnlockSurfaceDescriptionContext): string {
    const sourceText = formatBrowserSource(ctx.request);
    const base = sourceText
      ? `来自 ${sourceText}`
      : '在桌面端完成解锁以启用浏览器插件';
    if (ctx.pinLocked) {
      return `${base} · PIN 已锁定，请使用主密码`;
    }
    if (ctx.pinPreferred) {
      return `${base} · 输入 6 位 PIN（还可尝试 ${ctx.pinRemainingAttempts ?? 0} 次）`;
    }
    return base;
  }

  buildTouchIdHint(pinPreferred: boolean): string {
    return pinPreferred
      ? '触碰 Touch ID 解锁浏览器插件，或输入下方 PIN'
      : '触碰 Touch ID 解锁浏览器插件，或输入下方主密码';
  }
}

export class BrowserRepromptUnlockSurfaceAdapter implements UnlockSurfaceUiAdapter {
  readonly kind: UnlockSurfaceKind = 'browser-reprompt';
  readonly title = '解锁 VaultMesh 浏览器插件';
  readonly pinLabel = '浏览器插件 PIN';
  readonly forceMasterPassword = true;
  readonly showAgentScopeSwitch = false;
  readonly showCancelAction = true;
  readonly showSetupWhenVaultMissing = false;
  readonly hasCountdown = true;
  readonly countdownAriaLabel = '本次主密码确认剩余时间';
  readonly usesErrorBanner = false;
  readonly centerPinLabel = true;
  readonly vaultMissingDescription = '请先在 VaultMesh 主窗口创建保险库。';
  readonly formId = 'agent-unlock-form';
  readonly pinInputId = 'agent-unlock-pin';
  readonly passwordInputId = 'agent-unlock-password';

  pinSwitchLabel(): string {
    return '';
  }

  submitLabel(busy: boolean): string {
    return busy ? '正在解锁…' : '解锁并填充';
  }

  buildDescription(ctx: UnlockSurfaceDescriptionContext): string {
    const sourceText = formatBrowserSource(ctx.request);
    return sourceText
      ? `来自 ${sourceText} · 此条目受主密码保护，需要输入主密码确认填充。`
      : '此条目受主密码保护，需要输入主密码确认填充。';
  }

  buildTouchIdHint(): string {
    return '';
  }
}

export class AgentUnlockSurfaceAdapter implements UnlockSurfaceUiAdapter {
  readonly kind: UnlockSurfaceKind = 'agent';
  readonly title = '解锁 VaultMesh Agent工具';
  readonly pinLabel = 'Agent 专用 PIN';
  readonly forceMasterPassword = false;
  readonly showAgentScopeSwitch = true;
  readonly showCancelAction = true;
  readonly showSetupWhenVaultMissing = false;
  readonly hasCountdown = true;
  readonly countdownAriaLabel = '本次 MCP 解锁剩余时间';
  readonly usesErrorBanner = false;
  readonly centerPinLabel = true;
  readonly vaultMissingDescription = '请先在 VaultMesh 主窗口创建保险库。';
  readonly formId = 'agent-unlock-form';
  readonly pinInputId = 'agent-unlock-pin';
  readonly passwordInputId = 'agent-unlock-password';

  pinSwitchLabel(pinPreferred: boolean, pinLocked: boolean): string {
    if (pinPreferred) return '改用主密码';
    return pinLocked ? 'PIN 已锁定' : '改用 Agent PIN';
  }

  submitLabel(busy: boolean): string {
    return busy ? '正在解锁…' : '解锁 MCP';
  }

  buildDescription(ctx: UnlockSurfaceDescriptionContext): string {
    const req = ctx.request && ctx.request.kind === 'agent' ? ctx.request : null;
    const clientPrefix = req?.clientKey ? `客户端 ${req.clientKey} · ` : '';
    if (ctx.pinLocked) {
      return `${clientPrefix}Agent PIN 已锁定，请使用主密码。`;
    }
    return ctx.unlockScope === 'client'
      ? `${clientPrefix}同一已配对客户端的并行 MCP 连接共享此次解锁，不会解锁桌面或插件。`
      : `${clientPrefix}仅授权当前 MCP 连接，不会解锁桌面、插件或其他 Agent。`;
  }

  buildTouchIdHint(pinPreferred: boolean): string {
    return pinPreferred
      ? '触碰 Touch ID 解锁 Agent 工具，或输入下方 PIN'
      : '触碰 Touch ID 解锁 Agent 工具，或输入下方主密码';
  }
}

const DESKTOP_ADAPTER = new DesktopUnlockSurfaceAdapter();
const BROWSER_SESSION_ADAPTER = new BrowserSessionUnlockSurfaceAdapter();
const BROWSER_REPROMPT_ADAPTER = new BrowserRepromptUnlockSurfaceAdapter();
const AGENT_ADAPTER = new AgentUnlockSurfaceAdapter();

const ADAPTERS: Record<UnlockSurfaceKind, UnlockSurfaceUiAdapter> = {
  desktop: DESKTOP_ADAPTER,
  'browser-session': BROWSER_SESSION_ADAPTER,
  'browser-reprompt': BROWSER_REPROMPT_ADAPTER,
  agent: AGENT_ADAPTER,
};

export const UnlockSurfaceUiFactory = {
  all(): readonly UnlockSurfaceUiAdapter[] {
    return [DESKTOP_ADAPTER, BROWSER_SESSION_ADAPTER, BROWSER_REPROMPT_ADAPTER, AGENT_ADAPTER];
  },

  createFor(kind: UnlockSurfaceKind): UnlockSurfaceUiAdapter {
    return ADAPTERS[kind];
  },

  fromWindowRequest(request?: UnlockWindowRequest | null): UnlockSurfaceUiAdapter {
    if (!request || request.kind === 'desktop') {
      return DESKTOP_ADAPTER;
    }
    if (request.kind === 'agent') {
      return AGENT_ADAPTER;
    }
    return request.masterPasswordReprompt
      ? BROWSER_REPROMPT_ADAPTER
      : BROWSER_SESSION_ADAPTER;
  },
};
