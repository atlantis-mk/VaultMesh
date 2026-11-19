import type { PinSetup, PinStatus } from '../../../shared/contracts';

export type PinSettingsDomain = 'desktop' | 'browser' | 'agent';

export interface PinSettingsDomainAdapter {
  readonly domain: PinSettingsDomain;
  readonly label: string;
  readonly title: string;
  readonly description: string;
  readonly lockedDescription: string;
  readonly idPrefix: string;
  readonly enableSuccessMessage: string;
  readonly updateSuccessMessage: string;
  readonly disableSuccessMessage: string;
  readonly disableButtonLabel: string;
  getStatus(): Promise<PinStatus>;
  enable(input: PinSetup): Promise<PinStatus>;
  disable(): Promise<PinStatus>;
}

export class DesktopPinSettingsAdapter implements PinSettingsDomainAdapter {
  readonly domain: PinSettingsDomain = 'desktop';
  readonly label = '桌面端';
  readonly title = '桌面端 PIN';
  readonly description = '仅用于此台设备的桌面端主窗口锁屏解锁，与浏览器插件和 Agent PIN 完全独立。';
  readonly lockedDescription = '下次使用主密码成功解锁桌面端后，会恢复 PIN 尝试次数。';
  readonly idPrefix = 'desktop-pin';
  readonly enableSuccessMessage = '桌面端 PIN 解锁已启用，所有端已锁定，请重新解锁。';
  readonly updateSuccessMessage = '桌面端 PIN 已更新，所有端已锁定，请重新解锁。';
  readonly disableSuccessMessage = '桌面端 PIN 解锁已关闭，所有端已锁定，请重新解锁。';
  readonly disableButtonLabel = '关闭桌面端 PIN';

  getStatus(): Promise<PinStatus> {
    return window.vaultMesh.vault.pinStatus();
  }

  enable(input: PinSetup): Promise<PinStatus> {
    return window.vaultMesh.vault.enablePin(input);
  }

  disable(): Promise<PinStatus> {
    return window.vaultMesh.vault.disablePin();
  }
}

export class BrowserPinSettingsAdapter implements PinSettingsDomainAdapter {
  readonly domain: PinSettingsDomain = 'browser';
  readonly label = '浏览器插件';
  readonly title = '浏览器插件 PIN';
  readonly description = '仅用于浏览器插件会话解锁，与桌面端和 Agent PIN 相互独立；插件设置页也会实时同步此状态。';
  readonly lockedDescription = '请在浏览器插件解锁时改用主密码，或在此重新设置浏览器插件 PIN。';
  readonly idPrefix = 'browser-pin';
  readonly enableSuccessMessage = '浏览器插件 PIN 解锁已启用，浏览器插件已锁定。';
  readonly updateSuccessMessage = '浏览器插件 PIN 已更新，浏览器插件已锁定。';
  readonly disableSuccessMessage = '浏览器插件 PIN 解锁已关闭，浏览器插件已锁定。';
  readonly disableButtonLabel = '关闭浏览器插件 PIN';

  getStatus(): Promise<PinStatus> {
    return window.vaultMesh.browser.pinStatus();
  }

  enable(input: PinSetup): Promise<PinStatus> {
    return window.vaultMesh.browser.enablePin(input);
  }

  disable(): Promise<PinStatus> {
    return window.vaultMesh.browser.disablePin();
  }
}

export class AgentPinSettingsAdapter implements PinSettingsDomainAdapter {
  readonly domain: PinSettingsDomain = 'agent';
  readonly label = 'Agent 工具';
  readonly title = 'Agent PIN';
  readonly description = '仅用于本地 MCP 工具解锁，与桌面端和浏览器插件 PIN 相互独立。';
  readonly lockedDescription = '请在 Agent 解锁时改用主密码，或在此重新设置 Agent PIN。';
  readonly idPrefix = 'agent-pin';
  readonly enableSuccessMessage = 'Agent PIN 快速解锁已启用，Agent 已锁定。';
  readonly updateSuccessMessage = 'Agent PIN 已更新，Agent 已锁定。';
  readonly disableSuccessMessage = 'Agent PIN 快速解锁已关闭，Agent 已锁定。';
  readonly disableButtonLabel = '关闭 Agent PIN';

  getStatus(): Promise<PinStatus> {
    return window.vaultMesh.agent.pinStatus();
  }

  enable(input: PinSetup): Promise<PinStatus> {
    return window.vaultMesh.agent.enablePin(input);
  }

  disable(): Promise<PinStatus> {
    return window.vaultMesh.agent.disablePin();
  }
}

const DESKTOP_PIN_ADAPTER = new DesktopPinSettingsAdapter();
const BROWSER_PIN_ADAPTER = new BrowserPinSettingsAdapter();
const AGENT_PIN_ADAPTER = new AgentPinSettingsAdapter();

const ADAPTERS: Record<PinSettingsDomain, PinSettingsDomainAdapter> = {
  desktop: DESKTOP_PIN_ADAPTER,
  browser: BROWSER_PIN_ADAPTER,
  agent: AGENT_PIN_ADAPTER,
};

export const PinSettingsDomainFactory = {
  all(): readonly PinSettingsDomainAdapter[] {
    return [DESKTOP_PIN_ADAPTER, BROWSER_PIN_ADAPTER, AGENT_PIN_ADAPTER];
  },

  createFor(domain: PinSettingsDomain): PinSettingsDomainAdapter {
    return ADAPTERS[domain];
  },
};
