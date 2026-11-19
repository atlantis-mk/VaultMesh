// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { VaultMeshApi } from '../../../shared/api';
import {
  AgentPinSettingsAdapter,
  BrowserPinSettingsAdapter,
  DesktopPinSettingsAdapter,
  PinSettingsDomainFactory,
} from './pin-settings-adapter';

describe('PinSettingsDomainFactory & PinSettingsDomainAdapter variants', () => {
  const desktopPinStatus = { enabled: true, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 };
  const browserPinStatus = { enabled: false, locked: false, failureLimit: 5, failedAttempts: 0, remainingAttempts: 5 };
  const agentPinStatus = { enabled: true, locked: true, failureLimit: 3, failedAttempts: 3, remainingAttempts: 0 };

  let apiMock: {
    vault: { pinStatus: ReturnType<typeof vi.fn>; enablePin: ReturnType<typeof vi.fn>; disablePin: ReturnType<typeof vi.fn> };
    browser: { pinStatus: ReturnType<typeof vi.fn>; enablePin: ReturnType<typeof vi.fn>; disablePin: ReturnType<typeof vi.fn> };
    agent: { pinStatus: ReturnType<typeof vi.fn>; enablePin: ReturnType<typeof vi.fn>; disablePin: ReturnType<typeof vi.fn> };
  };

  beforeEach(() => {
    apiMock = {
      vault: {
        pinStatus: vi.fn().mockResolvedValue(desktopPinStatus),
        enablePin: vi.fn().mockResolvedValue(desktopPinStatus),
        disablePin: vi.fn().mockResolvedValue({ ...desktopPinStatus, enabled: false }),
      },
      browser: {
        pinStatus: vi.fn().mockResolvedValue(browserPinStatus),
        enablePin: vi.fn().mockResolvedValue({ ...browserPinStatus, enabled: true }),
        disablePin: vi.fn().mockResolvedValue(browserPinStatus),
      },
      agent: {
        pinStatus: vi.fn().mockResolvedValue(agentPinStatus),
        enablePin: vi.fn().mockResolvedValue({ ...agentPinStatus, locked: false, failedAttempts: 0, remainingAttempts: 3 }),
        disablePin: vi.fn().mockResolvedValue({ ...agentPinStatus, enabled: false, locked: false }),
      },
    };
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: apiMock as unknown as VaultMeshApi,
    });
  });

  it('returns all three domain adapters with distinct metadata and routes calls to isolated APIs', async () => {
    const all = PinSettingsDomainFactory.all();
    expect(all.map((adapter) => adapter.domain)).toEqual(['desktop', 'browser', 'agent']);
    expect(new Set(all.map((adapter) => adapter.idPrefix)).size).toBe(3);

    const desktop = PinSettingsDomainFactory.createFor('desktop');
    const browser = PinSettingsDomainFactory.createFor('browser');
    const agent = PinSettingsDomainFactory.createFor('agent');

    expect(desktop).toBeInstanceOf(DesktopPinSettingsAdapter);
    expect(browser).toBeInstanceOf(BrowserPinSettingsAdapter);
    expect(agent).toBeInstanceOf(AgentPinSettingsAdapter);

    expect(desktop.enableSuccessMessage).toContain('所有端已锁定，请重新解锁。');
    expect(desktop.updateSuccessMessage).toContain('所有端已锁定，请重新解锁。');
    expect(desktop.disableSuccessMessage).toContain('所有端已锁定，请重新解锁。');
    expect(browser.enableSuccessMessage).toContain('浏览器插件已锁定。');
    expect(browser.updateSuccessMessage).toContain('浏览器插件已锁定。');
    expect(browser.disableSuccessMessage).toContain('浏览器插件已锁定。');
    expect(agent.enableSuccessMessage).toContain('Agent 已锁定。');
    expect(agent.updateSuccessMessage).toContain('Agent 已锁定。');
    expect(agent.disableSuccessMessage).toContain('Agent 已锁定。');

    await expect(desktop.getStatus()).resolves.toEqual(desktopPinStatus);
    await desktop.enable({ pin: '111111', failureLimit: 5 });
    await desktop.disable();
    expect(apiMock.vault.pinStatus).toHaveBeenCalledOnce();
    expect(apiMock.vault.enablePin).toHaveBeenCalledWith({ pin: '111111', failureLimit: 5 });
    expect(apiMock.vault.disablePin).toHaveBeenCalledOnce();

    await expect(browser.getStatus()).resolves.toEqual(browserPinStatus);
    await browser.enable({ pin: '222222', failureLimit: 7 });
    await browser.disable();
    expect(apiMock.browser.pinStatus).toHaveBeenCalledOnce();
    expect(apiMock.browser.enablePin).toHaveBeenCalledWith({ pin: '222222', failureLimit: 7 });
    expect(apiMock.browser.disablePin).toHaveBeenCalledOnce();

    await expect(agent.getStatus()).resolves.toEqual(agentPinStatus);
    await agent.enable({ pin: '333333', failureLimit: 3 });
    await agent.disable();
    expect(apiMock.agent.pinStatus).toHaveBeenCalledOnce();
    expect(apiMock.agent.enablePin).toHaveBeenCalledWith({ pin: '333333', failureLimit: 3 });
    expect(apiMock.agent.disablePin).toHaveBeenCalledOnce();
  });
});
