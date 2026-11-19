// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { invoke, listen } = vi.hoisted(() => ({
  invoke: vi.fn(),
  listen: vi.fn(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke }));
vi.mock('@tauri-apps/api/event', () => ({ listen }));

import type { DesktopAuthenticationEvent, VaultMeshApi } from '../../../shared/api';
import {
  MainWindowAuthBridgeAdapter,
  PlatformAuthBridgeFactory,
  StandaloneWindowAuthBridgeAdapter,
} from './platform-auth-bridge';

describe('PlatformAuthBridgeFactory & PlatformAuthBridgeAdapter variants', () => {
  beforeEach(() => {
    invoke.mockReset();
    listen.mockReset();
  });

  it('creates MainWindowAuthBridgeAdapter and delegates via window.vaultMesh.desktop', async () => {
    const unlisten = vi.fn();
    const desktopMock = {
      authenticationStatus: vi.fn().mockResolvedValue({ supported: true, label: 'Touch ID' }),
      beginAuthentication: vi.fn().mockResolvedValue(undefined),
      layoutAuthentication: vi.fn().mockResolvedValue(undefined),
      cancelAuthentication: vi.fn().mockResolvedValue(undefined),
      onAuthentication: vi.fn().mockResolvedValue(unlisten),
      setCompactWindowMode: vi.fn().mockResolvedValue(undefined),
    };
    Object.defineProperty(window, 'vaultMesh', {
      configurable: true,
      value: { desktop: desktopMock } as unknown as VaultMeshApi,
    });

    const adapter = PlatformAuthBridgeFactory.createFor('main-window');
    expect(adapter).toBeInstanceOf(MainWindowAuthBridgeAdapter);
    expect(adapter.kind).toBe('main-window');
    expect(PlatformAuthBridgeFactory.createFor('main-window')).toBe(adapter);

    const bounds = { x: 10, y: 20, width: 64, height: 64 };
    const callback = vi.fn<(event: DesktopAuthenticationEvent) => void>();

    await expect(adapter.authenticationStatus()).resolves.toEqual({ supported: true, label: 'Touch ID' });
    await adapter.beginAuthentication('session-1', bounds);
    await adapter.layoutAuthentication('session-1', bounds);
    await adapter.cancelAuthentication('session-1');
    const off = await adapter.onAuthentication(callback);
    await adapter.setCompactWindowMode(true, 410);
    await adapter.setCompactWindowMode(false);

    expect(desktopMock.authenticationStatus).toHaveBeenCalledOnce();
    expect(desktopMock.beginAuthentication).toHaveBeenCalledWith('session-1', bounds);
    expect(desktopMock.layoutAuthentication).toHaveBeenCalledWith('session-1', bounds);
    expect(desktopMock.cancelAuthentication).toHaveBeenCalledWith('session-1');
    expect(desktopMock.onAuthentication).toHaveBeenCalledWith(callback);
    expect(off).toBe(unlisten);
    expect(desktopMock.setCompactWindowMode).toHaveBeenNthCalledWith(1, true, 410);
    expect(desktopMock.setCompactWindowMode).toHaveBeenNthCalledWith(2, false);
    expect(PlatformAuthBridgeFactory.create()).toBeInstanceOf(MainWindowAuthBridgeAdapter);
  });

  it('creates StandaloneWindowAuthBridgeAdapter and delegates via Tauri core invoke/event', async () => {
    const unlisten = vi.fn();
    let capturedListener: ((event: { payload: DesktopAuthenticationEvent }) => void) | undefined;
    invoke.mockResolvedValue({ supported: true, label: 'Touch ID' });
    listen.mockImplementation(async (_event, cb) => {
      capturedListener = cb as (event: { payload: DesktopAuthenticationEvent }) => void;
      return unlisten;
    });

    const adapter = PlatformAuthBridgeFactory.createFor('standalone-window');
    expect(adapter).toBeInstanceOf(StandaloneWindowAuthBridgeAdapter);
    expect(adapter.kind).toBe('standalone-window');
    expect(PlatformAuthBridgeFactory.createFor('standalone-window')).toBe(adapter);

    const bounds = { x: 12, y: 24, width: 64, height: 64 };
    const callback = vi.fn();

    await expect(adapter.authenticationStatus()).resolves.toEqual({ supported: true, label: 'Touch ID' });
    await adapter.beginAuthentication('session-2', bounds);
    await adapter.layoutAuthentication('session-2', bounds);
    await adapter.cancelAuthentication('session-2');
    const off = await adapter.onAuthentication(callback);
    await adapter.setCompactWindowMode(true, 440);
    await adapter.setCompactWindowMode(false);

    expect(invoke).toHaveBeenCalledWith('desktop_authentication_status');
    expect(invoke).toHaveBeenCalledWith('desktop_authentication_begin', { sessionId: 'session-2', bounds });
    expect(invoke).toHaveBeenCalledWith('desktop_authentication_layout', { sessionId: 'session-2', bounds });
    expect(invoke).toHaveBeenCalledWith('desktop_authentication_cancel', { sessionId: 'session-2' });
    expect(invoke).toHaveBeenCalledWith('desktop_window_set_compact_mode', { compact: true, contentHeight: 440 });
    expect(invoke).toHaveBeenCalledWith('desktop_window_set_compact_mode', { compact: false, contentHeight: null });
    expect(listen).toHaveBeenCalledWith('desktop-authentication', expect.any(Function));

    capturedListener?.({ payload: { sessionId: 'session-2', status: 'listening' } });
    expect(callback).toHaveBeenCalledWith({ sessionId: 'session-2', status: 'listening' });
    expect(off).toBe(unlisten);
  });
});
