import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

import type { DesktopAuthenticationBounds, DesktopAuthenticationEvent } from '../../../shared/api';

export type PlatformAuthBridgeKind = 'main-window' | 'standalone-window';

export interface PlatformAuthBridgeAdapter {
  readonly kind: PlatformAuthBridgeKind;
  authenticationStatus(): Promise<{ supported: boolean; label: string }>;
  beginAuthentication(sessionId: string, bounds: DesktopAuthenticationBounds): Promise<void>;
  layoutAuthentication(sessionId: string, bounds: DesktopAuthenticationBounds): Promise<void>;
  cancelAuthentication(sessionId: string): Promise<void>;
  onAuthentication(callback: (event: DesktopAuthenticationEvent) => void): Promise<() => void>;
  setCompactWindowMode(compact: boolean, contentHeight?: number): Promise<void>;
}

export class MainWindowAuthBridgeAdapter implements PlatformAuthBridgeAdapter {
  readonly kind: PlatformAuthBridgeKind = 'main-window';

  authenticationStatus(): Promise<{ supported: boolean; label: string }> {
    return window.vaultMesh.desktop.authenticationStatus();
  }

  beginAuthentication(sessionId: string, bounds: DesktopAuthenticationBounds): Promise<void> {
    return window.vaultMesh.desktop.beginAuthentication(sessionId, bounds);
  }

  layoutAuthentication(sessionId: string, bounds: DesktopAuthenticationBounds): Promise<void> {
    return window.vaultMesh.desktop.layoutAuthentication(sessionId, bounds);
  }

  cancelAuthentication(sessionId: string): Promise<void> {
    return window.vaultMesh.desktop.cancelAuthentication(sessionId);
  }

  onAuthentication(callback: (event: DesktopAuthenticationEvent) => void): Promise<() => void> {
    return window.vaultMesh.desktop.onAuthentication(callback);
  }

  setCompactWindowMode(compact: boolean, contentHeight?: number): Promise<void> {
    const setCompact = window.vaultMesh?.desktop?.setCompactWindowMode;
    if (!setCompact) return Promise.resolve();
    return contentHeight === undefined ? setCompact(compact) : setCompact(compact, contentHeight);
  }
}

export class StandaloneWindowAuthBridgeAdapter implements PlatformAuthBridgeAdapter {
  readonly kind: PlatformAuthBridgeKind = 'standalone-window';

  authenticationStatus(): Promise<{ supported: boolean; label: string }> {
    return invoke<{ supported: boolean; label: string }>('desktop_authentication_status');
  }

  beginAuthentication(sessionId: string, bounds: DesktopAuthenticationBounds): Promise<void> {
    return invoke('desktop_authentication_begin', { sessionId, bounds });
  }

  layoutAuthentication(sessionId: string, bounds: DesktopAuthenticationBounds): Promise<void> {
    return invoke('desktop_authentication_layout', { sessionId, bounds });
  }

  cancelAuthentication(sessionId: string): Promise<void> {
    return invoke('desktop_authentication_cancel', { sessionId });
  }

  onAuthentication(callback: (event: DesktopAuthenticationEvent) => void): Promise<() => void> {
    return listen<DesktopAuthenticationEvent>('desktop-authentication', ({ payload }) => callback(payload));
  }

  setCompactWindowMode(compact: boolean, contentHeight?: number): Promise<void> {
    return invoke('desktop_window_set_compact_mode', { compact, contentHeight: contentHeight ?? null });
  }
}

const MAIN_WINDOW_ADAPTER = new MainWindowAuthBridgeAdapter();
const STANDALONE_WINDOW_ADAPTER = new StandaloneWindowAuthBridgeAdapter();

export const PlatformAuthBridgeFactory = {
  currentKind(): PlatformAuthBridgeKind {
    if (typeof window !== 'undefined') {
      const surface = new URLSearchParams(window.location.search).get('surface');
      if (surface === 'agent-unlock') return 'standalone-window';
      if (window.vaultMesh?.desktop) return 'main-window';
    }
    return 'standalone-window';
  },

  createFor(kind: PlatformAuthBridgeKind): PlatformAuthBridgeAdapter {
    return kind === 'main-window' ? MAIN_WINDOW_ADAPTER : STANDALONE_WINDOW_ADAPTER;
  },

  create(): PlatformAuthBridgeAdapter {
    return this.createFor(this.currentKind());
  },
};
