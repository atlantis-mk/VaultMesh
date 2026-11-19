import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { useEffect, useMemo, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';

import { UnlockCard } from './renderer/src/components/UnlockCard';
import { Spinner } from './renderer/src/components/ui/spinner';
import { PlatformAuthBridgeFactory } from './renderer/src/lib/platform-auth-bridge';
import {
  UnlockSurfaceUiFactory,
  type AgentUnlockRequest,
  type BrowserUnlockRequest,
} from './renderer/src/lib/unlock-surface-adapter';
import './renderer/src/styles/app.css';

const AGENT_UNLOCK_WAIT_MILLIS = 30_000;

type UnlockRequest = AgentUnlockRequest | BrowserUnlockRequest;

interface UnlockStatus {
  now?: number;
  request: UnlockRequest | null;
  access: {
    hasVault: boolean;
    clientUnlocked: boolean;
    settings: { unlockScope: 'connection' | 'client' };
  };
  pin: { enabled: boolean; locked: boolean; remainingAttempts: number };
  biometric: { available: boolean; enabled: boolean; kind: 'touchId' | null };
}

function message(reason: unknown): string {
  if (reason instanceof Error) return reason.message;
  if (typeof reason === 'string' && reason.length > 0) return reason;
  return '临时解锁失败。';
}

function resolveInitialRemainingMillis(status: UnlockStatus): number {
  const req = status.request;
  if (!req) return 0;
  if (typeof status.now === 'number' && Number.isFinite(status.now)) {
    return Math.max(0, Math.min(AGENT_UNLOCK_WAIT_MILLIS, req.expiresAt - status.now));
  }
  return AGENT_UNLOCK_WAIT_MILLIS;
}

export function AgentUnlockWindow() {
  const [status, setStatus] = useState<UnlockStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [expired, setExpired] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scopeBusy, setScopeBusy] = useState(false);
  const [deadline, setDeadline] = useState(0);
  const [remaining, setRemaining] = useState(AGENT_UNLOCK_WAIT_MILLIS);
  const statusRef = useRef<UnlockStatus | null>(null);
  const activeUnlockRef = useRef('');
  const lastExpiresAtRef = useRef(0);
  const expiredHandledRef = useRef('');

  const bridge = useMemo(() => PlatformAuthBridgeFactory.createFor('standalone-window'), []);
  const surface = useMemo(
    () => UnlockSurfaceUiFactory.fromWindowRequest(status?.request),
    [status?.request],
  );

  const applyStatus = (next: UnlockStatus): void => {
    statusRef.current = next;
    setStatus(next);
    const nextReq = next.request;
    if (!nextReq) {
      activeUnlockRef.current = '';
      lastExpiresAtRef.current = 0;
      setDeadline(0);
      return;
    }
    const nextRemaining = resolveInitialRemainingMillis(next);
    if (activeUnlockRef.current !== nextReq.unlockRef) {
      activeUnlockRef.current = nextReq.unlockRef;
      lastExpiresAtRef.current = nextReq.expiresAt;
      setExpired(false);
      setRemaining(nextRemaining);
      setDeadline(Date.now() + nextRemaining);
    } else if (nextReq.expiresAt > lastExpiresAtRef.current) {
      lastExpiresAtRef.current = nextReq.expiresAt;
      setRemaining(nextRemaining);
      setDeadline(Date.now() + nextRemaining);
    }
  };

  const refresh = async (): Promise<void> => {
    const next = await invoke<UnlockStatus>('agent_unlock_status');
    applyStatus(next);
  };

  const advanceOrHide = async (): Promise<void> => {
    const next = await invoke<UnlockStatus>('agent_unlock_status');
    if (next.request) {
      applyStatus(next);
    } else {
      applyStatus(next);
      await getCurrentWindow().hide();
    }
  };

  const expireCurrentRequest = async (): Promise<void> => {
    const unlockRef = statusRef.current?.request?.unlockRef;
    if (!unlockRef || expiredHandledRef.current === unlockRef) return;
    expiredHandledRef.current = unlockRef;
    setExpired(true);
    setDeadline(0);
    setRemaining(0);
    await invoke('agent_unlock_cancel').catch(() => undefined);
    const next = await invoke<UnlockStatus>('agent_unlock_status').catch(() => null);
    if (next?.request && next.request.unlockRef !== unlockRef) {
      setBusy(false);
      setError(null);
      applyStatus(next);
      return;
    }
    setBusy(false);
    await getCurrentWindow().hide();
  };

  useEffect(() => {
    void refresh().catch((reason) => setError(message(reason)));
    const unlisteners: Array<() => void> = [];
    let disposed = false;
    const register = (event: string, handler: () => void): void => {
      void listen(event, handler).then((unlisten) => {
        if (disposed) unlisten();
        else unlisteners.push(unlisten);
      });
    };
    register('agent-unlock-requested', () => {
      setError(null);
      void refresh().catch((reason) => setError(message(reason)));
    });
    register('agent-unlock-expired', () => {
      void expireCurrentRequest();
    });
    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    if (!deadline) return;
    let cancelled = false;
    const update = (): void => {
      if (cancelled) return;
      const next = Math.max(0, deadline - Date.now());
      setRemaining(next);
      if (next === 0) {
        window.clearInterval(timer);
        void expireCurrentRequest();
      }
    };
    const timer = window.setInterval(update, 200);
    update();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [deadline]);

  const submitCredential = async (
    command: 'agent_unlock_password' | 'agent_unlock_pin',
    input: Record<string, string>,
  ): Promise<void> => {
    if (busy) return;
    const attemptedRef = statusRef.current?.request?.unlockRef ?? '';
    setBusy(true);
    setError(null);
    try {
      await invoke(command, input);
      if (attemptedRef && expiredHandledRef.current === attemptedRef) return;
      setBusy(false);
      await advanceOrHide();
    } catch (reason) {
      if (attemptedRef && expiredHandledRef.current === attemptedRef) return;
      setError(message(reason));
      setBusy(false);
      await refresh().catch(() => undefined);
    }
  };

  const handleBiometricUnlocked = async (): Promise<void> => {
    const attemptedRef = statusRef.current?.request?.unlockRef ?? '';
    if (attemptedRef && expiredHandledRef.current === attemptedRef) return;
    setError(null);
    await advanceOrHide();
  };

  const cancel = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await invoke('agent_unlock_cancel');
      setBusy(false);
      setError(null);
      await advanceOrHide();
    } catch (reason) {
      setError(message(reason));
      setBusy(false);
    }
  };

  const setSharedUnlock = async (shared: boolean): Promise<void> => {
    if (scopeBusy) return;
    setScopeBusy(true);
    setError(null);
    try {
      const settings = await invoke<UnlockStatus['access']['settings']>('agent_unlock_set_scope', {
        scope: shared ? 'client' : 'connection',
      });
      setStatus((current) => {
        const updated = current ? {
          ...current,
          access: { ...current.access, settings },
        } : current;
        statusRef.current = updated;
        return updated;
      });
    } catch (reason) {
      setError(message(reason));
    } finally {
      setScopeBusy(false);
    }
  };

  if (!status) {
    return (
      <main className="grid w-full max-w-[460px] place-items-center bg-background p-8 text-foreground">
        <Spinner />
      </main>
    );
  }

  if (!status.request) {
    return (
      <main className="w-full max-w-[460px] bg-background p-5 text-foreground">
        <h1 className="text-base leading-snug font-medium">没有等待中的解锁请求</h1>
      </main>
    );
  }

  const seconds = Math.max(0, Math.ceil(remaining / 1_000));
  const progress = Math.max(0, Math.min(100, (remaining / AGENT_UNLOCK_WAIT_MILLIS) * 100));

  return (
    <main className="w-full max-w-[460px] overflow-x-hidden bg-background text-foreground">
      <UnlockCard
        surface={surface}
        bridge={bridge}
        hasVault={status.access.hasVault}
        unlockRef={status.request.unlockRef}
        request={status.request}
        pin={status.pin}
        biometric={status.biometric}
        busy={busy}
        error={error}
        countdown={{ seconds, progress, expired }}
        agentScope={{
          checked: status.access.settings.unlockScope === 'client',
          busy: scopeBusy,
          onChange: setSharedUnlock,
        }}
        onSubmitPassword={(password) => submitCredential('agent_unlock_password', { password })}
        onSubmitPin={(pin) => submitCredential('agent_unlock_pin', { pin })}
        onBiometricUnlocked={handleBiometricUnlocked}
        onCancel={cancel}
        onClearError={() => setError(null)}
      />
    </main>
  );
}

export function bootstrapAgentUnlock(container: HTMLElement): void {
  createRoot(container).render(<AgentUnlockWindow />);
}
