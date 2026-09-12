import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { REGEXP_ONLY_DIGITS } from 'input-otp';
import { FingerprintIcon, LockKeyholeIcon } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { createRoot } from 'react-dom/client';

import { PasswordField } from './renderer/src/components/PasswordField';
import { Alert, AlertDescription, AlertTitle } from './renderer/src/components/ui/alert';
import { Badge } from './renderer/src/components/ui/badge';
import { Button } from './renderer/src/components/ui/button';
import { Field, FieldGroup, FieldLabel } from './renderer/src/components/ui/field';
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from './renderer/src/components/ui/input-otp';
import { Progress } from './renderer/src/components/ui/progress';
import { Spinner } from './renderer/src/components/ui/spinner';
import { Switch } from './renderer/src/components/ui/switch';
import './renderer/src/styles/app.css';

const AGENT_UNLOCK_WAIT_MILLIS = 30_000;

interface UnlockRequest {
  unlockRef: string;
  clientId: string;
  clientKey: string;
  createdAt: number;
  expiresAt: number;
}

interface UnlockStatus {
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
  return 'MCP 解锁失败。';
}

export function AgentUnlockWindow() {
  const [status, setStatus] = useState<UnlockStatus | null>(null);
  const [credential, setCredential] = useState('');
  const [usePin, setUsePin] = useState(false);
  const [busy, setBusy] = useState(false);
  const [expired, setExpired] = useState(false);
  const [error, setError] = useState('');
  const [scopeBusy, setScopeBusy] = useState(false);
  const [deadline, setDeadline] = useState(0);
  const [remaining, setRemaining] = useState(AGENT_UNLOCK_WAIT_MILLIS);
  const biometricAttempt = useRef('');
  const factorRequest = useRef('');

  const refresh = async (): Promise<void> => {
    const next = await invoke<UnlockStatus>('agent_unlock_status');
    setStatus(next);
    if (next.request) {
      setDeadline((current) => current || Date.now() + AGENT_UNLOCK_WAIT_MILLIS);
    } else {
      setDeadline(0);
    }
  };

  useEffect(() => {
    void refresh().catch((reason) => setError(message(reason)));
    const unlisteners: Array<() => void> = [];
    let disposed = false;
    const register = (event: string, handler: () => void): void => {
      void listen(event, handler).then((unlisten) => {
        if (disposed) unlisten(); else unlisteners.push(unlisten);
      });
    };
    register('agent-unlock-requested', () => {
      setExpired(false);
      setDeadline(Date.now() + AGENT_UNLOCK_WAIT_MILLIS);
      setError('');
      void refresh().catch((reason) => setError(message(reason)));
    });
    register('agent-unlock-expired', () => {
      setExpired(true);
      setDeadline(Date.now());
      setRemaining(0);
    });
    return () => {
      disposed = true;
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  useEffect(() => {
    if (!deadline) return;
    const update = (): void => {
      const next = Math.max(0, deadline - Date.now());
      setRemaining(next);
      if (next === 0) window.clearInterval(timer);
    };
    const timer = window.setInterval(update, 200);
    update();
    return () => window.clearInterval(timer);
  }, [deadline]);

  const pinPreferred = Boolean(status?.pin.enabled && !status.pin.locked && usePin);
  const seconds = Math.max(0, Math.ceil(remaining / 1_000));
  const progress = Math.max(0, Math.min(100, remaining / AGENT_UNLOCK_WAIT_MILLIS * 100));

  const unlock = async (command: 'agent_unlock_password' | 'agent_unlock_pin' | 'agent_unlock_biometric', input?: Record<string, string>): Promise<void> => {
    if (busy) return;
    setBusy(true);
    setError('');
    try {
      if (input) await invoke(command, input);
      else await invoke(command);
      setCredential('');
      setBusy(false);
      const next = await invoke<UnlockStatus>('agent_unlock_status');
      if (next.request) {
        setStatus(next);
        setExpired(false);
      } else {
        await getCurrentWindow().hide();
      }
    } catch (reason) {
      setError(message(reason));
      setCredential('');
      setBusy(false);
      await refresh().catch(() => undefined);
    }
  };

  useEffect(() => {
    const unlockRef = status?.request?.unlockRef;
    if (!unlockRef || factorRequest.current === unlockRef) return;
    factorRequest.current = unlockRef;
    setUsePin(Boolean(status.pin.enabled && !status.pin.locked && !status.biometric.enabled));
  }, [status?.request?.unlockRef, status?.pin.enabled, status?.pin.locked, status?.biometric.enabled]);

  useEffect(() => {
    const unlockRef = status?.request?.unlockRef;
    if (!unlockRef || !status.biometric.enabled || biometricAttempt.current === unlockRef) return;
    biometricAttempt.current = unlockRef;
    void unlock('agent_unlock_biometric');
  }, [status?.request?.unlockRef, status?.biometric.enabled]);

  const submit = (event: FormEvent): void => {
    event.preventDefault();
    if (!pinPreferred) void unlock('agent_unlock_password', { password: credential });
  };

  const cancel = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await invoke('agent_unlock_cancel');
      const next = await invoke<UnlockStatus>('agent_unlock_status');
      if (next.request) {
        setStatus(next);
        setExpired(false);
        setCredential('');
        setBusy(false);
      } else {
        await getCurrentWindow().hide();
      }
    } catch (reason) {
      setError(message(reason));
      setBusy(false);
    }
  };

  const setSharedUnlock = async (shared: boolean): Promise<void> => {
    if (scopeBusy) return;
    setScopeBusy(true);
    setError('');
    try {
      const settings = await invoke<UnlockStatus['access']['settings']>('agent_unlock_set_scope', {
        scope: shared ? 'client' : 'connection',
      });
      setStatus((current) => current ? {
        ...current,
        access: { ...current.access, settings },
      } : current);
    } catch (reason) {
      setError(message(reason));
    } finally {
      setScopeBusy(false);
    }
  };

  if (!status) return <main className="grid min-h-svh place-items-center bg-background"><Spinner /></main>;
  if (!status.request) {
    return <main className="flex min-h-svh flex-col bg-background p-5 text-foreground"><h1 className="text-base leading-snug font-medium">没有等待中的 MCP 解锁</h1></main>;
  }

  return (
    <main className="flex min-h-svh flex-col bg-background text-foreground">
      <Progress className="shrink-0 rounded-none" value={progress} aria-label="本次 MCP 解锁剩余时间" />
      <header className="grid gap-1 p-5 pb-3">
        <div className="mb-2 flex items-center gap-3">
          <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-primary text-primary-foreground"><LockKeyholeIcon /></div>
          <h1 className="min-w-0 flex-1 text-base leading-snug font-medium">解锁 {status.request.clientKey} 的 MCP 访问</h1>
          <Badge className="shrink-0" variant={expired ? 'destructive' : 'secondary'}>{expired ? '本次调用已超时' : `剩余 ${seconds} 秒`}</Badge>
        </div>
        <p className="text-sm text-wrap-normal text-muted-foreground">
          {status.access.settings.unlockScope === 'client'
            ? '本次解锁允许同一已配对客户端的并行 MCP 连接共享，不会解锁桌面、插件或其他 Agent。'
            : '本次解锁只授权当前 MCP 连接，不会解锁桌面、插件或其他 Agent。'}
        </p>
      </header>
      <section className="min-h-0 flex-1 overflow-y-auto px-5 pb-4">
        <form id="agent-unlock-form" onSubmit={submit}>
          <FieldGroup>
            {error ? <Alert variant="destructive" role="alert"><AlertTitle>解锁失败</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
            <div className="flex items-center justify-between gap-4 rounded-md border p-3">
              <div className="grid gap-1">
                <FieldLabel htmlFor="agent-unlock-shared-scope">同一客户端只解锁一次</FieldLabel>
                <p className="text-xs text-muted-foreground">这是全局 Agent 解锁范围；开启后，同一已配对客户端的并行连接无需分别输入凭据。</p>
              </div>
              <Switch id="agent-unlock-shared-scope" checked={status.access.settings.unlockScope === 'client'} disabled={scopeBusy} onCheckedChange={(checked) => void setSharedUnlock(checked)} />
            </div>
            {!status.access.hasVault ? <Alert variant="destructive"><AlertTitle>尚未创建保险库</AlertTitle><AlertDescription>请先在 VaultMesh 主窗口创建保险库。</AlertDescription></Alert> : pinPreferred ? (
              <Field>
                <FieldLabel className="justify-center text-center" htmlFor="agent-unlock-pin">Agent 专用 PIN</FieldLabel>
                <InputOTP id="agent-unlock-pin" value={credential} maxLength={6} pattern={REGEXP_ONLY_DIGITS} autoComplete="off" pushPasswordManagerStrategy="none" autoFocus disabled={busy} containerClassName="justify-center" onChange={setCredential} onComplete={(value) => void unlock('agent_unlock_pin', { pin: value })}>
                  <InputOTPGroup><InputOTPSlot index={0} mask /><InputOTPSlot index={1} mask /><InputOTPSlot index={2} mask /></InputOTPGroup>
                  <InputOTPSeparator />
                  <InputOTPGroup><InputOTPSlot index={3} mask /><InputOTPSlot index={4} mask /><InputOTPSlot index={5} mask /></InputOTPGroup>
                </InputOTP>
              </Field>
            ) : <PasswordField id="agent-unlock-password" label="主密码" value={credential} minLength={8} maxLength={1_024} autoFocus onChange={setCredential} />}
          </FieldGroup>
        </form>
      </section>
      <footer className="flex flex-wrap justify-between gap-2 border-t bg-muted/50 p-3">
        <Button variant="outline" disabled={busy} onClick={() => void cancel()}>取消</Button>
        {status.access.hasVault && status.pin.enabled ? <Button variant="ghost" disabled={busy || status.pin.locked} onClick={() => { setCredential(''); setUsePin(!pinPreferred); }}>{pinPreferred ? '改用主密码' : '改用 Agent PIN'}</Button> : null}
        {status.access.hasVault && status.biometric.enabled ? <Button variant="secondary" type="button" disabled={busy} onClick={() => void unlock('agent_unlock_biometric')}><FingerprintIcon data-icon="inline-start" />使用 Touch ID</Button> : null}
        {status.access.hasVault && !pinPreferred ? <Button type="submit" form="agent-unlock-form" disabled={busy || credential.length < 8}>{busy ? <Spinner data-icon="inline-start" /> : null}{busy ? '正在解锁…' : '解锁 MCP'}</Button> : null}
      </footer>
    </main>
  );
}

export function bootstrapAgentUnlock(container: HTMLElement): void {
  createRoot(container).render(<AgentUnlockWindow />);
}
