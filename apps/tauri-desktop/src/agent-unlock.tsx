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

interface AgentUnlockRequest {
  kind?: 'agent';
  unlockRef: string;
  clientId: string;
  clientKey: string;
  createdAt: number;
  expiresAt: number;
}

interface BrowserAutofillUnlockRequest {
  kind: 'browser-autofill';
  unlockRef: string;
  origin: string;
  itemTitle: string;
  itemKind: 'login' | 'card' | 'identity' | 'secret' | 'ssh';
  masterPasswordReprompt: boolean;
  createdAt: number;
  expiresAt: number;
}

type UnlockRequest = AgentUnlockRequest | BrowserAutofillUnlockRequest;

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
  return '临时解锁失败。';
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
  const statusRef = useRef<UnlockStatus | null>(null);
  const activeUnlockRef = useRef('');
  const expiredHandledRef = useRef('');
  const biometricAttempt = useRef('');
  const factorRequest = useRef('');

  const applyStatus = (next: UnlockStatus): void => {
    statusRef.current = next;
    setStatus(next);
    const nextRef = next.request?.unlockRef ?? '';
    if (!nextRef) {
      activeUnlockRef.current = '';
      setDeadline(0);
      return;
    }
    if (activeUnlockRef.current !== nextRef) {
      activeUnlockRef.current = nextRef;
      setExpired(false);
      setRemaining(AGENT_UNLOCK_WAIT_MILLIS);
      setDeadline(Date.now() + AGENT_UNLOCK_WAIT_MILLIS);
    }
  };

  const refresh = async (): Promise<void> => {
    const next = await invoke<UnlockStatus>('agent_unlock_status');
    applyStatus(next);
  };

  const expireCurrentRequest = async (): Promise<void> => {
    const unlockRef = statusRef.current?.request?.unlockRef;
    if (!unlockRef || expiredHandledRef.current === unlockRef) return;
    expiredHandledRef.current = unlockRef;
    setExpired(true);
    setDeadline(0);
    setRemaining(0);
    setCredential('');
    await invoke('agent_unlock_cancel').catch(() => undefined);
    const next = await invoke<UnlockStatus>('agent_unlock_status').catch(() => null);
    if (next?.request && next.request.unlockRef !== unlockRef) {
      setBusy(false);
      setError('');
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
        if (disposed) unlisten(); else unlisteners.push(unlisten);
      });
    };
    register('agent-unlock-requested', () => {
      setError('');
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

  const pinPreferred = Boolean(status?.pin.enabled && !status.pin.locked && usePin);
  const seconds = Math.max(0, Math.ceil(remaining / 1_000));
  const progress = Math.max(0, Math.min(100, remaining / AGENT_UNLOCK_WAIT_MILLIS * 100));

  const unlock = async (command: 'agent_unlock_password' | 'agent_unlock_pin' | 'agent_unlock_biometric', input?: Record<string, string>): Promise<void> => {
    if (busy) return;
    const attemptedRef = statusRef.current?.request?.unlockRef ?? '';
    setBusy(true);
    setError('');
    try {
      if (input) await invoke(command, input);
      else await invoke(command);
      if (attemptedRef && expiredHandledRef.current === attemptedRef) return;
      setCredential('');
      setBusy(false);
      const next = await invoke<UnlockStatus>('agent_unlock_status');
      if (next.request) {
        applyStatus(next);
      } else {
        applyStatus(next);
        await getCurrentWindow().hide();
      }
    } catch (reason) {
      if (attemptedRef && expiredHandledRef.current === attemptedRef) return;
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
        setCredential('');
        setBusy(false);
        setError('');
        applyStatus(next);
      } else {
        applyStatus(next);
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

  if (!status) return <main className="grid min-h-svh place-items-center bg-background"><Spinner /></main>;
  if (!status.request) {
    return <main className="flex min-h-svh flex-col bg-background p-5 text-foreground"><h1 className="text-base leading-snug font-medium">没有等待中的 MCP 解锁</h1></main>;
  }

  const currentRequest = status.request;
  const isBrowserAutofill = currentRequest.kind === 'browser-autofill';
  const pinLabel = isBrowserAutofill ? '桌面端 PIN' : 'Agent 专用 PIN';
  const pinSwitchLabel = pinPreferred
    ? '改用主密码'
    : (isBrowserAutofill ? '改用桌面端 PIN' : '改用 Agent PIN');
  const submitLabel = busy
    ? '正在解锁…'
    : (isBrowserAutofill ? '解锁并填充' : '解锁 MCP');

  return (
    <main className="flex min-h-svh flex-col bg-background text-foreground">
      <Progress
        className="shrink-0 rounded-none"
        value={progress}
        aria-label={isBrowserAutofill ? '本次自动填充解锁剩余时间' : '本次 MCP 解锁剩余时间'}
      />
      <header className="grid gap-1 p-5 pb-3">
        <div className="mb-2 flex items-center gap-3">
          <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-primary text-primary-foreground"><LockKeyholeIcon /></div>
          <h1 className="min-w-0 flex-1 text-base leading-snug font-medium">
            {currentRequest.kind === 'browser-autofill'
              ? `解锁自动填充 · ${currentRequest.itemTitle}`
              : `解锁 ${currentRequest.clientKey} 的 MCP 访问`}
          </h1>
          <Badge className="shrink-0" variant={expired ? 'destructive' : 'secondary'}>{expired ? '本次调用已超时' : `剩余 ${seconds} 秒`}</Badge>
        </div>
        <p className="text-sm text-wrap-normal text-muted-foreground">
          {currentRequest.kind === 'browser-autofill'
            ? `本次解锁仅填充当前网页（${currentRequest.origin}）的所选凭据，不会解锁桌面端、浏览器插件弹窗或 MCP。${currentRequest.masterPasswordReprompt ? '此条目受主密码保护，需要输入主密码确认填充。' : ''}`
            : status.access.settings.unlockScope === 'client'
              ? '本次解锁允许同一已配对客户端的并行 MCP 连接共享，不会解锁桌面、插件或其他 Agent。'
              : '本次解锁只授权当前 MCP 连接，不会解锁桌面、插件或其他 Agent。'}
        </p>
      </header>
      <section className="min-h-0 flex-1 overflow-y-auto px-5 pb-4">
        <form id="agent-unlock-form" onSubmit={submit}>
          <FieldGroup>
            {error ? <Alert variant="destructive" role="alert"><AlertTitle>解锁失败</AlertTitle><AlertDescription>{error}</AlertDescription></Alert> : null}
            {!isBrowserAutofill ? (
              <div className="flex items-center justify-between gap-4 rounded-md border p-3">
                <div className="grid gap-1">
                  <FieldLabel htmlFor="agent-unlock-shared-scope">同一客户端只解锁一次</FieldLabel>
                  <p className="text-xs text-muted-foreground">这是全局 Agent 解锁范围；开启后，同一已配对客户端的并行连接无需分别输入凭据。</p>
                </div>
                <Switch id="agent-unlock-shared-scope" checked={status.access.settings.unlockScope === 'client'} disabled={scopeBusy} onCheckedChange={(checked) => void setSharedUnlock(checked)} />
              </div>
            ) : null}
            {!status.access.hasVault ? <Alert variant="destructive"><AlertTitle>尚未创建保险库</AlertTitle><AlertDescription>请先在 VaultMesh 主窗口创建保险库。</AlertDescription></Alert> : pinPreferred ? (
              <Field>
                <FieldLabel className="justify-center text-center" htmlFor="agent-unlock-pin">{pinLabel}</FieldLabel>
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
        {status.access.hasVault && status.pin.enabled ? <Button variant="ghost" disabled={busy || status.pin.locked} onClick={() => { setCredential(''); setUsePin(!pinPreferred); }}>{pinSwitchLabel}</Button> : null}
        {status.access.hasVault && status.biometric.enabled ? <Button variant="secondary" type="button" disabled={busy} onClick={() => void unlock('agent_unlock_biometric')}><FingerprintIcon data-icon="inline-start" />使用 Touch ID</Button> : null}
        {status.access.hasVault && !pinPreferred ? <Button type="submit" form="agent-unlock-form" disabled={busy || credential.length < 8}>{busy ? <Spinner data-icon="inline-start" /> : null}{busy ? '正在解锁…' : submitLabel}</Button> : null}
      </footer>
    </main>
  );
}

export function bootstrapAgentUnlock(container: HTMLElement): void {
  createRoot(container).render(<AgentUnlockWindow />);
}
