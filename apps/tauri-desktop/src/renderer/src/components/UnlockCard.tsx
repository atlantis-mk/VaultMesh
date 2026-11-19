import { REGEXP_ONLY_DIGITS } from 'input-otp';
import { ArrowLeftIcon, ArrowRightIcon, LockKeyholeIcon } from 'lucide-react';
import { useEffect, useRef, useState, type FormEvent } from 'react';

import { usePlatformAuthentication } from '../hooks/use-platform-authentication';
import type { PlatformAuthBridgeAdapter } from '../lib/platform-auth-bridge';
import type { UnlockSurfaceUiAdapter, UnlockWindowRequest } from '../lib/unlock-surface-adapter';
import { ErrorBanner } from './ErrorBanner';
import { PasswordField } from './PasswordField';
import { Alert, AlertDescription, AlertTitle } from './ui/alert';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from './ui/card';
import { Field, FieldGroup, FieldLabel } from './ui/field';
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from './ui/input-otp';
import { Progress } from './ui/progress';
import { Spinner } from './ui/spinner';
import { Switch } from './ui/switch';
import { cn } from '../lib/utils';

export const COMPACT_WINDOW_HEIGHT_SLACK_PX = 8;

export interface UnlockCardProps {
  surface: UnlockSurfaceUiAdapter;
  bridge: PlatformAuthBridgeAdapter;
  hasVault: boolean;
  unlockRef?: string;
  request?: UnlockWindowRequest | null;
  pin: { enabled: boolean; locked: boolean; remainingAttempts: number } | null;
  biometric: { available: boolean; enabled: boolean; kind: 'touchId' | null } | null;
  busy: boolean;
  error: string | null;
  countdown?: { seconds: number; progress: number; expired: boolean };
  agentScope?: { checked: boolean; busy: boolean; onChange: (checked: boolean) => Promise<void> };
  onSubmitPassword: (password: string) => Promise<void>;
  onSubmitPin: (pin: string) => Promise<void>;
  onBiometricUnlocked: () => Promise<void>;
  onCancel?: () => Promise<void>;
  onClearError?: () => void;
  onNavigateSetup?: () => void;
}

export function UnlockCard({
  surface,
  bridge,
  hasVault,
  unlockRef = surface.kind,
  request,
  pin,
  biometric,
  busy,
  error,
  countdown,
  agentScope,
  onSubmitPassword,
  onSubmitPin,
  onBiometricUnlocked,
  onCancel,
  onClearError,
  onNavigateSetup,
}: UnlockCardProps) {
  const cardRef = useRef<HTMLDivElement>(null);
  const syncHeightRef = useRef<() => void>(() => {});
  const submitting = useRef(false);
  const [credential, setCredential] = useState('');
  const [useMasterPassword, setUseMasterPassword] = useState(false);

  useEffect(() => {
    setCredential('');
    setUseMasterPassword(false);
    submitting.current = false;
  }, [unlockRef, surface.kind]);

  const pinPreferred = Boolean(
    pin?.enabled
    && !pin.locked
    && !useMasterPassword
    && !surface.forceMasterPassword,
  );
  const biometricEnabledInSurface = Boolean(
    hasVault
    && !surface.forceMasterPassword
    && biometric?.available
    && biometric.enabled,
  );

  const authentication = usePlatformAuthentication({
    bridge,
    enabled: biometricEnabledInSurface,
    attemptKey: unlockRef,
    onUnlocked: async () => {
      setCredential('');
      await onBiometricUnlocked();
    },
  });

  const effectiveBusy = busy || authentication.status === 'opening';
  const embeddedBiometricActive = biometricEnabledInSurface && Boolean(authentication.capability?.supported);
  const showUnsupportedHint = Boolean(
    hasVault
    && !surface.forceMasterPassword
    && biometric?.enabled
    && authentication.capability
    && !authentication.capability.supported,
  );
  const showRetryTouchId = embeddedBiometricActive
    && (authentication.status === 'failed' || authentication.status === 'paused');
  const hasAgentScope = Boolean(surface.showAgentScopeSwitch && agentScope);

  useEffect(() => {
    const element = cardRef.current;
    if (!element) {
      syncHeightRef.current = () => {};
      return;
    }
    let disposed = false;
    let lastHeight = 0;
    let frameId = 0;
    const syncHeight = () => {
      if (disposed) return;
      const contentHeight = Math.ceil(Math.max(element.getBoundingClientRect().height, element.scrollHeight));
      if (contentHeight <= 0) return;
      const targetHeight = contentHeight + COMPACT_WINDOW_HEIGHT_SLACK_PX;
      if (targetHeight !== lastHeight) {
        lastHeight = targetHeight;
        void bridge.setCompactWindowMode(true, targetHeight).catch(() => {});
      }
    };
    syncHeightRef.current = syncHeight;
    syncHeight();
    void document.fonts?.ready?.then(() => {
      if (!disposed) {
        syncHeight();
      }
    }, () => {});
    if (typeof ResizeObserver === 'undefined') {
      return () => {
        disposed = true;
        syncHeightRef.current = () => {};
      };
    }
    const observer = new ResizeObserver(() => {
      if (typeof requestAnimationFrame === 'function') {
        cancelAnimationFrame(frameId);
        frameId = requestAnimationFrame(syncHeight);
      } else {
        syncHeight();
      }
    });
    observer.observe(element);
    return () => {
      disposed = true;
      syncHeightRef.current = () => {};
      cancelAnimationFrame(frameId);
      observer.disconnect();
    };
  }, [bridge, unlockRef]);

  useEffect(() => {
    syncHeightRef.current();
  }, [
    surface.kind,
    pinPreferred,
    embeddedBiometricActive,
    showUnsupportedHint,
    showRetryTouchId,
    error,
    hasVault,
    hasAgentScope,
  ]);

  const biometricStatusText =
    authentication.status === 'opening'
      ? '指纹验证成功，正在打开保险库…'
      : authentication.status === 'listening'
        ? surface.buildTouchIdHint(pinPreferred)
        : authentication.status === 'failed'
          ? authentication.error ?? 'Touch ID 验证未完成，可重试或输入密码'
          : '可重试 Touch ID，或使用密码解锁';

  const submitCredential = async (value: string): Promise<void> => {
    if (effectiveBusy || submitting.current) return;
    submitting.current = true;
    try {
      await authentication.cancel().catch(() => {});
      if (pinPreferred) {
        await onSubmitPin(value);
      } else {
        await onSubmitPassword(value);
      }
    } finally {
      submitting.current = false;
      setCredential('');
    }
  };

  const submit = (event: FormEvent): void => {
    event.preventDefault();
    if (!pinPreferred) {
      void submitCredential(credential);
    }
  };

  const description = surface.buildDescription({
    pinPreferred,
    pinLocked: Boolean(pin?.locked),
    pinRemainingAttempts: pin?.remainingAttempts,
    biometricEnabled: Boolean(biometric?.enabled),
    request,
    unlockScope: agentScope?.checked ? 'client' : 'connection',
  });

  return (
    <div className="flex min-h-svh w-full max-w-[460px] flex-col bg-card">
      <Card
        ref={cardRef}
        className={cn(
          'w-full max-w-[460px] rounded-none border-0 shadow-none ring-0',
          surface.hasCountdown && countdown && 'pt-0',
        )}
      >
      {surface.hasCountdown && countdown ? (
        <Progress
          className="h-1 shrink-0 rounded-none"
          value={countdown.progress}
          aria-label={surface.countdownAriaLabel}
        />
      ) : null}
      <CardHeader className="pb-1">
        <div className="mb-1 flex items-center gap-3">
          <div className="grid size-9 shrink-0 place-items-center rounded-lg bg-primary text-primary-foreground">
            <LockKeyholeIcon className="size-4" />
          </div>
          <CardTitle className="min-w-0 flex-1">{surface.title}</CardTitle>
          {surface.hasCountdown && countdown ? (
            <Badge className="shrink-0" variant={countdown.expired ? 'destructive' : 'secondary'}>
              {countdown.expired ? '本次调用已超时' : `剩余 ${countdown.seconds} 秒`}
            </Badge>
          ) : null}
        </div>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <form id={surface.formId} onSubmit={submit}>
          <FieldGroup className="gap-3">
            {embeddedBiometricActive ? (
              <div className="flex flex-col items-center gap-1.5" aria-label="Touch ID 认证">
                <div className="relative size-16 shrink-0">
                  <div ref={authentication.anchor} className="size-16" />
                  {authentication.status === 'opening' ? (
                    <Spinner role="presentation" aria-hidden="true" className="absolute inset-0 m-auto size-8" />
                  ) : null}
                </div>
                <p className="text-center text-sm text-muted-foreground" role="status" aria-label="解锁状态">
                  {biometricStatusText}
                </p>
              </div>
            ) : showUnsupportedHint ? (
              <p className="text-sm text-muted-foreground">
                {authentication.capability?.label}，请使用主密码或 PIN。
              </p>
            ) : null}
            <ErrorBanner message={surface.usesErrorBanner ? error : null} />
            {error && !surface.usesErrorBanner ? (
              <Alert variant="destructive" role="alert">
                <AlertTitle>解锁失败</AlertTitle>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            ) : null}
            {surface.showAgentScopeSwitch && agentScope ? (
              <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
                <div className="grid gap-0.5">
                  <FieldLabel htmlFor="agent-unlock-shared-scope">同一客户端只解锁一次</FieldLabel>
                  <p className="text-xs text-muted-foreground">开启后，同一已配对客户端的并行连接无需重复解锁。</p>
                </div>
                <Switch
                  id="agent-unlock-shared-scope"
                  checked={agentScope.checked}
                  disabled={agentScope.busy}
                  onCheckedChange={(checked) => void agentScope.onChange(checked)}
                />
              </div>
            ) : null}
            {!hasVault ? (
              <Alert variant="destructive">
                <AlertTitle>尚未创建保险库</AlertTitle>
                <AlertDescription>{surface.vaultMissingDescription}</AlertDescription>
              </Alert>
            ) : pinPreferred ? (
              <Field>
                <FieldLabel className={surface.centerPinLabel ? 'justify-center text-center' : undefined} htmlFor={surface.pinInputId}>
                  {surface.pinLabel}
                </FieldLabel>
                <InputOTP
                  id={surface.pinInputId}
                  value={credential}
                  maxLength={6}
                  pattern={REGEXP_ONLY_DIGITS}
                  autoComplete="off"
                  pushPasswordManagerStrategy="none"
                  autoFocus
                  disabled={effectiveBusy}
                  containerClassName="justify-center"
                  onChange={setCredential}
                  onComplete={(value) => void submitCredential(value)}
                >
                  <InputOTPGroup>
                    <InputOTPSlot index={0} mask />
                    <InputOTPSlot index={1} mask />
                    <InputOTPSlot index={2} mask />
                  </InputOTPGroup>
                  <InputOTPSeparator />
                  <InputOTPGroup>
                    <InputOTPSlot index={3} mask />
                    <InputOTPSlot index={4} mask />
                    <InputOTPSlot index={5} mask />
                  </InputOTPGroup>
                </InputOTP>
              </Field>
            ) : (
              <PasswordField
                id={surface.passwordInputId}
                label="主密码"
                value={credential}
                minLength={8}
                maxLength={1_024}
                inputMode="text"
                autoFocus
                onChange={setCredential}
              />
            )}
          </FieldGroup>
        </form>
      </CardContent>
      <CardFooter className="flex flex-wrap items-center justify-end gap-1.5 rounded-none">
        {surface.showCancelAction && onCancel ? (
          <Button variant="outline" size="sm" type="button" disabled={effectiveBusy} onClick={() => void onCancel()}>
            取消
          </Button>
        ) : null}
        {surface.showSetupWhenVaultMissing && !hasVault && onNavigateSetup ? (
          <Button variant="ghost" size="sm" type="button" onClick={onNavigateSetup}>
            <ArrowLeftIcon data-icon="inline-start" />
            创建保险库
          </Button>
        ) : null}
        {hasVault && !surface.forceMasterPassword && pin?.enabled ? (
          <Button
            variant="ghost"
            size="sm"
            type="button"
            disabled={effectiveBusy || pin.locked}
            onClick={() => {
              setCredential('');
              onClearError?.();
              setUseMasterPassword(pinPreferred);
            }}
          >
            {surface.pinSwitchLabel(pinPreferred, pin.locked)}
          </Button>
        ) : null}
        {showRetryTouchId ? (
          <Button variant="secondary" size="sm" type="button" disabled={effectiveBusy} onClick={authentication.retry}>
            重试 Touch ID
          </Button>
        ) : null}
        {hasVault && !pinPreferred ? (
          <Button size="sm" type="submit" form={surface.formId} disabled={effectiveBusy || credential.length < 8}>
            {effectiveBusy ? <Spinner data-icon="inline-start" /> : <ArrowRightIcon data-icon="inline-start" />}
            {surface.submitLabel(effectiveBusy)}
          </Button>
        ) : null}
      </CardFooter>
      </Card>
      <div aria-hidden="true" className="flex-1 bg-muted/50" />
    </div>
  );
}
