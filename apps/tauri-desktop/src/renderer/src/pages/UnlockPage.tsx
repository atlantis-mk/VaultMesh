import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { REGEXP_ONLY_DIGITS } from 'input-otp';
import { ArrowRightIcon, ArrowLeftIcon, FingerprintIcon, LockKeyholeIcon } from 'lucide-react';

import { ErrorBanner } from '../components/ErrorBanner';
import { PasswordField } from '../components/PasswordField';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field';
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from '@/components/ui/input-otp';
import { Spinner } from '@/components/ui/spinner';
import { useVaultStore } from '@/stores/vault-store';

export function UnlockPage() {
  const [credential, setCredential] = useState('');
  const [useMasterPassword, setUseMasterPassword] = useState(false);
  const busy = useVaultStore((state) => state.busy);
  const error = useVaultStore((state) => state.error);
  const status = useVaultStore((state) => state.status);
  const biometric = useVaultStore((state) => state.biometric);
  const pin = useVaultStore((state) => state.pin);
  const unlockVault = useVaultStore((state) => state.unlockVault);
  const unlockWithBiometrics = useVaultStore((state) => state.unlockWithBiometrics);
  const unlockWithPin = useVaultStore((state) => state.unlockWithPin);
  const clearError = useVaultStore((state) => state.clearError);
  const navigate = useNavigate();
  const biometricAttempted = useRef(false);
  const pinPreferred = Boolean(pin?.enabled && !pin.locked && !useMasterPassword);

  useEffect(() => {
    if (biometricAttempted.current || busy || !status?.hasVault || status.unlocked || !biometric?.available || !biometric.enabled) return;
    biometricAttempted.current = true;
    void unlockWithBiometrics().then((unlocked) => {
      if (unlocked) void navigate({ to: '/vault', replace: true });
    });
  }, [biometric?.available, biometric?.enabled, busy, navigate, status?.hasVault, status?.unlocked, unlockWithBiometrics]);

  const unlockCredential = async (value: string): Promise<void> => {
    if (busy) return;
    try {
      const unlocked = pinPreferred ? await unlockWithPin(value) : await unlockVault(value);
      if (unlocked) {
        void navigate({ to: '/vault', replace: true });
      }
    } finally {
      setCredential('');
    }
  };

  const submit = (event: FormEvent): void => {
    event.preventDefault();
    if (!pinPreferred) void unlockCredential(credential);
  };

  const unlockUsingBiometrics = async (): Promise<void> => {
    if (await unlockWithBiometrics()) {
      void navigate({ to: '/vault', replace: true });
    }
  };

  return (
    <section className="mx-auto grid min-h-svh w-full max-w-6xl place-items-center px-5 py-10">
      <Card className="w-full max-w-md">
        <CardHeader>
          <div className="mb-2 grid size-10 place-items-center rounded-lg bg-primary text-primary-foreground">
            <LockKeyholeIcon />
          </div>
          <CardTitle>解锁 VaultMesh</CardTitle>
          <CardDescription>{pinPreferred ? `输入 6 位 PIN 后自动解锁，还可尝试 ${pin?.remainingAttempts ?? 0} 次。` : pin?.locked ? 'PIN 已锁定，请先使用主密码解锁以恢复尝试次数。' : biometric?.enabled ? '使用 Touch ID 或主密码在本地解锁保险库。' : '使用主密码在本地解锁保险库。'}</CardDescription>
        </CardHeader>
        <CardContent>
          <form id="unlock-vault" onSubmit={submit}>
            <FieldGroup>
              <ErrorBanner message={error} />
              {pinPreferred ? (
                <Field>
                  <FieldLabel htmlFor="unlock-pin">6 位 PIN</FieldLabel>
                  <InputOTP
                    id="unlock-pin"
                    value={credential}
                    maxLength={6}
                    pattern={REGEXP_ONLY_DIGITS}
                    autoComplete="off"
                    pushPasswordManagerStrategy="none"
                    autoFocus
                    disabled={busy}
                    containerClassName="justify-center"
                    onChange={setCredential}
                    onComplete={(value) => void unlockCredential(value)}
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
                <PasswordField id="unlock-password" label="主密码" value={credential} minLength={8} maxLength={1_024} inputMode="text" autoFocus onChange={setCredential} />
              )}
            </FieldGroup>
          </form>
        </CardContent>
        <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-between">
          {!status?.hasVault ? (
            <Button variant="ghost" type="button" onClick={() => { clearError(); void navigate({ to: '/setup' }); }}>
              <ArrowLeftIcon data-icon="inline-start" />
              创建保险库
            </Button>
          ) : <span />}
          {!pinPreferred ? (
            <Button type="submit" form="unlock-vault" disabled={busy || credential.length < 8}>
              {busy ? <Spinner data-icon="inline-start" /> : <ArrowRightIcon data-icon="inline-start" />}
              {busy ? '正在解锁…' : '使用主密码解锁'}
            </Button>
          ) : null}
          {pin?.enabled ? (
            <Button variant="ghost" type="button" disabled={busy || pin.locked} onClick={() => { setCredential(''); clearError(); setUseMasterPassword(pinPreferred); }}>
              {pinPreferred ? '改用主密码' : pin.locked ? 'PIN 已锁定' : '改用 PIN'}
            </Button>
          ) : null}
          {biometric?.available && biometric.enabled ? (
            <Button variant="secondary" type="button" disabled={busy} onClick={() => void unlockUsingBiometrics()}>
              <FingerprintIcon data-icon="inline-start" />
              使用 Touch ID
            </Button>
          ) : null}
        </CardFooter>
      </Card>
    </section>
  );
}
