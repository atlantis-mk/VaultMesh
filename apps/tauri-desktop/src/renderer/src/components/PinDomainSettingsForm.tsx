import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { toast } from 'sonner';

import type { PinStatus } from '../../../shared/contracts';
import type { PinSettingsDomainAdapter } from '../lib/pin-settings-adapter';
import { Button } from './ui/button';
import { Card, CardDescription, CardHeader, CardTitle } from './ui/card';
import { Field, FieldGroup, FieldLabel } from './ui/field';
import { Input } from './ui/input';
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from './ui/select';

const FAILURE_LIMIT_OPTIONS = [3, 4, 5, 6, 7, 8, 9, 10] as const;

export interface PinDomainSettingsFormProps {
  adapter: PinSettingsDomainAdapter;
  status: PinStatus | null;
  busy: boolean;
  resetKey?: string | number | boolean;
  onStatusChange: (status: PinStatus) => void;
  onRun: (operation: () => Promise<void>, successMessage: string) => Promise<void>;
  extraActions?: ReactNode;
}

export function PinDomainSettingsForm({
  adapter,
  status,
  busy,
  resetKey,
  onStatusChange,
  onRun,
  extraActions,
}: PinDomainSettingsFormProps) {
  const [pinValue, setPinValue] = useState('');
  const [pinConfirmation, setPinConfirmation] = useState('');
  const [failureLimit, setFailureLimit] = useState(status?.failureLimit ?? 5);

  const clearDrafts = (): void => {
    setPinValue('');
    setPinConfirmation('');
  };

  useEffect(() => {
    clearDrafts();
    setFailureLimit(status?.failureLimit ?? 5);
  }, [adapter.domain, resetKey]);

  useEffect(() => {
    if (status?.failureLimit !== undefined) {
      setFailureLimit(status.failureLimit);
    }
  }, [status?.failureLimit]);

  useEffect(() => {
    const onVisibilityChange = (): void => {
      if (document.visibilityState === 'hidden') {
        clearDrafts();
      }
    };
    const onPageHide = (): void => {
      clearDrafts();
    };
    document.addEventListener('visibilitychange', onVisibilityChange);
    window.addEventListener('pagehide', onPageHide);
    return () => {
      document.removeEventListener('visibilitychange', onVisibilityChange);
      window.removeEventListener('pagehide', onPageHide);
    };
  }, []);

  const handleSubmit = (event: FormEvent): void => {
    event.preventDefault();
    if (pinValue.length !== 6) {
      toast.error('PIN 必须为 6 位数字。');
      return;
    }
    if (pinValue !== pinConfirmation) {
      toast.error('两次输入的 PIN 不一致。');
      clearDrafts();
      return;
    }
    const nextPin = pinValue;
    const nextLimit = failureLimit;
    const wasEnabled = Boolean(status?.enabled);
    clearDrafts();
    void onRun(async () => {
      const next = await adapter.enable({ pin: nextPin, failureLimit: nextLimit });
      onStatusChange(next);
    }, wasEnabled ? adapter.updateSuccessMessage : adapter.enableSuccessMessage);
  };

  const handleDisable = (): void => {
    clearDrafts();
    void onRun(async () => {
      const next = await adapter.disable();
      onStatusChange(next);
    }, adapter.disableSuccessMessage);
  };

  return (
    <form className="flex flex-col gap-4" onSubmit={handleSubmit}>
      {status?.locked ? (
        <Card size="sm">
          <CardHeader>
            <CardTitle>{adapter.title}已锁定</CardTitle>
            <CardDescription>{adapter.lockedDescription}</CardDescription>
          </CardHeader>
        </Card>
      ) : null}
      <FieldGroup>
        <Field>
          <FieldLabel htmlFor={adapter.idPrefix}>{status?.enabled ? '新 6 位 PIN' : '6 位 PIN'}</FieldLabel>
          <Input
            id={adapter.idPrefix}
            type="password"
            inputMode="numeric"
            value={pinValue}
            minLength={6}
            maxLength={6}
            autoComplete="new-password"
            onChange={(event) => setPinValue(event.target.value.replace(/\D/g, '').slice(0, 6))}
          />
        </Field>
        <Field data-invalid={pinConfirmation.length > 0 && pinValue !== pinConfirmation}>
          <FieldLabel htmlFor={`${adapter.idPrefix}-confirmation`}>确认 6 位 PIN</FieldLabel>
          <Input
            id={`${adapter.idPrefix}-confirmation`}
            type="password"
            inputMode="numeric"
            value={pinConfirmation}
            minLength={6}
            maxLength={6}
            autoComplete="new-password"
            aria-invalid={pinConfirmation.length > 0 && pinValue !== pinConfirmation}
            onChange={(event) => setPinConfirmation(event.target.value.replace(/\D/g, '').slice(0, 6))}
          />
        </Field>
        <Field>
          <FieldLabel htmlFor={`${adapter.idPrefix}-limit`}>连续失败次数上限</FieldLabel>
          <Select value={String(failureLimit)} onValueChange={(value) => setFailureLimit(Number(value))}>
            <SelectTrigger id={`${adapter.idPrefix}-limit`}><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectGroup>
                {FAILURE_LIMIT_OPTIONS.map((value) => (
                  <SelectItem key={value} value={String(value)}>
                    {value} 次{value === 5 ? '（默认）' : ''}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </Field>
        <div className="flex flex-wrap gap-2">
          <Button size="sm" type="submit" disabled={busy || pinValue.length !== 6 || pinValue !== pinConfirmation}>
            {status?.enabled ? '更新 PIN' : '启用 PIN 解锁'}
          </Button>
          {status?.enabled ? (
            <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={handleDisable}>
              {adapter.disableButtonLabel}
            </Button>
          ) : null}
          {extraActions}
        </div>
      </FieldGroup>
    </form>
  );
}
