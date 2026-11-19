import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { ArrowRightIcon, FolderOpenIcon, ShieldCheckIcon } from 'lucide-react';

import { ErrorBanner } from '../components/ErrorBanner';
import { PasswordField } from '../components/PasswordField';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { FieldGroup } from '@/components/ui/field';
import { Spinner } from '@/components/ui/spinner';
import { useVaultStore } from '@/stores/vault-store';

export function CreateVaultPage() {
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [localError, setLocalError] = useState<string | null>(null);
  const busy = useVaultStore((state) => state.busy);
  const error = useVaultStore((state) => state.error);
  const createVault = useVaultStore((state) => state.createVault);
  const clearError = useVaultStore((state) => state.clearError);
  const navigate = useNavigate();

  useEffect(() => {
    void window.vaultMesh?.desktop?.setCompactWindowMode?.(false).catch(() => {});
  }, []);

  const submit = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (password !== confirmation) {
      setLocalError('两次输入的主密码不一致。');
      return;
    }
    setLocalError(null);
    try {
      if (await createVault(password)) {
        void window.vaultMesh?.desktop?.setCompactWindowMode?.(false).catch(() => {});
        void navigate({ to: '/vault', replace: true });
      }
    } finally {
      setPassword('');
      setConfirmation('');
    }
  };

  return (
    <section className="mx-auto grid min-h-[calc(100svh-4rem)] w-full max-w-6xl place-items-center px-5 py-10">
      <Card className="w-full max-w-lg">
        <CardHeader>
          <div className="mb-2 grid size-10 place-items-center rounded-lg bg-primary text-primary-foreground">
            <ShieldCheckIcon />
          </div>
          <CardTitle>创建本地保险库</CardTitle>
          <CardDescription>请设置一个足够长且唯一的主密码。VaultMesh 无法为您找回该密码。</CardDescription>
        </CardHeader>
        <CardContent>
          <form id="create-vault" onSubmit={(event) => void submit(event)}>
            <FieldGroup>
              <ErrorBanner message={localError ?? error} />
              <PasswordField id="master-password" label="主密码" value={password} minLength={8} autoFocus onChange={setPassword} />
              <PasswordField id="confirm-master-password" label="确认主密码" value={confirmation} minLength={8} onChange={setConfirmation} />
            </FieldGroup>
          </form>
        </CardContent>
        <CardFooter className="flex-col items-stretch gap-2 sm:flex-row sm:justify-between">
          <Button variant="ghost" type="button" onClick={() => { clearError(); void navigate({ to: '/unlock' }); }}>
            <FolderOpenIcon data-icon="inline-start" />
            打开已有保险库
          </Button>
          <Button type="submit" form="create-vault" disabled={busy}>
            {busy ? <Spinner data-icon="inline-start" /> : <ArrowRightIcon data-icon="inline-start" />}
            {busy ? '正在创建…' : '创建保险库'}
          </Button>
        </CardFooter>
      </Card>
    </section>
  );
}
