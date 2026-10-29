import { useEffect, useState } from 'react';
import { CheckIcon, ChevronDownIcon, Code2Icon, CopyIcon, TerminalIcon, type LucideIcon } from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { ButtonGroup } from '@/components/ui/button-group';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { setPreferredSshExternalClient, usePreferredSshExternalClient } from '@/lib/ssh-external-client-preference';
import { cn } from '@/lib/utils';
import type { SshCredentialSummary, SshExternalClient, SshExternalClientId } from '../../../shared/contracts';

export function SshExternalLauncher({ account }: { account: SshCredentialSummary }) {
  const [clients, setClients] = useState<SshExternalClient[]>([]);
  const preferredClientId = usePreferredSshExternalClient();
  const [busy, setBusy] = useState(false);
  useEffect(() => { void window.vaultMesh.ssh.externalClients().then(setClients).catch(() => setClients([])); }, []);
  const selectPreferredClient = (client: SshExternalClient): void => {
    setPreferredSshExternalClient(client.id);
    toast.success(`默认打开方式已切换为 ${client.label}。`);
  };
  const launch = async (): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      const settings = await window.vaultMesh.security.settings();
      const result = await window.vaultMesh.ssh.launch({ accountId: account.id, clientId: preferredClientId, copyPassword: settings.copySshPasswordOnLaunch });
      if (preferredClientId === 'copyCommand') {
        toast.success('SSH 命令已复制。');
      } else if (result.passwordCopied) {
        toast.success(`${preferredClientLabel} 已打开，SSH 密码已复制。`, { description: '密码会按安全设置自动清除；可在设置中关闭自动复制。' });
      } else if (result.passwordCopySkipped) {
        toast.warning(`${preferredClientLabel} 已打开，但密码未自动复制。`, { description: '窗口失焦锁定或主密码复核策略阻止了自动复制，请从保险库手动复制 SSH 密码。' });
      } else if (result.authentication === 'key') {
        const duration = result.durationMinutes ?? settings.sshSessionDurationMinutes ?? 15;
        toast.success(`${preferredClientLabel} 已通过短时 SSH 会话打开。`, { description: `已签发内存 SSH-Agent 临时会话（有效期 ${duration} 分钟）。` });
      } else if (result.authentication === 'password') {
        toast.success(`${preferredClientLabel} 已打开。`, { description: '请在终端输入 SSH 密码；可在设置中启用自动复制。' });
      } else {
        toast.success(`${preferredClientLabel} 已通过 SSH Agent 或系统配置打开。`);
      }
    } catch (reason) { toast.error(reason instanceof Error ? reason.message : '无法打开外部终端。'); } finally { setBusy(false); }
  };
  const preferredClient = clients.find((client) => client.id === preferredClientId);
  const preferredClientLabel = preferredClient?.label ?? CLIENT_VISUALS[preferredClientId].label;
  const launcherButtonClassName = 'bg-white/15 text-white hover:bg-white/25 aria-expanded:bg-white/25 aria-expanded:text-white';
  return <ButtonGroup aria-label="SSH 外部打开方式"><Button className={launcherButtonClassName} variant="ghost" size="icon-sm" aria-label={`使用 ${preferredClientLabel} 打开`} title={`使用 ${preferredClientLabel} 打开`} disabled={busy || preferredClient?.available === false} onClick={() => void launch()}><ClientIcon clientId={preferredClientId} className="text-white" /></Button><DropdownMenu><DropdownMenuTrigger asChild><Button className={launcherButtonClassName} variant="ghost" size="icon-sm" aria-label="切换全局默认打开方式" title="切换全局默认打开方式"><ChevronDownIcon /></Button></DropdownMenuTrigger><DropdownMenuContent className="min-w-48" align="end">{clients.map((client) => <DropdownMenuItem key={client.id} disabled={!client.available} onSelect={() => selectPreferredClient(client)}><ClientIcon clientId={client.id} />{client.label}{client.id === preferredClientId && <CheckIcon className="ml-auto" />}</DropdownMenuItem>)}</DropdownMenuContent></DropdownMenu></ButtonGroup>;
}

const CLIENT_VISUALS: Record<SshExternalClientId, { icon: LucideIcon; className: string; label: string }> = {
  systemTerminal: { icon: TerminalIcon, className: 'text-foreground', label: '系统终端' },
  vscode: { icon: Code2Icon, className: 'text-blue-600 dark:text-blue-400', label: 'VS Code' },
  copyCommand: { icon: CopyIcon, className: 'text-emerald-600 dark:text-emerald-400', label: '复制 SSH 命令' },
};

function ClientIcon({ clientId, className }: { clientId: SshExternalClientId; className?: string }) {
  const visual = CLIENT_VISUALS[clientId];
  const Icon = visual.icon;
  return <Icon className={cn(visual.className, className)} />;
}
