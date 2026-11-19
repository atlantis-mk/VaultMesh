import { Outlet, useLocation, useNavigate } from '@tanstack/react-router';
import { ArrowLeftIcon, FingerprintIcon, LockKeyholeIcon, MailCheckIcon, ShieldCheckIcon, UploadIcon, SettingsIcon } from 'lucide-react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';

import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { useVaultStore } from '@/stores/vault-store';
import type { ImportPreview, ImportSource } from '../../../shared/contracts';
import { AddItemMenu } from '@/components/AddItemMenu';
import { SshKeyScanDialog } from '@/components/SshKeyScanDialog';

const importSources: Array<{ id: ImportSource; label: string }> = [
  { id: 'chromium', label: 'Chrome / Chromium' },
  { id: 'edge', label: 'Microsoft Edge' },
  { id: 'firefox', label: 'Firefox' },
  { id: 'safari', label: 'Safari' },
  { id: 'onePassword', label: '1Password' },
  { id: 'bitwarden', label: 'Bitwarden' },
  { id: 'lastPass', label: 'LastPass' },
  { id: 'dashlane', label: 'Dashlane' },
  { id: 'keepass', label: 'KeePass / KeePassXC' },
  { id: 'csv', label: '通用 CSV' },
];

interface VaultPageHeader {
  title: string;
  description: string;
}

export function agentPairingUsesMainWindow(): false {
  return false;
}

export function isFocusedLoginEditor(pathname: string): boolean {
  return /^\/vault\/items\/(?:new|[^/]+)$/.test(pathname);
}

export function isFocusedItemEditor(pathname: string): boolean {
  return /^\/vault\/(?:items|cards|ssh|identities|secrets)\/(?:new|[^/]+)$/.test(pathname);
}

export function usesViewportShell(pathname: string): boolean {
  return isFocusedItemEditor(pathname) || pathname === '/vault/services';
}

export function getVaultPageHeader(pathname: string): VaultPageHeader | null {
  if (pathname === '/nearby') {
    return { title: '附近设备', description: '发现并验证同一局域网中的 VaultMesh 桌面端' };
  }
  if (pathname === '/vault/security/agent') {
    return { title: '本地 Agent 能力代理', description: '管理 MCP 解锁、授权、连接与审计' };
  }
  if (pathname === '/vault/security') {
    return { title: '安全中心', description: '备份、恢复与凭据安全' };
  }
  if (pathname === '/vault/email-otp') {
    return { title: '邮箱验证码', description: '连接邮箱并读取最近的一次性验证码' };
  }
  if (pathname === '/vault/services') {
    return { title: '网站 / 服务', description: '按服务聚合账号、密钥与 SSH 凭据' };
  }

  const isNew = pathname.endsWith('/new');
  if (/^\/vault\/items\/(?:new|[^/]+)$/.test(pathname)) {
    return { title: isNew ? '新增登录' : '编辑登录信息', description: '将凭据及附加信息保存在加密保险库中。' };
  }
  if (/^\/vault\/cards\/(?:new|[^/]+)$/.test(pathname)) {
    return { title: isNew ? '新增支付卡' : '编辑支付卡', description: '卡号、安全码和 PIN 只保存在本地加密保险库中。' };
  }
  if (/^\/vault\/ssh\/(?:new|[^/]+)$/.test(pathname)) {
    return { title: isNew ? '添加 SSH 凭据' : '编辑 SSH 凭据', description: '密码、私钥和密钥口令只保存在加密载荷中。' };
  }
  if (/^\/vault\/identities\/(?:new|[^/]+)$/.test(pathname)) {
    return { title: isNew ? '新增身份' : '编辑身份', description: '联系方式与地址仅保存在本地加密保险库中。' };
  }
  if (/^\/vault\/secrets\/(?:new|[^/]+)$/.test(pathname)) {
    return { title: isNew ? '新增机密信息' : '编辑机密信息', description: '保存 API Key、访问令牌、安全笔记及其他机密信息。' };
  }
  return null;
}

export function AppShell() {
  const status = useVaultStore((state) => state.status);
  const busy = useVaultStore((state) => state.busy);
  const biometric = useVaultStore((state) => state.biometric);
  const lockVault = useVaultStore((state) => state.lockVault);
  const enableBiometric = useVaultStore((state) => state.enableBiometric);
  const disableBiometric = useVaultStore((state) => state.disableBiometric);
  const selectImport = useVaultStore((state) => state.selectImport);
  const commitImport = useVaultStore((state) => state.commitImport);
  const cancelImport = useVaultStore((state) => state.cancelImport);
  const navigate = useNavigate();
  const pathname = useLocation({ select: (location) => location.pathname });
  const isSecurityCenter = pathname.startsWith('/vault/security');
  const isSecuritySubpage = pathname === '/vault/security/agent' || pathname === '/nearby';
  const isEmailOtp = pathname === '/vault/email-otp';
  const isItemEditor = isFocusedItemEditor(pathname);
  const isCompactUnlock = pathname === '/unlock';
  const isViewportShell = usesViewportShell(pathname);
  const pageHeader = getVaultPageHeader(pathname);
  const [selectingImport, setSelectingImport] = useState(false);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);

  useEffect(() => {
    if (!isCompactUnlock) {
      void window.vaultMesh?.desktop?.setCompactWindowMode?.(false).catch(() => {});
    }
  }, [isCompactUnlock]);

  const lock = async (): Promise<void> => {
    if (await lockVault()) {
      void navigate({ to: '/unlock', replace: true });
    }
  };

  const toggleBiometric = async (): Promise<void> => {
    if (biometric?.enabled) {
      await disableBiometric();
    } else {
      await enableBiometric();
    }
  };

  const chooseImportSource = async (source: ImportSource): Promise<void> => {
    setSelectingImport(false);
    const preview = await selectImport(source);
    if (preview) setImportPreview(preview);
  };

  const closeImportPreview = (): void => {
    if (importPreview) void cancelImport(importPreview.sessionId);
    setImportPreview(null);
  };

  const importItems = async (): Promise<void> => {
    if (!importPreview) return;
    const result = await commitImport(importPreview.sessionId);
    setImportPreview(null);
    if (result) {
      const parts = [
        result.loginCount ? `${result.loginCount} 条登录信息` : '',
        result.paymentCardCount ? `${result.paymentCardCount} 张支付卡` : '',
        result.sshCredentialCount ? `${result.sshCredentialCount} 条 SSH 凭据` : '',
      ].filter(Boolean);
      toast.success(`已导入 ${parts.join('、')}。`);
    }
  };

  return (
    <main
      className={cn(
        'bg-background text-foreground',
        isViewportShell ? 'flex h-svh w-full flex-col overflow-hidden' : isCompactUnlock ? 'mx-auto w-full max-w-[460px] overflow-x-hidden' : 'min-h-svh',
        isItemEditor && 'mx-auto max-w-6xl',
      )}
      data-viewport-shell={isViewportShell ? 'true' : undefined}
    >
      {status?.unlocked ? (
        <header className="sticky top-0 z-40 shrink-0 border-b bg-background/80 backdrop-blur">
          <div className={cn('flex h-16 w-full items-center justify-between px-5', !isItemEditor && 'mx-auto max-w-6xl')}>
            {pageHeader ? (
              <div className="flex items-center gap-3">
                <Button
                  variant="ghost"
                  size="icon"
                  type="button"
                  aria-label={isSecuritySubpage ? '返回安全中心' : '返回保险库'}
                  onClick={() => void navigate({ to: pathname === '/nearby' ? '/vault/security' : isSecuritySubpage ? '/vault/security' : '/vault' })}
                >
                  <ArrowLeftIcon />
                </Button>
                <div>
                  <strong className="block text-sm font-semibold">{pageHeader.title}</strong>
                  <span className="block text-xs text-muted-foreground">{pageHeader.description}</span>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <span className="grid size-9 place-items-center rounded-lg bg-primary text-primary-foreground" aria-hidden="true">
                  <ShieldCheckIcon />
                </span>
                <div>
                  <strong className="block text-sm font-semibold">VaultMesh</strong>
                  <span className="block text-xs text-muted-foreground">本地保险库</span>
                </div>
              </div>
            )}
            <div className="flex items-center gap-2">
              {!isItemEditor && (
                <>
                  {biometric?.available ? (
                    <Button variant="outline" size="sm" type="button" disabled={busy} onClick={() => void toggleBiometric()}>
                      <FingerprintIcon data-icon="inline-start" />
                      {biometric.enabled ? '关闭 Touch ID' : '启用 Touch ID'}
                    </Button>
                  ) : null}
                  <Button variant="outline" size="sm" type="button" disabled={busy} onClick={() => setSelectingImport(true)}>
                    <UploadIcon data-icon="inline-start" />
                    导入
                  </Button>
                  <SshKeyScanDialog />
                  {!isEmailOtp ? (
                    <Button variant="outline" size="sm" type="button" disabled={busy} onClick={() => void navigate({ to: '/vault/email-otp' })}>
                      <MailCheckIcon data-icon="inline-start" />邮箱验证码
                    </Button>
                  ) : null}
                  {!isSecurityCenter ? (
                    <Button variant="outline" size="sm" type="button" disabled={busy} onClick={() => void navigate({ to: '/vault/security' })}>
                      <SettingsIcon data-icon="inline-start" />安全中心
                    </Button>
                  ) : null}
                  <AddItemMenu size="sm" />
                </>
              )}
              <Button variant="outline" size="sm" type="button" disabled={busy} onClick={() => void lock()}>
                <LockKeyholeIcon data-icon="inline-start" />
                锁定
              </Button>
            </div>
          </div>
        </header>
      ) : null}
      <Outlet />
      <AlertDialog open={selectingImport} onOpenChange={setSelectingImport}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>从其他软件导入</AlertDialogTitle>
            <AlertDialogDescription>选择导出文件的来源。除 Bitwarden 支持 JSON 或 CSV 外，其余来源使用 CSV 导出文件。</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid grid-cols-2 gap-2">
            {importSources.map((source) => (
              <Button key={source.id} variant="outline" type="button" className="justify-start" disabled={busy} onClick={() => void chooseImportSource(source.id)}>
                {source.label}
              </Button>
            ))}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>取消</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <AlertDialog open={importPreview !== null} onOpenChange={(open) => { if (!open) closeImportPreview(); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认导入 {importPreview?.importableCount ?? 0} 条记录</AlertDialogTitle>
            <AlertDialogDescription>
              {importPreview?.fileName} 中有 {importPreview?.importableCount ?? 0} 条可导入记录。
              {(importPreview?.paymentCardCount ?? 0) > 0 ? ` 包含 ${importPreview?.loginCount ?? 0} 条登录信息和 ${importPreview?.paymentCardCount ?? 0} 张支付卡。` : ''}
              {(importPreview?.sshCredentialCount ?? 0) > 0 ? ` 包含 ${importPreview?.sshCredentialCount ?? 0} 条 SSH 凭据。` : ''}
              {(importPreview?.skippedCount ?? 0) > 0 ? ` 已跳过 ${importPreview?.skippedCount} 条无效或不支持的记录。` : ''}
              密码和卡号不会显示在此预览中。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="max-h-52 overflow-y-auto rounded-md border border-border">
            {importPreview?.items.map((item) => (
              <div key={`${item.type}-${item.title}-${item.detail}`} className="border-b border-border px-3 py-2 text-sm last:border-0">
                <p className="truncate font-medium">{item.title}</p>
                <p className="truncate text-muted-foreground">{item.type === 'paymentCard' ? '支付卡' : item.type === 'sshCredential' ? 'SSH 凭据' : '登录信息'} · {item.detail || '未填写详情'}</p>
              </div>
            ))}
            {(importPreview?.importableCount ?? 0) > (importPreview?.items.length ?? 0) && (
              <p className="px-3 py-2 text-sm text-muted-foreground">仅显示前 20 条记录。</p>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
            <Button type="button" disabled={busy} onClick={() => void importItems()}>
              <UploadIcon data-icon="inline-start" />
              确认导入
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </main>
  );
}
