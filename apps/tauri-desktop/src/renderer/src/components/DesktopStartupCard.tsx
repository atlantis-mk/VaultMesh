import { useEffect, useState } from 'react';
import { ExternalLinkIcon, PowerIcon } from 'lucide-react';
import { toast } from 'sonner';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldContent, FieldDescription, FieldLabel } from '@/components/ui/field';
import { Switch } from '@/components/ui/switch';
import type { DesktopStartupSettings } from '../../../shared/contracts';

export function DesktopStartupCard() {
  const [settings, setSettings] = useState<DesktopStartupSettings | null>(null);
  const [busy, setBusy] = useState(false);

  const reload = async (): Promise<void> => {
    setSettings(await window.vaultMesh.desktop.startupSettings());
  };

  useEffect(() => {
    void reload().catch((reason) => {
      toast.error(reason instanceof Error ? reason.message : '无法读取登录时启动设置。');
    });
  }, []);

  const update = async (enabled: boolean): Promise<void> => {
    setBusy(true);
    try {
      const updated = await window.vaultMesh.desktop.updateStartupSettings({ enabled });
      setSettings(updated);
      toast.success(enabled ? '已启用登录时启动。' : '已关闭登录时启动。');
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : '登录时启动设置更新失败。');
      try {
        await reload();
      } catch {
        // Keep the last confirmed state when the OS cannot be queried either.
      }
    } finally {
      setBusy(false);
    }
  };

  const openSystemSettings = async (): Promise<void> => {
    try {
      await window.vaultMesh.desktop.openSystemSettings();
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : '无法打开系统设置。');
    }
  };

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><PowerIcon />系统启动与后台运行</CardTitle>
        <CardDescription>让 VaultMesh 在你登录电脑后保持可用，窗口关闭时保持后台服务常驻。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <Field orientation="horizontal">
          <FieldContent>
            <FieldLabel htmlFor="desktop-start-on-login">登录时启动 VaultMesh</FieldLabel>
            <FieldDescription>启动后保持锁定并静默进入系统托盘，不会弹出主窗口。</FieldDescription>
          </FieldContent>
          <Switch
            id="desktop-start-on-login"
            checked={settings?.enabled ?? false}
            disabled={busy || settings === null}
            onCheckedChange={(enabled) => void update(enabled)}
          />
        </Field>
        {settings?.canOpenSystemSettings ? (
          <div className="pt-3 border-t space-y-2">
            <p className="text-xs text-muted-foreground">
              {settings.systemSettingsHint || '若系统禁用了登录项或后台运行，可前往系统设置开启。'}
            </p>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void openSystemSettings()}
            >
              <ExternalLinkIcon className="h-3.5 w-3.5 mr-1" />
              打开系统后台权限设置
            </Button>
          </div>
        ) : null}
      </CardContent>
    </Card>
  );
}
