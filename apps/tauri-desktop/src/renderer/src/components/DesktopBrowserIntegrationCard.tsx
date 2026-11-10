import { useEffect, useState } from 'react';
import {
  AlertTriangleIcon,
  CableIcon,
  CheckCircle2Icon,
  ExternalLinkIcon,
  RotateCwIcon,
  XCircleIcon,
} from 'lucide-react';
import { toast } from 'sonner';

import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import type { DesktopBrowserIntegrationStatus } from '../../../shared/contracts';

const errorMessages: Record<NonNullable<DesktopBrowserIntegrationStatus['errorCode']>, string> = {
  'pairing-unavailable': '无法读取或创建浏览器配对凭据。',
  'broker-unavailable': '浏览器 RPC Broker 无法启动。',
  'listener-unavailable': 'Windows 浏览器通信管道无法启动。',
  'listener-stopped': 'Windows 浏览器通信管道已经停止。',
  'host-missing': '安装包中缺少 Browser Native Host。',
  'registration-unavailable': '无法注册 Chrome/Edge Browser Native Host。',
  'identity-invalid': '扩展 ID 构建配置无效。',
};

export function DesktopBrowserIntegrationCard() {
  const [status, setStatus] = useState<DesktopBrowserIntegrationStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void window.vaultMesh.desktop.browserIntegrationStatus()
      .then(setStatus)
      .catch((reason) => {
        toast.error(reason instanceof Error ? reason.message : '无法读取浏览器集成状态。');
      });
  }, []);

  if (status && !status.supported) return null;

  const retry = async (): Promise<void> => {
    setBusy(true);
    try {
      const next = await window.vaultMesh.desktop.retryBrowserIntegration();
      setStatus(next);
      if (next.ready) toast.success('Chrome/Edge 插件连接服务已就绪。');
      else toast.error(next.errorCode ? errorMessages[next.errorCode] : '浏览器集成仍不可用。');
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : '浏览器集成重试失败。');
    } finally {
      setBusy(false);
    }
  };

  const openStore = async (browserId: string): Promise<void> => {
    try {
      await window.vaultMesh.desktop.openBrowserStore(browserId);
      toast.success('正在调起浏览器打开扩展商店…');
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : '打开扩展商店失败。');
    }
  };

  const summary = status?.ready
    ? 'Chrome/Edge 插件连接服务已就绪。'
    : status?.errorCode
      ? errorMessages[status.errorCode]
      : '正在检查浏览器连接与 Doctor 状态…';

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><CableIcon />浏览器连接与 Doctor 诊断</CardTitle>
        <CardDescription>{summary}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {status?.checkItems && status.checkItems.length > 0 ? (
          <div className="space-y-2 rounded-md border p-3 bg-muted/30">
            <div className="text-xs font-semibold text-muted-foreground">Doctor 连通性体检</div>
            <div className="space-y-2">
              {status.checkItems.map((item) => (
                <div key={item.id} className="flex items-start gap-2 text-xs">
                  {item.status === 'ok' ? (
                    <CheckCircle2Icon className="h-4 w-4 text-emerald-500 shrink-0 mt-0.5" />
                  ) : item.status === 'warn' ? (
                    <AlertTriangleIcon className="h-4 w-4 text-amber-500 shrink-0 mt-0.5" />
                  ) : (
                    <XCircleIcon className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
                  )}
                  <div className="flex-1">
                    <span className="font-medium mr-1.5">{item.label}:</span>
                    <span className="text-muted-foreground">{item.message}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : status?.supported ? (
          <div className="space-y-1 text-muted-foreground">
            <p>通信管道：{status.brokerReady ? '正常' : '不可用'}</p>
            <p>Chrome/Edge Host：{status.hostRegistered ? '已注册' : '未注册'}</p>
            <p className="break-all">扩展 ID：{status.extensionId || '配置无效'}</p>
          </div>
        ) : null}

        {status?.browsers && status.browsers.length > 0 ? (
          <div className="space-y-2 rounded-md border p-3 bg-muted/30">
            <div className="text-xs font-semibold text-muted-foreground">支持的浏览器与插件状态</div>
            <div className="divide-y divide-border/50">
              {status.browsers.map((browser) => (
                <div key={browser.id} className="flex items-center justify-between py-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{browser.name}</span>
                    {browser.installed ? (
                      browser.extensionInstalled ? (
                        <Badge variant="outline" className="text-[10px] text-emerald-600 border-emerald-500/30">
                          插件已安装
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="text-[10px]">
                          未检测到插件
                        </Badge>
                      )
                    ) : (
                      <span className="text-muted-foreground text-[11px]">未安装此浏览器</span>
                    )}
                  </div>
                  {browser.installed && !browser.extensionInstalled ? (
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs px-2"
                      onClick={() => void openStore(browser.id)}
                    >
                      <ExternalLinkIcon className="h-3 w-3 mr-1" />
                      {browser.id === 'chrome' ? '去插件市场安装' : '前往 Release 下载'}
                    </Button>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}

        <Button
          type="button"
          variant="outline"
          disabled={busy || status === null}
          onClick={() => void retry()}
        >
          <RotateCwIcon className={busy ? 'animate-spin' : undefined} />
          重新检查并修复
        </Button>
      </CardContent>
    </Card>
  );
}
