import { useEffect, useMemo, useState } from 'react';
import { CheckIcon, Link2Icon, RadioTowerIcon, RefreshCwIcon, ShieldCheckIcon, UnplugIcon } from 'lucide-react';
import { toast } from 'sonner';

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import type { LanPairingStatus, LanTrustedPeer } from '../../../shared/contracts';

function remainingLabel(expiresAt: number | null): string {
  if (expiresAt === null) return '';
  const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1_000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

function shortPeer(reference: string): string {
  return reference.slice(-6).toUpperCase();
}

export function NearbyDevicesPage() {
  const [status, setStatus] = useState<LanPairingStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [revokePeer, setRevokePeer] = useState<LanTrustedPeer | null>(null);
  const [editingPeer, setEditingPeer] = useState<string | null>(null);
  const [label, setLabel] = useState('');

  const refresh = async (): Promise<void> => {
    setStatus(await window.vaultMesh.lan.status());
  };

  useEffect(() => {
    let mounted = true;
    void window.vaultMesh.lan.status().then((next) => {
      if (mounted) setStatus(next);
    }).catch(() => {
      if (mounted) toast.error('无法读取附近设备状态。');
    });
    const timer = window.setInterval(() => {
      void window.vaultMesh.lan.status().then((next) => {
        if (mounted) setStatus(next);
      }).catch(() => undefined);
    }, 1_000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
      void window.vaultMesh.lan.stopDiscovery().catch(() => undefined);
    };
  }, []);

  const trustedByRef = useMemo(
    () => new Map(status?.trusted.map((peer) => [peer.pairingRef, peer]) ?? []),
    [status?.trusted],
  );

  const run = async (action: () => Promise<void>, success?: string): Promise<void> => {
    if (busy) return;
    setBusy(true);
    try {
      await action();
      await refresh();
      if (success) toast.success(success);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : '附近设备操作失败。');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="mx-auto grid w-full max-w-5xl gap-5 px-5 py-8" aria-label="附近设备管理">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><RadioTowerIcon />局域网发现</CardTitle>
          <CardDescription>发现默认关闭。每次最多开启 10 分钟；离开此页面、锁屏、休眠或退出应用会立即停止。</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={status?.discoverable ? 'default' : 'outline'}>{status?.discoverable ? '可被发现' : '发现已关闭'}</Badge>
            {status?.discoverable ? <span className="text-xs text-muted-foreground">剩余 {remainingLabel(status.expiresAt)}</span> : null}
          </div>
          <p className="text-sm text-muted-foreground">广播不包含主机名、账号、保险库元数据或秘密。配对只验证另一台 VaultMesh 客户端的设备身份。</p>
        </CardContent>
        <CardFooter className="flex flex-wrap gap-2">
          {status?.discoverable ? (
            <>
              <Button variant="outline" type="button" disabled={busy} onClick={() => void run(async () => { setStatus(await window.vaultMesh.lan.scan()); })}>
                <RefreshCwIcon data-icon="inline-start" />立即扫描
              </Button>
              <Button variant="destructive" type="button" disabled={busy} onClick={() => void run(async () => { setStatus(await window.vaultMesh.lan.stopDiscovery()); }, '附近设备发现已停止。')}>
                <UnplugIcon data-icon="inline-start" />停止发现
              </Button>
            </>
          ) : (
            <Button type="button" disabled={busy} onClick={() => void run(async () => { setStatus(await window.vaultMesh.lan.startDiscovery()); }, '附近设备发现已开启 10 分钟。')}>
              <RadioTowerIcon data-icon="inline-start" />开启 10 分钟
            </Button>
          )}
        </CardFooter>
      </Card>

      {status?.pending.map((pending) => (
        <Card key={pending.pairingRef} className="ring-2 ring-primary/40">
          <CardHeader>
            <CardTitle>配对请求：核对安全短码</CardTitle>
            <CardDescription>这与蓝牙数字比较相同：确认另一台设备显示完全相同的六码，再在两台设备上分别确认。任何差异都必须取消。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            <div className="rounded-xl bg-muted px-4 py-5 text-center font-mono text-4xl font-semibold tracking-[0.3em]" aria-label={`安全短码 ${pending.safetyCode}`}>
              {pending.safetyCode}
            </div>
            <p className="text-center text-xs text-muted-foreground">设备 {shortPeer(pending.pairingRef)} · {remainingLabel(pending.expiresAt)} 后失效</p>
          </CardContent>
          <CardFooter className="flex gap-2">
            <Button variant="outline" type="button" disabled={busy} onClick={() => void run(() => window.vaultMesh.lan.cancel(pending.pairingRef).then(() => undefined), '配对已取消。')}>取消</Button>
            <Button type="button" disabled={busy} onClick={() => void run(() => window.vaultMesh.lan.confirm(pending.pairingRef).then(() => undefined), '已确认；正在等待另一台设备确认。')}>
              <CheckIcon data-icon="inline-start" />短码一致
            </Button>
          </CardFooter>
        </Card>
      ))}

      <div className="grid gap-5 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>发现的设备</CardTitle>
            <CardDescription>任一端点击一次“配对”即可，对端会自动显示同一短码；即使两端同时点击，也会自动合并为一个请求。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            {status?.nearby.length ? status.nearby.map((device) => {
              const trusted = trustedByRef.get(device.pairingRef);
              const connecting = device.status === 'connecting';
              const confirming = device.status === 'confirming';
              return (
                <div key={device.pairingRef} className="flex items-center justify-between gap-3 rounded-lg border p-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{trusted?.label ?? `VaultMesh ${shortPeer(device.pairingRef)}`}</p>
                    <p className="text-xs text-muted-foreground">{device.status === 'connected' ? '已通过证书固定验证连通' : connecting ? '正在建立加密连接并生成安全短码' : confirming ? '本机已确认，正在等待另一台设备' : device.status === 'failed' ? '配对未完成，请重试' : trusted ? '已信任，等待双方重连' : '尚未验证'}</p>
                  </div>
                  {device.status === 'connected' ? <Badge><ShieldCheckIcon data-icon="inline-start" />已验证</Badge> : connecting ? <Badge variant="outline"><RefreshCwIcon className="animate-spin" data-icon="inline-start" />正在配对</Badge> : confirming ? <Badge variant="outline"><RefreshCwIcon className="animate-spin" data-icon="inline-start" />等待确认</Badge> : trusted ? <Badge variant="outline">等待重连</Badge> : (
                    <Button size="sm" type="button" disabled={busy || status.pending.some((item) => item.pairingRef === device.pairingRef)} onClick={() => void run(() => window.vaultMesh.lan.begin(device.pairingRef).then(() => undefined))}>
                      <Link2Icon data-icon="inline-start" />配对
                    </Button>
                  )}
                </div>
              );
            }) : <p className="text-sm text-muted-foreground">{status?.discoverable ? '尚未发现兼容设备。请在另一台设备上也开启“附近设备”。' : '开启发现后才能扫描附近设备。'}</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>已配对设备</CardTitle>
            <CardDescription>信任关系保存在系统凭据库中；不会自动广播、解锁保险库或恢复旧会话。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            {status?.trusted.length ? status.trusted.map((peer) => (
              <div key={peer.pairingRef} className="grid gap-3 rounded-lg border p-3">
                {editingPeer === peer.pairingRef ? (
                  <form className="flex gap-2" onSubmit={(event) => {
                    event.preventDefault();
                    void run(() => window.vaultMesh.lan.rename(peer.pairingRef, label.trim()).then(() => undefined), '设备名称已更新。').then(() => setEditingPeer(null));
                  }}>
                    <Input value={label} maxLength={64} autoFocus aria-label="设备名称" onChange={(event) => setLabel(event.target.value)} />
                    <Button size="sm" type="submit" disabled={busy || !label.trim()}>保存</Button>
                  </form>
                ) : (
                  <div>
                    <p className="font-medium">{peer.label}</p>
                    <p className="text-xs text-muted-foreground">协议 v{peer.protocolMajor} · 设备 {shortPeer(peer.pairingRef)}</p>
                  </div>
                )}
                <div className="flex gap-2">
                  <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => { setEditingPeer(peer.pairingRef); setLabel(peer.label); }}>重命名</Button>
                  <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => setRevokePeer(peer)}>撤销信任</Button>
                </div>
              </div>
            )) : <p className="text-sm text-muted-foreground">还没有已配对设备。</p>}
          </CardContent>
        </Card>
      </div>

      <Card size="sm">
        <CardHeader>
          <CardTitle>能力边界</CardTitle>
          <CardDescription>附近设备只完成发现、双向验证、信任保存和连通性确认；不支持 Vault 同步、秘密传输、分享、远程操作、账号、云服务或端口映射。</CardDescription>
        </CardHeader>
        <CardFooter>
          <Button variant="outline" asChild><a href="#/">返回 VaultMesh</a></Button>
        </CardFooter>
      </Card>

      <AlertDialog open={revokePeer !== null} onOpenChange={(open) => { if (!open) setRevokePeer(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>撤销 {revokePeer?.label} 的信任？</AlertDialogTitle>
            <AlertDialogDescription>这会删除本机保存的验证材料并断开当前会话。另一台设备仍需要在其本机单独撤销。</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={busy}>取消</AlertDialogCancel>
            <AlertDialogAction variant="destructive" disabled={busy} onClick={() => {
              const peer = revokePeer;
              if (!peer) return;
              void run(() => window.vaultMesh.lan.revoke(peer.pairingRef).then(() => undefined), '本机设备信任已撤销。').then(() => setRevokePeer(null));
            }}>撤销信任</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </section>
  );
}
