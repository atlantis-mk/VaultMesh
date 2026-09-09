import { useEffect, useMemo, useState } from 'react';
import { Link2Icon, RadioTowerIcon, RefreshCwIcon, ShieldCheckIcon, UnplugIcon } from 'lucide-react';
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
  const [pairingPeer, setPairingPeer] = useState<string | null>(null);
  const [pairingCode, setPairingCode] = useState('');

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
          {status?.discoverable && status.pairingCode ? (
            <div className="grid gap-2 rounded-xl bg-muted px-4 py-5 text-center">
              <p className="text-xs font-medium text-muted-foreground">本机配对码</p>
              <div className="font-mono text-4xl font-semibold tracking-[0.3em]" aria-label={`本机配对码 ${status.pairingCode}`}>{status.pairingCode}</div>
              <p className="text-xs text-muted-foreground">在另一台设备选择本机并输入此码，验证成功后会自动完成配对。</p>
            </div>
          ) : status?.discoverable ? (
            <p className="text-sm text-destructive">错误尝试次数过多。请停止发现后重新开启，以生成新的配对码。</p>
          ) : null}
          <p className="text-sm text-muted-foreground">配对码不会广播、记录或持久化。广播也不包含主机名、账号、保险库元数据或秘密。</p>
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

      {pairingPeer ? (
        <Card className="ring-2 ring-primary/40">
          <form onSubmit={(event) => {
            event.preventDefault();
            const target = pairingPeer;
            const code = pairingCode;
            void run(async () => {
              await window.vaultMesh.lan.begin(target, code);
              setPairingPeer(null);
              setPairingCode('');
            }, '配对码已提交，正在安全验证。');
          }}>
            <CardHeader>
              <CardTitle>输入另一台设备的配对码</CardTitle>
              <CardDescription>请输入设备 {shortPeer(pairingPeer)} 当前显示的六码。正确后两端会自动完成，不需要再次确认。</CardDescription>
            </CardHeader>
            <CardContent>
              <Input
                value={pairingCode}
                autoFocus
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={6}
                pattern="[0-9]{6}"
                placeholder="000000"
                aria-label="六位配对码"
                className="text-center font-mono text-2xl tracking-[0.3em]"
                onChange={(event) => setPairingCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
              />
            </CardContent>
            <CardFooter className="flex gap-2">
              <Button variant="outline" type="button" disabled={busy} onClick={() => { setPairingPeer(null); setPairingCode(''); }}>取消</Button>
              <Button type="submit" disabled={busy || !/^\d{6}$/.test(pairingCode)}><Link2Icon data-icon="inline-start" />开始配对</Button>
            </CardFooter>
          </form>
        </Card>
      ) : null}

      <div className="grid gap-5 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>发现的设备</CardTitle>
            <CardDescription>查看另一台设备显示的本机配对码，选择对应设备并输入该六码。</CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3">
            {status?.nearby.length ? status.nearby.map((device) => {
              const trusted = trustedByRef.get(device.pairingRef);
              const connecting = device.status === 'connecting';
              return (
                <div key={device.pairingRef} className="flex items-center justify-between gap-3 rounded-lg border p-3">
                  <div className="min-w-0">
                    <p className="truncate font-medium">{trusted?.label ?? `VaultMesh ${shortPeer(device.pairingRef)}`}</p>
                    <p className="text-xs text-muted-foreground">{device.status === 'connected' ? '已通过证书固定验证连通' : connecting ? '正在验证配对码并建立信任' : device.status === 'code-rejected' ? '配对码不正确或安全验证失败' : device.status === 'local-storage-failed' ? '本机无法安全保存设备信任' : device.status === 'peer-storage-failed' ? '另一台设备无法安全保存信任' : device.status === 'transport-failed' ? '无法连接该设备，请检查双方防火墙和局域网访问权限' : device.status === 'certificate-exchange-failed' ? '设备证书交换失败，请重新开启发现后再试' : device.status === 'tls-failed' ? 'TLS 握手失败，请检查系统时间和安全软件' : device.status === 'protocol-failed' ? '配对协议握手失败，请确认两端版本一致' : device.status === 'discovery-changed' ? '设备发现信息已变化，请重新扫描' : device.status === 'identity-changed' ? '设备证书与本机旧信任不一致，请先撤销该设备' : device.status === 'peer-identity-rejected' ? '另一台设备拒绝了本机身份，请在对端撤销旧信任' : device.status === 'local-trust-state-failed' ? '本机无法读取设备信任状态' : device.status === 'code-attempts-exhausted' ? '对端配对码尝试次数已用完，请重新开启发现' : device.status === 'persistence-sync-failed' ? '双方未能确认信任保存结果，请重试' : device.status === 'secure-channel-failed' ? '安全连接在完成前中断，请重试' : trusted ? '已信任，等待双方重连' : '尚未验证'}</p>
                  </div>
                  {device.status === 'connected' ? <Badge><ShieldCheckIcon data-icon="inline-start" />已验证</Badge> : connecting ? <Badge variant="outline"><RefreshCwIcon className="animate-spin" data-icon="inline-start" />正在配对</Badge> : trusted ? <Badge variant="outline">等待重连</Badge> : (
                    <Button size="sm" type="button" disabled={busy} onClick={() => { setPairingPeer(device.pairingRef); setPairingCode(''); }}>
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
