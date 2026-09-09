import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import type { LanSyncStatus, LanSyncConflict, LanTrustedPeer } from '../../../shared/contracts';

const labels: Record<LanSyncStatus['peers'][number]['state'], string> = {
  disabled: '自动同步已关闭', offline: '等待对端上线并解锁', 'waiting-unlock': '等待解锁',
  syncing: '正在同步', synced: '已同步', failed: '同步失败，可重试',
};

export function LanSyncPanel({ trusted }: { trusted: LanTrustedPeer[] }) {
  const [status, setStatus] = useState<LanSyncStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [enablePeer, setEnablePeer] = useState<LanTrustedPeer | null>(null);
  const [conflicts, setConflicts] = useState<LanSyncConflict[] | null>(null);
  const [restore, setRestore] = useState<LanSyncConflict | null>(null);
  const [busy, setBusy] = useState(false);
  const [clear, setClear] = useState(false);
  useEffect(() => {
    let active = true;
    const refresh = () => { void window.vaultMesh.lan.syncStatus().then((value) => {
      if (active) { setStatus(value); setError(null); }
    }).catch(() => { if (active) setError('无法读取同步状态。'); }); };
    refresh(); const timer = window.setInterval(refresh, 2_000);
    return () => { active = false; window.clearInterval(timer); };
  }, []);
  const run = async (action: () => Promise<unknown>) => {
    if (busy) return;
    setBusy(true);
    try { await action(); setStatus(await window.vaultMesh.lan.syncStatus()); if (conflicts) setConflicts(await window.vaultMesh.lan.syncConflicts()); }
    catch (reason) { toast.error(reason instanceof Error ? reason.message : '同步操作失败。'); }
    finally { setBusy(false); }
  };
  return <Card aria-label="局域网自动同步">
    <CardHeader><CardTitle>自动同步</CardTitle><CardDescription>已授权设备在同一局域网且双方保险库解锁时自动双向合并，离开此页面仍继续。各设备保留自己的主密码。邮件授权和设备权限保持本地；旧 Passkey 仅在本机使用。</CardDescription></CardHeader>
    <CardContent className="grid gap-4">
      {error ? <p role="status" className="text-sm text-destructive">{error}</p> : null}
      {!trusted.length ? <p className="text-sm text-muted-foreground">配对设备后即可自动同步。</p> : trusted.map((peer) => {
        const sync = status?.peers.find((p) => p.peerRef === peer.pairingRef);
        return <div key={peer.pairingRef} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3">
          <div><p className="font-medium">{peer.label}</p><p className="text-sm text-muted-foreground">{sync ? labels[sync.state] : '读取同步状态中'}</p>{sync?.lastSuccessAt ? <p className="text-xs text-muted-foreground">上次成功：{new Date(sync.lastSuccessAt).toLocaleString()}</p> : null}</div>
          <div className="flex gap-2"><Button type="button" variant="outline" disabled={busy || !sync} aria-label={`${sync?.enabled ? '关闭' : '开启'} ${peer.label} 自动同步`} onClick={() => sync?.enabled ? void run(() => window.vaultMesh.lan.disableSync(peer.pairingRef)) : setEnablePeer(peer)}>{sync?.enabled ? '关闭自动同步' : '授权自动同步'}</Button>
          {sync?.enabled ? <Button type="button" variant="outline" disabled={busy} onClick={() => void run(() => window.vaultMesh.lan.retrySync(peer.pairingRef))}>立即重试</Button> : null}</div>
        </div>;
      })}
      <Button type="button" variant="outline" disabled={busy} onClick={() => void run(async () => { setConflicts(await window.vaultMesh.lan.syncConflicts()); })}>冲突历史（{status?.conflictCount ?? 0}）</Button>
      {conflicts ? <div className="grid gap-2" aria-label="同步冲突历史">{conflicts.length ? conflicts.map((item) => <div key={item.id} className="flex items-center justify-between gap-3 rounded-lg border p-3"><span className="text-sm">{item.kind} · {new Date(item.savedAt).toLocaleString()}</span><Button type="button" variant="outline" disabled={busy} onClick={() => setRestore(item)}>恢复此版本</Button></div>) : <p className="text-sm text-muted-foreground">没有冲突历史。</p>}</div> : null}
      {conflicts?.length ? <Button type="button" variant="outline" disabled={busy} onClick={() => setClear(true)}>清空冲突历史</Button> : null}
      <p className="text-xs text-muted-foreground">关闭同步或撤销配对会停止后续传输，各端已保存的数据仍保留。</p>
    </CardContent>
    <AlertDialog open={enablePeer !== null} onOpenChange={(open) => { if (!open) setEnablePeer(null); }}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>授权自动同步</AlertDialogTitle><AlertDialogDescription>允许与 {enablePeer?.label} 双向同步当前保险库的全部适用凭据及组织信息。同名但独立创建的条目会保留；同条目冲突自动选取最后修改版本，另一版保留在历史中。旧配对设备也需要在对端确认一次。</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>取消</AlertDialogCancel><AlertDialogAction onClick={() => { const peer = enablePeer; setEnablePeer(null); if (peer) void run(() => window.vaultMesh.lan.enableSync(peer.pairingRef)); }}>授权并启用</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    <AlertDialog open={clear} onOpenChange={setClear}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>清空冲突历史</AlertDialogTitle><AlertDialogDescription>这些历史版本将被永久删除。清理标记会同步到已授权设备，离线设备重新连接也不会恢复已清理的版本。</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>取消</AlertDialogCancel><AlertDialogAction onClick={() => { setClear(false); void run(() => window.vaultMesh.lan.clearSyncConflicts()); }}>永久清空</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    <AlertDialog open={restore !== null} onOpenChange={(open) => { if (!open) setRestore(null); }}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>恢复历史版本</AlertDialogTitle><AlertDialogDescription>此操作会替换当前条目，并作为一次新修改同步到已授权设备。</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>取消</AlertDialogCancel><AlertDialogAction onClick={() => { const item = restore; setRestore(null); if (item) void run(() => window.vaultMesh.lan.restoreSyncConflict(item.id)); }}>恢复并同步</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
  </Card>;
}
