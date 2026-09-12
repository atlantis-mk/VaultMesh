import { useEffect, useMemo, useRef, useState } from "react";
import { ArrowLeftIcon, HistoryIcon, RefreshCwIcon, RotateCcwIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { clearRecoveryHistory, emptyRecoveryTrash, getRecoveryHistory, getRecoveryTrash, purgeRecoveryTrash, restoreRecoveryHistory, restoreRecoveryTrash, type RecoverableKind, type RecoveryRevisionSummary, type RecoveryTrashSummary } from "@/lib/desktop-rpc";

export type RecoveryTarget = { id: string; kind: RecoverableKind; title: string; detail: string };

const kindMeta: Record<RecoverableKind, string> = { login: "登录", card: "支付卡", identity: "身份", ssh: "SSH" };

export function RecoveryPanel({ targets, onBack, onChanged }: { targets: RecoveryTarget[]; onBack: () => void; onChanged: () => void | Promise<void> }) {
  const [kind, setKind] = useState<RecoverableKind>("login");
  const [mode, setMode] = useState<"trash" | "history">("trash");
  const [targetId, setTargetId] = useState("");
  const [trash, setTrash] = useState<RecoveryTrashSummary[]>([]);
  const [history, setHistory] = useState<RecoveryRevisionSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const loadSequence = useRef(0);
  const active = useRef(true);
  const availableTargets = useMemo(() => targets.filter((target) => target.kind === kind), [kind, targets]);

  useEffect(() => {
    setTargetId((current) => availableTargets.some((target) => target.id === current) ? current : availableTargets[0]?.id ?? "");
  }, [availableTargets]);

  useEffect(() => { void load(); }, [kind, mode, targetId]);

  useEffect(() => {
    active.current = true;
    const visibilityChanged = () => {
      active.current = !document.hidden;
      loadSequence.current += 1;
      setTrash([]); setHistory([]); setNotice(""); setBusy(false);
      if (active.current) void load();
    };
    document.addEventListener("visibilitychange", visibilityChanged);
    return () => { active.current = false; loadSequence.current += 1; document.removeEventListener("visibilitychange", visibilityChanged); };
  }, []);

  async function load() {
    const sequence = ++loadSequence.current;
    const currentTarget = targetId;
    setBusy(true); setNotice(""); setTrash([]); setHistory([]);
    try {
      const nextTrash = mode === "trash" ? await getRecoveryTrash(kind) : [];
      const nextHistory = mode === "history" && currentTarget ? await getRecoveryHistory(kind, currentTarget) : [];
      if (!active.current || sequence !== loadSequence.current) return;
      setTrash(nextTrash); setHistory(nextHistory);
    } catch (error) {
      if (active.current && sequence === loadSequence.current) setNotice(error instanceof Error ? error.message : "无法读取恢复数据。");
    } finally {
      if (active.current && sequence === loadSequence.current) setBusy(false);
    }
  }

  async function mutate(action: () => Promise<void>, success: string) {
    if (busy) return;
    setBusy(true); setNotice("");
    try { await action(); if (!active.current) return; await onChanged(); if (!active.current) return; await load(); if (active.current) setNotice(success); }
    catch (error) { if (active.current) { setNotice(error instanceof Error ? error.message : "操作未完成；不会自动重试。"); setBusy(false); } }
  }

  return <section className="flex min-h-0 flex-1 flex-col gap-3" aria-label="回收站与历史">
    <div className="flex items-center gap-2"><Button aria-label="返回设置" size="icon-sm" variant="ghost" disabled={busy} onClick={onBack}><ArrowLeftIcon /></Button><h2 className="text-sm font-semibold">回收站与历史</h2><Button className="ml-auto" aria-label="刷新恢复数据" size="icon-sm" variant="ghost" disabled={busy} onClick={() => void load()}><RefreshCwIcon className={busy ? "animate-spin" : ""} /></Button></div>
    <Tabs value={kind} onValueChange={(value) => setKind(value as RecoverableKind)}><TabsList className="grid w-full grid-cols-4">{(Object.keys(kindMeta) as RecoverableKind[]).map((value) => <TabsTrigger key={value} value={value} className="text-xs" disabled={busy}>{kindMeta[value]}</TabsTrigger>)}</TabsList></Tabs>
    <Tabs value={mode} onValueChange={(value) => setMode(value as typeof mode)}><TabsList className="grid w-full grid-cols-2"><TabsTrigger value="trash" disabled={busy}><Trash2Icon size={14} />回收站</TabsTrigger><TabsTrigger value="history" disabled={busy}><HistoryIcon size={14} />历史</TabsTrigger></TabsList></Tabs>
    {notice ? <p className="rounded-lg bg-muted px-3 py-2 text-xs" role="status">{notice}</p> : null}
    {mode === "history" ? <div className="flex flex-col gap-1.5 text-xs"><span id="history-item-label">选择当前项目</span><Select value={targetId || null} disabled={busy} onValueChange={(value) => setTargetId(value ?? "")}><SelectTrigger aria-labelledby="history-item-label"><SelectValue placeholder="没有可用项目" /></SelectTrigger><SelectContent><SelectGroup>{availableTargets.map((target) => <SelectItem key={target.id} value={target.id}>{target.title}</SelectItem>)}</SelectGroup></SelectContent></Select></div> : null}
    <div className="min-h-0 flex-1 space-y-2 overflow-y-auto">
      {mode === "trash" ? trash.map((row) => <RecoveryRow key={row.trashId} title={row.title} detail={row.detail} timestamp={row.deletedAt} actions={<><Button size="xs" variant="outline" disabled={busy} onClick={() => { if (window.confirm(`恢复“${row.title}”？`)) void mutate(() => restoreRecoveryTrash(kind, row.trashId, row.itemId), "项目已恢复。"); }}><RotateCcwIcon />恢复</Button><Button size="xs" variant="destructive" disabled={busy} onClick={() => { if (window.confirm(`永久删除“${row.title}”？此操作无法撤销。`)) void mutate(() => purgeRecoveryTrash(kind, row.trashId), "项目已永久删除。"); }}><Trash2Icon />永久删除</Button></>} />)
        : history.map((row) => <RecoveryRow key={row.revisionId} title={row.title} detail={row.detail} timestamp={row.savedAt} actions={<Button size="xs" variant="outline" disabled={busy} onClick={() => { if (window.confirm(`把“${row.title}”恢复到这个版本？当前版本会进入历史。`)) void mutate(() => restoreRecoveryHistory(kind, row.itemId, row.revisionId), "历史版本已恢复。"); }}><RotateCcwIcon />恢复此版本</Button>} />)}
      {!busy && (mode === "trash" ? trash.length === 0 : history.length === 0) ? <p className="py-8 text-center text-xs text-muted-foreground">{mode === "trash" ? "回收站为空。" : targetId ? "此项目没有历史版本。" : "当前类型没有可查看的项目。"}</p> : null}
    </div>
    {mode === "trash" && trash.length > 0 ? <Button variant="destructive" disabled={busy} onClick={() => { if (window.confirm(`永久删除${kindMeta[kind]}回收站中的全部项目？此操作无法撤销。`)) void mutate(() => emptyRecoveryTrash(kind), "回收站已清空。"); }}>清空{kindMeta[kind]}回收站</Button> : null}
    {mode === "history" && targetId && history.length > 0 ? <Button variant="destructive" disabled={busy} onClick={() => { if (window.confirm("清除此项目的全部历史版本？此操作无法撤销。")) void mutate(() => clearRecoveryHistory(kind, targetId), "历史记录已清空。"); }}>清空此项目历史</Button> : null}
  </section>;
}

function RecoveryRow({ title, detail, timestamp, actions }: { title: string; detail: string; timestamp: number; actions: React.ReactNode }) {
  const milliseconds = timestamp < 10_000_000_000 ? timestamp * 1_000 : timestamp;
  return <Card size="sm"><CardContent className="flex flex-col gap-2"><div><p className="truncate text-sm font-medium">{title}</p>{detail ? <p className="truncate text-xs text-muted-foreground">{detail}</p> : null}<p className="text-[11px] text-muted-foreground">{new Date(milliseconds).toLocaleString()}</p></div><div className="flex flex-wrap gap-2">{actions}</div></CardContent></Card>;
}
