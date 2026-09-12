import { useEffect, useState } from "react";
import { ArchiveRestoreIcon, ArrowLeftIcon, ChevronRightIcon, HistoryIcon, LockKeyholeIcon, RefreshCwIcon, SettingsIcon, ShieldCheckIcon, type LucideIcon } from "lucide-react";

import { ToastMessage, type ToastVariant } from "@/components/ToastMessage";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { confirmedDesktopRpc, desktopRpc, getPasswordHealth, getUnlockHistory, type FillEvent, type PasswordHealth, type UnlockEvent } from "@/lib/desktop-rpc";
import {
  loadPluginSecurityPolicy,
  savePluginSecurityPolicy,
  type PluginSecurityPolicy,
} from "@/lib/plugin-security-policy";
import { RecoveryPanel, type RecoveryTarget } from "./recovery-panel";

type PinStatus = { enabled: boolean; locked: boolean; failureLimit: number; remainingAttempts: number };
type BiometricStatus = { available: boolean; enabled: boolean };
type DesktopSecuritySettings = { lockOnBlur: boolean; idleTimeoutMs: number; lockOnSleep: boolean; clipboardClearTimeoutMs: number; copySshPasswordOnLaunch: boolean };
type SettingsSection = "menu" | "pin" | "security" | "device" | "history" | "recovery";

const fieldClass = "h-9 rounded-md border border-input bg-background px-3 text-sm";

export function SettingsPanel({ fillHistory, recoveryTargets, onRecoveryChanged, onNotice, onLocked }: { fillHistory: FillEvent[]; recoveryTargets: RecoveryTarget[]; onRecoveryChanged: () => void | Promise<void>; onNotice: (message: string, variant?: ToastVariant) => void; onLocked: () => void }) {
  const [pinStatus, setPinStatus] = useState<PinStatus | null>(null);
  const [pin, setPin] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [failureLimit, setFailureLimit] = useState(5);
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [paired, setPaired] = useState(false);
  const [pluginPolicy, setPluginPolicy] = useState<PluginSecurityPolicy | null>(null);
  const [desktopSettings, setDesktopSettings] = useState<DesktopSecuritySettings | null>(null);
  const [busy, setBusy] = useState(false);
  const [section, setSection] = useState<SettingsSection>("menu");
  const [health, setHealth] = useState<PasswordHealth | null>(null);
  const [unlockHistory, setUnlockHistory] = useState<UnlockEvent[]>([]);
  const [auditBusy, setAuditBusy] = useState(false);

  async function load() {
    try {
      const [nextPin, nextBiometric, nextPairing, nextDesktopSettings, nextPluginPolicy] = await Promise.all([
        desktopRpc("pin.status"),
        desktopRpc("biometric.status"),
        desktopRpc("browser.pairing.status"),
        desktopRpc("security.settings.get"),
        loadPluginSecurityPolicy(),
      ]);
      const parsedPin = nextPin as PinStatus;
      setPinStatus(parsedPin);
      setFailureLimit(parsedPin.failureLimit);
      setBiometric(nextBiometric as BiometricStatus);
      setPaired(Boolean((nextPairing as { paired: boolean }).paired));
      setDesktopSettings(nextDesktopSettings as DesktopSecuritySettings);
      setPluginPolicy(nextPluginPolicy);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "无法加载插件设置。", "error");
    }
  }

  useEffect(() => {
    void load();
    const clear = () => { if (document.hidden) { setPin(""); setConfirmation(""); } };
    document.addEventListener("visibilitychange", clear);
    return () => document.removeEventListener("visibilitychange", clear);
  }, []);

  async function run(operation: () => Promise<unknown>, success: string, reload = true) {
    if (busy) return false;
    setBusy(true);
    try {
      await operation();
      onNotice(success, "success");
      if (reload) await load();
      return true;
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "操作失败。", "error");
      return false;
    } finally {
      setBusy(false);
    }
  }

  async function savePin() {
    if (pin.length !== 6 || pin !== confirmation) return;
    await run(() => desktopRpc("pin.enable", { pin, failureLimit }), pinStatus?.enabled ? "插件 PIN 已更新。" : "插件 PIN 解锁已启用。");
    setPin("");
    setConfirmation("");
  }

  async function saveSecurityPolicy() {
    if (!pluginPolicy || !desktopSettings) return;
    await run(async () => {
      if (!await savePluginSecurityPolicy(pluginPolicy)) throw new Error("无法保存插件安全策略。");
      await Promise.all([
        browser.runtime.sendMessage({ kind: "vaultmesh.security-policy.updated" }),
        desktopRpc("security.settings.update", desktopSettings),
      ]);
    }, "插件安全策略已更新。", false);
  }

  async function loadSecuritySummary() {
    if (auditBusy) return;
    setAuditBusy(true);
    try {
      const [nextHealth, nextUnlockHistory] = await Promise.all([getPasswordHealth(), getUnlockHistory()]);
      setHealth(nextHealth);
      setUnlockHistory(nextUnlockHistory.slice(0, 10));
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "无法读取安全摘要。", "error");
    } finally {
      setAuditBusy(false);
    }
  }

  if (section === "recovery") {
    return <RecoveryPanel targets={recoveryTargets} onBack={() => setSection("menu")} onChanged={onRecoveryChanged} />;
  }

  return (
    <ScrollArea className="-mr-3 min-h-0 flex-1">
      <div className="flex flex-col gap-3 pr-4">
      {section === "menu" ? <>
        <div className="px-1"><h2 className="text-base font-semibold">设置</h2><p className="text-xs text-muted-foreground">选择要配置的项目。</p></div>
        <SettingsMenuItem icon={ShieldCheckIcon} title="插件 PIN 解锁" description={pinStatus?.enabled ? pinStatus.locked ? "已锁定" : "已启用" : "未启用"} onClick={() => setSection("pin")} />
        <SettingsMenuItem icon={SettingsIcon} title="安全策略" description="浏览器重启、锁屏与空闲锁定" onClick={() => setSection("security")} />
        <SettingsMenuItem icon={LockKeyholeIcon} title="设备验证与配对" description={`${biometric?.enabled ? "生物识别已启用" : "生物识别未启用"} · ${paired ? "已配对" : "未配对"}`} onClick={() => setSection("device")} />
        <SettingsMenuItem icon={ArchiveRestoreIcon} title="回收站与历史" description="恢复或清理登录、支付卡、身份和 SSH" onClick={() => setSection("recovery")} />
        <SettingsMenuItem icon={HistoryIcon} title="最近填充记录" description={`${fillHistory.length} 条记录`} onClick={() => setSection("history")} />
      </> : <>
      <Button className="w-fit" size="sm" variant="ghost" onClick={() => setSection("menu")}><ArrowLeftIcon size={14} />返回设置</Button>
      {section === "pin" ? (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <div className="flex items-center gap-2"><ShieldCheckIcon size={18} /><h2 className="text-sm font-semibold">插件 PIN 解锁</h2></div>
          <p className="text-xs text-muted-foreground">{pinStatus?.enabled ? pinStatus.locked ? `已锁定（${pinStatus.failureLimit} 次失败上限），请使用主密码解锁插件。` : `已启用；输入固定 6 位 PIN 后自动解锁，失败上限 ${pinStatus.failureLimit} 次。` : "默认关闭，与桌面端 PIN 独立。启用后插件优先使用 PIN。"}</p>
          <input className={fieldClass} type="password" inputMode="numeric" minLength={6} maxLength={6} autoComplete="new-password" value={pin} onChange={(event) => setPin(event.target.value.replace(/\D/g, "").slice(0, 6))} placeholder={pinStatus?.enabled ? "新 6 位 PIN" : "6 位 PIN"} />
          <input className={fieldClass} type="password" inputMode="numeric" minLength={6} maxLength={6} autoComplete="new-password" value={confirmation} onChange={(event) => setConfirmation(event.target.value.replace(/\D/g, "").slice(0, 6))} placeholder="确认 6 位 PIN" />
          <div className="flex flex-col gap-1 text-xs"><span id="pin-failure-limit-label">连续失败次数上限</span><Select value={String(failureLimit)} onValueChange={(value) => { if (value !== null) setFailureLimit(Number(value)); }}><SelectTrigger className="h-9 w-full" aria-labelledby="pin-failure-limit-label"><SelectValue /></SelectTrigger><SelectContent><SelectGroup>{[3, 4, 5, 6, 7, 8, 9, 10].map((value) => <SelectItem key={value} value={String(value)}>{value} 次{value === 5 ? "（默认）" : ""}</SelectItem>)}</SelectGroup></SelectContent></Select></div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" disabled={busy || pin.length !== 6 || pin !== confirmation} onClick={() => void savePin()}>{pinStatus?.enabled ? "更新 PIN" : "启用 PIN"}</Button>
            {pinStatus?.enabled ? <Button size="sm" variant="destructive" disabled={busy} onClick={() => void run(() => desktopRpc("pin.disable"), "插件 PIN 解锁已关闭。")}>关闭 PIN</Button> : null}
          </div>
        </CardContent>
      </Card>
      ) : null}

      {section === "security" ? (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <div className="flex items-center gap-2"><SettingsIcon size={18} /><h2 className="text-sm font-semibold">安全策略</h2></div>
          {pluginPolicy && desktopSettings ? <>
            <p className="text-xs text-muted-foreground">以下规则只影响浏览器插件，不会改变桌面端的锁定设置。</p>
            <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={pluginPolicy.lockOnBrowserRestart} onChange={(event) => setPluginPolicy({ ...pluginPolicy, lockOnBrowserRestart: event.target.checked })} />浏览器启动或重启时锁定插件</label>
            <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={pluginPolicy.lockOnSystemLock} onChange={(event) => setPluginPolicy({ ...pluginPolicy, lockOnSystemLock: event.target.checked })} />系统锁屏时锁定插件</label>
            <div className="flex flex-col gap-1 text-xs"><span id="plugin-idle-timeout-label">浏览器空闲后锁定插件</span><Select value={String(pluginPolicy.idleTimeoutMinutes)} onValueChange={(value) => { if (value !== null) setPluginPolicy({ ...pluginPolicy, idleTimeoutMinutes: Number(value) as PluginSecurityPolicy["idleTimeoutMinutes"] }); }}><SelectTrigger className="h-9 w-full" aria-labelledby="plugin-idle-timeout-label"><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value="0">关闭</SelectItem><SelectItem value="1">1 分钟</SelectItem><SelectItem value="5">5 分钟（默认）</SelectItem><SelectItem value="10">10 分钟</SelectItem><SelectItem value="15">15 分钟</SelectItem><SelectItem value="30">30 分钟</SelectItem></SelectGroup></SelectContent></Select></div>
            <div className="flex flex-col gap-1 text-xs"><span id="clipboard-timeout-label">剪贴板自动清除</span><Select value={String(desktopSettings.clipboardClearTimeoutMs)} onValueChange={(value) => { if (value !== null) setDesktopSettings({ ...desktopSettings, clipboardClearTimeoutMs: Number(value) }); }}><SelectTrigger className="h-9 w-full" aria-labelledby="clipboard-timeout-label"><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value="10000">10 秒</SelectItem><SelectItem value="30000">30 秒</SelectItem><SelectItem value="60000">1 分钟</SelectItem><SelectItem value="120000">2 分钟</SelectItem></SelectGroup></SelectContent></Select></div>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" disabled={busy} onClick={() => void saveSecurityPolicy()}>保存安全策略</Button>
              <Button size="sm" variant="destructive" disabled={busy} onClick={() => void (async () => { if (await run(() => desktopRpc("vault.lock"), "插件已锁定。", false)) onLocked(); })()}><LockKeyholeIcon size={14} />立即锁定</Button>
            </div>
          </> : <p className="text-xs text-muted-foreground">正在读取安全策略…</p>}
        </CardContent>
      </Card>
      ) : null}

      {section === "device" ? (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <h2 className="text-sm font-semibold">设备验证与配对</h2>
          <p className="text-xs text-muted-foreground">生物识别：{biometric?.available ? biometric.enabled ? "已启用" : "可用" : "不可用"} · 桌面端配对：{paired ? "已配对" : "未配对"}</p>
          <div className="flex flex-wrap gap-2">
            {biometric?.available ? <Button size="sm" variant="secondary" disabled={busy} onClick={() => void run(() => desktopRpc(biometric.enabled ? "biometric.disable" : "biometric.enable"), `生物识别已${biometric.enabled ? "关闭" : "启用"}。`)}>{biometric.enabled ? "关闭" : "启用"}生物识别</Button> : null}
            {paired ? <Button size="sm" variant="destructive" disabled={busy} onClick={() => { if (window.confirm("撤销插件与桌面端的配对？")) void run(() => confirmedDesktopRpc("browser.pairing.revoke", {}), "插件配对已撤销。"); }}>撤销配对</Button> : null}
          </div>
        </CardContent>
      </Card>
      ) : null}

      {section === "history" ? (
      <Card>
        <CardContent className="flex flex-col gap-3">
          <div className="flex items-start gap-2"><div className="min-w-0 flex-1"><h2 className="text-sm font-semibold">安全与使用记录</h2><p className="text-xs text-muted-foreground">不记录填充值。</p></div><Button aria-label="刷新安全摘要" size="icon-sm" variant="ghost" disabled={auditBusy} onClick={() => void loadSecuritySummary()}><RefreshCwIcon className={auditBusy ? "animate-spin" : ""} /></Button></div>
          {health ? <div className="grid grid-cols-4 gap-2 rounded-lg bg-muted p-2 text-center text-xs"><span><strong className="block text-base">{health.score}</strong>评分</span><span><strong className="block text-base">{health.weakItemIds.length}</strong>弱密码</span><span><strong className="block text-base">{health.reusedItemIds.length}</strong>重复</span><span><strong className="block text-base">{health.oldItemIds.length}</strong>过旧</span></div> : <Button variant="outline" disabled={auditBusy} onClick={() => void loadSecuritySummary()}>读取密码健康和解锁记录</Button>}
          {fillHistory.length === 0 ? <ToastMessage id="empty-fill-history" message="暂无填充记录。" variant="info" /> : <div className="flex flex-col divide-y">{fillHistory.map((event) => <div key={event.eventId} className="flex items-start justify-between gap-3 py-2"><div className="min-w-0"><p className="truncate text-sm font-medium">{event.itemTitle}</p><p className="truncate text-xs text-muted-foreground">{event.origin}</p></div><div className="shrink-0 text-right"><p className="text-xs">{event.fieldCount} 个字段</p><p className="text-xs text-muted-foreground">{formatTime(event.occurredAt)}</p></div></div>)}</div>}
          {unlockHistory.length > 0 ? <div className="border-t pt-2"><h3 className="mb-1 text-xs font-semibold">最近解锁</h3>{unlockHistory.map((event) => <p key={event.eventId} className="text-xs text-muted-foreground">{formatTime(event.occurredAt)} · {unlockSourceLabel(event.source)}</p>)}</div> : null}
        </CardContent>
      </Card>
      ) : null}
      </>}
      </div>
    </ScrollArea>
  );
}

function SettingsMenuItem({ icon: Icon, title, description, onClick }: { icon: LucideIcon; title: string; description: string; onClick: () => void }) {
  return (
    <button className="flex w-full items-center gap-3 rounded-xl border bg-card p-3 text-left hover:bg-muted/50" type="button" onClick={onClick}>
      <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-muted"><Icon size={17} /></span>
      <span className="min-w-0 flex-1"><span className="block text-sm font-medium">{title}</span><span className="block truncate text-xs text-muted-foreground">{description}</span></span>
      <ChevronRightIcon className="shrink-0 text-muted-foreground" size={16} />
    </button>
  );
}

function formatTime(occurredAt: number): string {
  const milliseconds = occurredAt < 10_000_000_000 ? occurredAt * 1_000 : occurredAt;
  return new Intl.DateTimeFormat("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(milliseconds);
}

function unlockSourceLabel(source: UnlockEvent["source"]): string {
  return ({ desktop: "桌面主密码", "desktop-pin": "桌面 PIN", "extension-master-password": "插件主密码", "extension-biometric": "插件生物识别", "extension-pin": "插件 PIN" } as const)[source];
}
