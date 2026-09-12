import { useEffect, useMemo, useRef, useState } from "react";
import {
  CheckIcon,
  ChevronDownIcon,
  CopyIcon,
  FingerprintIcon,
  KeyRoundIcon,
  RefreshCwIcon,
  TextCursorInputIcon,
  UserRoundIcon,
} from "lucide-react";

import type { ToastVariant } from "@/components/ToastMessage";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  generatePassphrase,
  generatePassword,
  generateUsername,
  generateUuid,
  passwordEntropy,
  type PassphraseGeneratorOptions,
  type PasswordGeneratorOptions,
  type UsernameGeneratorOptions,
  type UuidGeneratorOptions,
} from "@/lib/generated-credentials";
import { desktopRpc } from "@/lib/desktop-rpc";
import {
  DEFAULT_GENERATOR_PREFERENCES,
  loadGeneratorPreferences,
  saveGeneratorPreferences,
  type GeneratorMode,
  type GeneratorPreferences,
} from "@/lib/generator-preferences";

type HistoryEntry = { id: string; mode: GeneratorMode; value: string; createdAt: number };
const GENERATED_VALUE_LIFETIME_MS = 60_000;

const modeMeta = {
  password: { label: "密码", icon: KeyRoundIcon },
  passphrase: { label: "短语", icon: TextCursorInputIcon },
  username: { label: "用户名", icon: UserRoundIcon },
  uuid: { label: "UUID", icon: FingerprintIcon },
} satisfies Record<GeneratorMode, { label: string; icon: typeof KeyRoundIcon }>;

export function GeneratorPanel({ onNotice }: { onNotice: (message: string, variant?: ToastVariant) => void }) {
  const [preferences, setPreferences] = useState(DEFAULT_GENERATOR_PREFERENCES);
  const [result, setResult] = useState(() => generatePassword(DEFAULT_GENERATOR_PREFERENCES.password));
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const [expiresAt, setExpiresAt] = useState(() => Date.now() + GENERATED_VALUE_LIFETIME_MS);
  const persistenceFailureNotified = useRef(false);
  const { mode, password: passwordOptions, passphrase: passphraseOptions, username: usernameOptions, uuid: uuidOptions } = preferences;

  const entropy = useMemo(() => mode === "password" ? passwordEntropy(passwordOptions) : mode === "passphrase" ? passphraseOptions.wordCount * 22 : mode === "username" ? usernameOptions.length * 4.8 : 122, [mode, passphraseOptions.wordCount, passwordOptions, usernameOptions.length]);
  const strength = entropy >= 100 ? "极强" : entropy >= 70 ? "强" : entropy >= 45 ? "中等" : "偏弱";
  const strengthWidth = Math.min(100, Math.round(entropy));
  const passwordIssue = useMemo(() => validatePasswordRules(passwordOptions), [passwordOptions]);

  useEffect(() => {
    let active = true;
    void loadGeneratorPreferences().then((loaded) => {
      if (!active || document.hidden) return;
      setPreferences(loaded);
      setResult(createGeneratorValue(loaded.mode, loaded));
      setExpiresAt(Date.now() + GENERATED_VALUE_LIFETIME_MS);
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    const clear = () => { setResult(""); setHistory([]); setCopied(false); };
    const timer = setTimeout(clear, Math.max(0, expiresAt - Date.now()));
    const hide = () => { if (document.hidden) clear(); };
    document.addEventListener("visibilitychange", hide);
    return () => { clearTimeout(timer); document.removeEventListener("visibilitychange", hide); };
  }, [expiresAt]);

  function updatePreferences(next: GeneratorPreferences) {
    setPreferences(next);
    void saveGeneratorPreferences(next).then((saved) => {
      if (saved || persistenceFailureNotified.current) return;
      persistenceFailureNotified.current = true;
      onNotice("生成器配置无法保存，本次弹窗内仍可继续使用。", "error");
    });
  }

  function createValue(nextMode = mode) {
    return createGeneratorValue(nextMode, preferences);
  }

  function generate(nextMode = mode) {
    try {
      const value = createValue(nextMode);
      setResult(value);
      setExpiresAt(Date.now() + GENERATED_VALUE_LIFETIME_MS);
      setHistory((current) => [{ id: crypto.randomUUID(), mode: nextMode, value, createdAt: Date.now() }, ...current].slice(0, 8));
      setCopied(false);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "生成失败，请检查规则。", "error");
    }
  }

  function selectMode(nextMode: GeneratorMode) {
    const next = { ...preferences, mode: nextMode };
    updatePreferences(next);
    try {
      const value = createGeneratorValue(nextMode, next);
      setResult(value);
      setExpiresAt(Date.now() + GENERATED_VALUE_LIFETIME_MS);
      setHistory((current) => [{ id: crypto.randomUUID(), mode: nextMode, value, createdAt: Date.now() }, ...current].slice(0, 8));
      setCopied(false);
    } catch (error) {
      onNotice(error instanceof Error ? error.message : "生成失败，请检查规则。", "error");
    }
  }

  async function copy(value = result, valueMode = mode) {
    if (!value) return;
    try {
      await desktopRpc("browser.generated.copy", { mode: valueMode, value });
      setCopied(value === result);
      onNotice("已复制，桌面端会按安全策略清除剪贴板。", "success");
    } catch {
      onNotice("桌面端无法写入安全剪贴板，请检查连接和插件解锁状态。", "error");
    }
  }

  return (
    <section className="flex min-h-0 flex-1 flex-col gap-3 px-1" aria-label="凭据生成器">
      <header className="shrink-0">
        <Tabs value={mode} onValueChange={(value) => selectMode(value as GeneratorMode)}>
          <TabsList className="grid h-10 w-full grid-cols-4" aria-label="生成类型">
            {(Object.keys(modeMeta) as GeneratorMode[]).map((value) => {
              const item = modeMeta[value];
              const Icon = item.icon;
              return <TabsTrigger key={value} value={value} className="h-8 gap-1 px-1 text-xs"><Icon size={14} aria-hidden="true" /><span>{item.label}</span></TabsTrigger>;
            })}
          </TabsList>
        </Tabs>
      </header>

      <Card className="shrink-0 border-primary/15 bg-primary/5 py-3 ring-primary/15">
        <CardContent className="flex flex-col gap-2 px-3">
          <div className="flex items-center justify-between gap-2">
            <span className="text-xs font-medium text-muted-foreground">生成结果</span>
            <Badge variant="secondary">{mode === "username" ? "可用性" : mode === "uuid" ? "版本" : "强度"} · {mode === "uuid" ? "v4" : strength}</Badge>
          </div>
          <output className="min-h-12 break-all font-mono text-[15px] font-semibold leading-6 tracking-wide" aria-live="polite">{result || "结果已清除，请重新生成"}</output>
          <div className="h-1 overflow-hidden rounded-full bg-primary/10" aria-hidden="true"><div className="h-full rounded-full bg-primary transition-[width]" style={{ width: `${strengthWidth}%` }} /></div>
          <div className="grid grid-cols-[1fr_auto] gap-2">
            <Button type="button" onClick={() => generate()} disabled={Boolean(passwordIssue && mode === "password")}><RefreshCwIcon data-icon="inline-start" />重新生成</Button>
            <Button type="button" variant="outline" size="icon" aria-label="复制生成结果" disabled={!result} onClick={() => void copy()}>{copied ? <CheckIcon /> : <CopyIcon />}</Button>
          </div>
        </CardContent>
      </Card>

      <ScrollArea key={mode} className="-mr-4 min-h-0 flex-1">
        <div className="flex flex-col gap-3 py-1 pl-1 pr-4">
          {mode === "password" ? <PasswordControls options={passwordOptions} issue={passwordIssue} onChange={(password) => updatePreferences({ ...preferences, password })} /> : null}
          {mode === "passphrase" ? <PassphraseControls options={passphraseOptions} onChange={(passphrase) => updatePreferences({ ...preferences, passphrase })} /> : null}
          {mode === "username" ? <UsernameControls options={usernameOptions} onChange={(username) => updatePreferences({ ...preferences, username })} /> : null}
          {mode === "uuid" ? <UuidControls options={uuidOptions} onChange={(uuid) => updatePreferences({ ...preferences, uuid })} /> : null}

          <Card size="sm">
            <button type="button" className="flex w-full items-center justify-between px-3 text-left" aria-expanded={historyOpen} onClick={() => setHistoryOpen((value) => !value)}>
              <span><span className="block text-sm font-medium">本次生成记录</span><span className="block text-xs text-muted-foreground">关闭弹窗后自动清除 · {history.length} 条</span></span>
              <ChevronDownIcon size={16} className={historyOpen ? "rotate-180 transition-transform" : "transition-transform"} aria-hidden="true" />
            </button>
            {historyOpen ? <CardContent className="flex flex-col gap-1 border-t pt-2">
              {history.map((entry) => <div key={entry.id} className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-muted"><span className="min-w-0 flex-1"><span className="block truncate font-mono text-xs">{entry.value}</span><span className="block text-[10px] text-muted-foreground">{modeMeta[entry.mode].label} · {new Date(entry.createdAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span></span><Button type="button" variant="ghost" size="icon-xs" aria-label={`复制 ${entry.value}`} onClick={() => void copy(entry.value, entry.mode)}><CopyIcon /></Button></div>)}
              {history.length === 0 ? <p className="px-2 py-1 text-xs text-muted-foreground">再次生成后，结果会暂时出现在这里。</p> : null}
            </CardContent> : null}
          </Card>
        </div>
      </ScrollArea>
    </section>
  );
}

function createGeneratorValue(mode: GeneratorMode, preferences: GeneratorPreferences): string {
  if (mode === "password") return generatePassword(preferences.password);
  if (mode === "passphrase") return generatePassphrase(preferences.passphrase);
  if (mode === "username") return generateUsername(preferences.username);
  return generateUuid(preferences.uuid);
}

function PasswordControls({ options, issue, onChange }: { options: PasswordGeneratorOptions; issue: string | null; onChange: (value: PasswordGeneratorOptions) => void }) {
  const set = <Key extends keyof PasswordGeneratorOptions>(key: Key, value: PasswordGeneratorOptions[Key]) => onChange({ ...options, [key]: value });
  return <Card size="sm"><CardContent className="flex flex-col gap-3">
    <div className="flex items-center justify-between"><label className="text-sm font-medium" htmlFor="password-length">密码长度</label><input id="password-length-number" className="h-7 w-14 rounded-lg border bg-background px-2 text-center text-sm font-medium" type="number" min={8} max={64} value={options.length} onChange={(event) => set("length", clamp(Number(event.target.value), 8, 64))} /></div>
    <input id="password-length" className="w-full accent-primary" type="range" min={8} max={64} value={options.length} onChange={(event) => set("length", Number(event.target.value))} />
    <div><p className="mb-2 text-xs font-medium text-muted-foreground">字符组成</p><div className="grid grid-cols-2 gap-2">
      <CheckOption label="大写字母" checked={options.uppercase} onChange={(value) => set("uppercase", value)} />
      <CheckOption label="小写字母" checked={options.lowercase} onChange={(value) => set("lowercase", value)} />
      <CheckOption label="数字" checked={options.numbers} onChange={(value) => set("numbers", value)} />
      <CheckOption label="符号" checked={options.symbols} onChange={(value) => set("symbols", value)} />
    </div></div>
    <div className="grid grid-cols-2 gap-2">
      <NumberField label="最少数字" value={options.minimumNumbers} disabled={!options.numbers} onChange={(value) => set("minimumNumbers", value)} />
      <NumberField label="最少符号" value={options.minimumSymbols} disabled={!options.symbols} onChange={(value) => set("minimumSymbols", value)} />
    </div>
    <CheckOption label="排除易混淆字符（I、l、1、O、0）" checked={options.avoidAmbiguous} onChange={(value) => set("avoidAmbiguous", value)} />
    {issue ? <p className="text-xs text-destructive">{issue}</p> : <p className="text-xs text-muted-foreground">建议至少 16 位，并保留三种以上字符类型。</p>}
  </CardContent></Card>;
}

function PassphraseControls({ options, onChange }: { options: PassphraseGeneratorOptions; onChange: (value: PassphraseGeneratorOptions) => void }) {
  const set = <Key extends keyof PassphraseGeneratorOptions>(key: Key, value: PassphraseGeneratorOptions[Key]) => onChange({ ...options, [key]: value });
  return <Card size="sm"><CardContent className="flex flex-col gap-3">
    <div className="flex items-center justify-between"><label className="text-sm font-medium" htmlFor="word-count">单词数量</label><span className="rounded-lg bg-muted px-2 py-1 text-xs font-semibold">{options.wordCount} 个</span></div>
    <input id="word-count" className="w-full accent-primary" type="range" min={3} max={8} value={options.wordCount} onChange={(event) => set("wordCount", Number(event.target.value))} />
    <div className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground"><span id="passphrase-separator-label">分隔方式</span><Select value={options.separator} onValueChange={(value) => { if (value !== null) set("separator", value as PassphraseGeneratorOptions["separator"]); }}><SelectTrigger className="h-9 w-full" aria-labelledby="passphrase-separator-label"><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value="-">连字符 —</SelectItem><SelectItem value=".">句点 ·</SelectItem><SelectItem value="_">下划线 _</SelectItem><SelectItem value=" ">空格</SelectItem></SelectGroup></SelectContent></Select></div>
    <div className="grid grid-cols-2 gap-2"><CheckOption label="单词首字母大写" checked={options.capitalize} onChange={(value) => set("capitalize", value)} /><CheckOption label="末尾添加数字" checked={options.includeNumber} onChange={(value) => set("includeNumber", value)} /></div>
    <p className="text-xs text-muted-foreground">使用可读的随机音节组合，兼顾记忆与安全性。</p>
  </CardContent></Card>;
}

function UsernameControls({ options, onChange }: { options: UsernameGeneratorOptions; onChange: (value: UsernameGeneratorOptions) => void }) {
  const set = <Key extends keyof UsernameGeneratorOptions>(key: Key, value: UsernameGeneratorOptions[Key]) => onChange({ ...options, [key]: value });
  return <Card size="sm"><CardContent className="flex flex-col gap-3">
    <div className="grid grid-cols-2 gap-2"><div className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground"><span id="username-style-label">风格</span><Select value={options.style} onValueChange={(value) => { if (value !== null) set("style", value as UsernameGeneratorOptions["style"]); }}><SelectTrigger className="h-9 w-full" aria-labelledby="username-style-label"><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value="readable">易读</SelectItem><SelectItem value="random">随机</SelectItem></SelectGroup></SelectContent></Select></div><label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">前缀<input className="h-9 rounded-lg border bg-background px-2 text-sm text-foreground" value={options.prefix} maxLength={8} placeholder="可选" onChange={(event) => set("prefix", event.target.value)} /></label></div>
    <div className="flex items-center justify-between"><label className="text-sm font-medium" htmlFor="username-length">用户名长度</label><span className="rounded-lg bg-muted px-2 py-1 text-xs font-semibold">{options.length} 位</span></div>
    <input id="username-length" className="w-full accent-primary" type="range" min={8} max={24} value={options.length} onChange={(event) => set("length", Number(event.target.value))} />
    <CheckOption label="包含两位随机数字" checked={options.includeNumber} onChange={(value) => set("includeNumber", value)} />
    <p className="text-xs text-muted-foreground">适合创建与真实身份无关的站点账号名。</p>
  </CardContent></Card>;
}

function UuidControls({ options, onChange }: { options: UuidGeneratorOptions; onChange: (value: UuidGeneratorOptions) => void }) {
  const set = <Key extends keyof UuidGeneratorOptions>(key: Key, value: UuidGeneratorOptions[Key]) => onChange({ ...options, [key]: value });
  return <Card size="sm"><CardContent className="flex flex-col gap-3">
    <div><h2 className="text-sm font-medium">UUID v4 格式</h2><p className="mt-1 text-xs text-muted-foreground">使用浏览器加密随机数生成 122 位随机标识。</p></div>
    <div className="grid grid-cols-2 gap-2"><CheckOption label="保留连字符" checked={options.hyphens} onChange={(value) => set("hyphens", value)} /><CheckOption label="使用大写字母" checked={options.uppercase} onChange={(value) => set("uppercase", value)} /></div>
    <CheckOption label="在结果外添加花括号" checked={options.braces} onChange={(value) => set("braces", value)} />
    <p className="text-xs text-muted-foreground">格式选项只改变显示方式，不影响 UUID 的随机性。</p>
  </CardContent></Card>;
}

function CheckOption({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="flex min-h-9 items-center gap-2 rounded-lg border bg-background px-2.5 text-xs font-medium"><input className="size-4 shrink-0 accent-primary" type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span>{label}</span></label>;
}

function NumberField({ label, value, disabled, onChange }: { label: string; value: number; disabled: boolean; onChange: (value: number) => void }) {
  return <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">{label}<input className="h-9 rounded-lg border bg-background px-2 text-sm text-foreground disabled:bg-muted disabled:opacity-60" type="number" min={0} max={8} value={disabled ? 0 : value} disabled={disabled} onChange={(event) => onChange(clamp(Number(event.target.value), 0, 8))} /></label>;
}

function validatePasswordRules(options: PasswordGeneratorOptions) {
  const enabled = [options.uppercase, options.lowercase, options.numbers, options.symbols].filter(Boolean).length;
  if (enabled === 0) return "至少选择一种字符类型。";
  const required = Number(options.uppercase) + Number(options.lowercase) + (options.numbers ? Math.max(1, options.minimumNumbers) : 0) + (options.symbols ? Math.max(1, options.minimumSymbols) : 0);
  if (required > options.length) return `当前规则至少需要 ${required} 位字符。`;
  return null;
}

function clamp(value: number, minimum: number, maximum: number) {
  if (!Number.isFinite(value)) return minimum;
  return Math.min(maximum, Math.max(minimum, value));
}
