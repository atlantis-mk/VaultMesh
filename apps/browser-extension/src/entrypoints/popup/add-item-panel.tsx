import { useEffect, useRef, useState } from "react";
import { ArrowLeftIcon, ClipboardPasteIcon, CreditCardIcon, FileKeyIcon, KeyRoundIcon, RefreshCwIcon, SaveIcon, TerminalIcon, UserRoundIcon } from "lucide-react";
import { parseSshCommand } from "@vaultmesh/ssh-command-parser";

import { ToastMessage } from "@/components/ToastMessage";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DatePicker } from "@/components/DatePicker";
import { desktopRpc, getCardDetail, getIdentityDetail, getSecretDetail, getSshDetail, type Operation } from "@/lib/desktop-rpc";
import { PAYMENT_CARD_NETWORK_OPTIONS } from "@/lib/payment-card-networks";

export type AddItemKind = "login" | "card" | "identity" | "ssh" | "secret";

export const ADD_ITEM_OPTIONS = [
  { kind: "login" as const, label: "登录信息", icon: KeyRoundIcon },
  { kind: "card" as const, label: "支付卡", icon: CreditCardIcon },
  { kind: "ssh" as const, label: "SSH 凭据", icon: TerminalIcon },
  { kind: "secret" as const, label: "机密信息", icon: FileKeyIcon },
  { kind: "identity" as const, label: "身份", icon: UserRoundIcon },
];

type Values = Record<string, string | boolean>;
const NO_CARD_NETWORK = "__no_card_network__";
const EDIT_SESSION_LIFETIME_MS = 5 * 60_000;

const defaults: Record<AddItemKind, Values> = {
  login: { title: "", username: "", password: "", url: "", totpSecret: "", additionalUrls: "", customFields: "", notes: "", folder: "", favorite: false, autofillOnPageLoad: true, masterPasswordReprompt: false },
  card: { title: "", cardholderName: "", cardNumber: "", expirationMonth: String(new Date().getMonth() + 1), expirationYear: String(new Date().getFullYear()), securityCode: "", pin: "", issuer: "", network: "", billingAddress: "", notes: "", folder: "", favorite: false, masterPasswordReprompt: false },
  identity: { title: "", firstName: "", middleName: "", lastName: "", birthDate: "", emails: "", phones: "", addresses: "", organization: "", department: "", jobTitle: "", website: "", notes: "", folder: "", favorite: false },
  ssh: { title: "", host: "", port: "22", username: "", password: "", publicKey: "", privateKey: "", keyPassphrase: "", notes: "", folder: "", favorite: false, masterPasswordReprompt: false },
  secret: { title: "", secretKind: "api-key", secret: "", provider: "", account: "", environment: "", scopes: "", expiresAt: "", website: "", notes: "", folder: "", favorite: false, masterPasswordReprompt: false },
};

export function AddItemPanel({ kind, editId, onCancel, onSaved }: { kind: AddItemKind; editId?: string; onCancel: () => void; onSaved: () => void | Promise<void> }) {
  const onCancelRef = useRef(onCancel);
  const [values, setValues] = useState<Values>(() => ({ ...defaults[kind] }));
  const [loading, setLoading] = useState(Boolean(editId));
  const [busy, setBusy] = useState(false);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const option = ADD_ITEM_OPTIONS.find((item) => item.kind === kind)!;
  const editing = Boolean(editId);
  const set = (key: string, value: string | boolean) => setValues((current) => ({ ...current, [key]: value }));
  onCancelRef.current = onCancel;

  useEffect(() => {
    const expire = () => {
      setValues({ ...defaults[kind] }); setError(null); setNotice(null);
      onCancelRef.current();
    };
    const hidden = () => { if (document.hidden) expire(); };
    const timer = setTimeout(expire, EDIT_SESSION_LIFETIME_MS);
    document.addEventListener("visibilitychange", hidden);
    return () => { clearTimeout(timer); document.removeEventListener("visibilitychange", hidden); };
  }, [editId, kind]);

  useEffect(() => {
    if (!editId || kind === "login") return;
    let active = true;
    setLoading(true);
    void loadEditValues(kind, editId).then((nextValues) => {
      if (active) setValues(nextValues);
    }).catch((cause) => {
      if (active) setError(cause instanceof Error ? cause.message : "无法读取项目详情。");
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, [editId, kind]);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      await desktopRpc(editId ? updateOperation(kind) : addOperation(kind), editId ? buildEditItemInput(kind, editId, values) : buildAddItemInput(kind, values));
      await onSaved();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法保存项目。");
    } finally {
      setBusy(false);
    }
  }

  async function importSshFromClipboard() {
    setImporting(true);
    setError(null);
    setNotice(null);
    try {
      const imported = parseSshCommand(await navigator.clipboard.readText());
      setValues((current) => ({
        ...current,
        title: imported.title,
        host: imported.host,
        port: String(imported.port),
        username: imported.username,
        notes: [stringValue(current.notes).trim(), imported.notes].filter(Boolean).join("\n"),
      }));
      setNotice("已导入 SSH 命令，请补充密码、公钥或私钥后保存。");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法读取剪贴板，请检查插件权限。");
    } finally {
      setImporting(false);
    }
  }

  return (
    <section className="flex min-h-0 flex-1 flex-col gap-3" aria-label={`${editing ? "编辑" : "新增"}${option.label}`}>
      <ToastMessage id="add-item-error" message={error} variant="error" />
      <ToastMessage id="add-item-notice" message={notice} variant="success" />
      <header className="flex shrink-0 items-center gap-2">
        <Button variant="ghost" size="icon-sm" type="button" aria-label="返回密码库" onClick={onCancel}><ArrowLeftIcon /></Button>
        <span className="grid size-8 place-items-center rounded-lg bg-muted"><option.icon size={16} /></span>
        <div><h1 className="text-sm font-semibold">{editing ? "编辑" : "新增"}{option.label}</h1><p className="text-xs text-muted-foreground">{editing ? "修改后保存到本机加密保险库" : "直接保存到本机加密保险库"}</p></div>
      </header>

      {loading ? <div className="grid min-h-0 flex-1 place-items-center text-muted-foreground"><RefreshCwIcon className="animate-spin" /></div> : <ScrollArea className="-mr-3 min-h-0 flex-1">
        <div className="flex flex-col gap-3 p-px pr-4">
          {kind === "ssh" && !editing ? <Button className="w-full" variant="outline" type="button" disabled={importing} onClick={() => void importSshFromClipboard()}>{importing ? <RefreshCwIcon className="animate-spin" data-icon="inline-start" /> : <ClipboardPasteIcon data-icon="inline-start" />}{importing ? "正在读取…" : "从剪贴板导入 SSH 命令"}</Button> : null}
          <Card size="sm"><CardContent className="flex flex-col gap-3">
            <Field label="标题" value={stringValue(values.title)} required onChange={(value) => set("title", value)} />
            {kind === "login" ? <LoginFields values={values} set={set} /> : null}
            {kind === "card" ? <CardFields values={values} set={set} editing={editing} /> : null}
            {kind === "identity" ? <IdentityFields values={values} set={set} /> : null}
            {kind === "ssh" ? <SshFields values={values} set={set} editing={editing} /> : null}
            {kind === "secret" ? <SecretFields values={values} set={set} editing={editing} /> : null}
          </CardContent></Card>
          <Card size="sm"><CardContent className="flex flex-col gap-3">
            <Area label="备注" value={stringValue(values.notes)} onChange={(value) => set("notes", value)} />
            <Field label="文件夹" value={stringValue(values.folder)} onChange={(value) => set("folder", value)} />
            <Check label="收藏" checked={Boolean(values.favorite)} onChange={(value) => set("favorite", value)} />
            {kind !== "identity" ? <Check label="访问敏感信息时重新验证主密码" checked={Boolean(values.masterPasswordReprompt)} onChange={(value) => set("masterPasswordReprompt", value)} /> : null}
          </CardContent></Card>
        </div>
      </ScrollArea>}

      <div className="grid shrink-0 grid-cols-[auto_1fr] gap-2 border-t pt-3">
        <Button variant="outline" type="button" disabled={busy} onClick={onCancel}>取消</Button>
        <Button type="button" disabled={loading || busy || !canSubmit(kind, values, editing)} onClick={() => void submit()}><SaveIcon data-icon="inline-start" />{busy ? "正在保存…" : `保存${option.label}`}</Button>
      </div>
    </section>
  );
}

type SetValue = (key: string, value: string | boolean) => void;

function LoginFields({ values, set }: { values: Values; set: SetValue }) {
  return <><Field label="用户名" value={stringValue(values.username)} onChange={(value) => set("username", value)} /><Field label="密码" type="password" required value={stringValue(values.password)} onChange={(value) => set("password", value)} /><Field label="网址" type="url" value={stringValue(values.url)} placeholder="https://example.com" onChange={(value) => set("url", value)} /><Field label="TOTP 密钥或 URI" type="password" value={stringValue(values.totpSecret)} onChange={(value) => set("totpSecret", value)} /><Area label="附加网址（每行一个）" value={stringValue(values.additionalUrls)} onChange={(value) => set("additionalUrls", value)} /><Area label="自定义字段（标签=值，每行一个）" value={stringValue(values.customFields)} onChange={(value) => set("customFields", value)} /><Check label="页面加载后允许自动填充" checked={Boolean(values.autofillOnPageLoad)} onChange={(value) => set("autofillOnPageLoad", value)} /></>;
}

function CardFields({ values, set, editing }: { values: Values; set: SetValue; editing: boolean }) {
  return <><Field label={editing ? "新卡号" : "卡号"} required={!editing} inputMode="numeric" value={stringValue(values.cardNumber)} placeholder={editing ? `留空保留 ${stringValue(values.existingCardNumber)}` : undefined} onChange={(value) => set("cardNumber", value)} /><Field label="持卡人" required value={stringValue(values.cardholderName)} onChange={(value) => set("cardholderName", value)} /><div className="grid grid-cols-2 gap-2"><Field label="到期月份" type="number" value={stringValue(values.expirationMonth)} onChange={(value) => set("expirationMonth", value)} /><Field label="到期年份" type="number" value={stringValue(values.expirationYear)} onChange={(value) => set("expirationYear", value)} /></div><div className="grid grid-cols-2 gap-2"><Field label={editing ? "新安全码" : "安全码"} type="password" inputMode="numeric" value={stringValue(values.securityCode)} placeholder={editing && values.hasSecurityCode ? "留空保留" : undefined} onChange={(value) => set("securityCode", value)} /><Field label={editing ? "新 PIN" : "PIN"} type="password" inputMode="numeric" value={stringValue(values.pin)} placeholder={editing && values.hasPin ? "留空保留" : undefined} onChange={(value) => set("pin", value)} /></div><Field label="发卡机构" value={stringValue(values.issuer)} onChange={(value) => set("issuer", value)} /><SelectField label="卡组织" value={stringValue(values.network)} onChange={(value) => set("network", value)} /><Area label="账单地址" value={stringValue(values.billingAddress)} onChange={(value) => set("billingAddress", value)} /></>;
}

function IdentityFields({ values, set }: { values: Values; set: SetValue }) {
  return <><div className="grid grid-cols-2 gap-2"><Field label="名" value={stringValue(values.firstName)} onChange={(value) => set("firstName", value)} /><Field label="姓" value={stringValue(values.lastName)} onChange={(value) => set("lastName", value)} /></div><Field label="中间名" value={stringValue(values.middleName)} onChange={(value) => set("middleName", value)} /><DateField label="出生日期" value={stringValue(values.birthDate)} onChange={(value) => set("birthDate", value)} placeholder="选择出生日期" endMonth={new Date()} maxDate={new Date()} /><Area label="邮箱（标签|邮箱，每行一个）" value={stringValue(values.emails)} onChange={(value) => set("emails", value)} /><Area label="电话（标签|号码，每行一个）" value={stringValue(values.phones)} onChange={(value) => set("phones", value)} /><Area label="地址（标签|地址1|地址2|城市|地区|邮编|国家代码|国家）" value={stringValue(values.addresses)} onChange={(value) => set("addresses", value)} /><Field label="组织" value={stringValue(values.organization)} onChange={(value) => set("organization", value)} /><Field label="部门" value={stringValue(values.department)} onChange={(value) => set("department", value)} /><Field label="职位" value={stringValue(values.jobTitle)} onChange={(value) => set("jobTitle", value)} /><Field label="网站" type="url" value={stringValue(values.website)} onChange={(value) => set("website", value)} /></>;
}

function SshFields({ values, set, editing }: { values: Values; set: SetValue; editing: boolean }) {
  const preserved = editing ? "留空则保留现有内容" : undefined;
  return <><Field label="主机" value={stringValue(values.host)} onChange={(value) => set("host", value)} /><Field label="端口" type="number" value={stringValue(values.port)} onChange={(value) => set("port", value)} /><Field label="用户名" value={stringValue(values.username)} onChange={(value) => set("username", value)} /><Field label={editing ? "新密码" : "密码"} type="password" value={stringValue(values.password)} placeholder={values.hasPassword ? preserved : undefined} onChange={(value) => set("password", value)} /><Area label={editing ? "新公钥" : "公钥"} value={stringValue(values.publicKey)} placeholder={values.hasPublicKey ? preserved : undefined} onChange={(value) => set("publicKey", value)} /><Area label={editing ? "新私钥" : "私钥"} value={stringValue(values.privateKey)} placeholder={values.hasPrivateKey ? preserved : undefined} onChange={(value) => set("privateKey", value)} /><Field label={editing ? "新私钥口令" : "私钥口令"} type="password" value={stringValue(values.keyPassphrase)} placeholder={values.hasKeyPassphrase ? preserved : undefined} onChange={(value) => set("keyPassphrase", value)} /></>;
}

function SecretFields({ values, set, editing }: { values: Values; set: SetValue; editing: boolean }) {
  const kind = stringValue(values.secretKind);
  const credentialKinds = ["api-key", "access-token", "authenticator-key", "client-secret", "webhook-secret"];
  return <><div className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground"><span id="secret-kind-label">类型</span><Select value={kind} onValueChange={(value) => { if (value !== null) set("secretKind", value); }}><SelectTrigger className="h-9 w-full" aria-labelledby="secret-kind-label"><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value="api-key">API Key</SelectItem><SelectItem value="access-token">访问令牌</SelectItem><SelectItem value="authenticator-key">认证密钥</SelectItem><SelectItem value="client-secret">客户端密钥</SelectItem><SelectItem value="webhook-secret">Webhook 密钥</SelectItem><SelectItem value="database-credential">数据库凭据</SelectItem><SelectItem value="recovery-codes">恢复码</SelectItem><SelectItem value="certificate">证书与 PEM</SelectItem><SelectItem value="software-license">软件许可证</SelectItem><SelectItem value="identity-document">身份证件</SelectItem><SelectItem value="secure-note">安全笔记</SelectItem><SelectItem value="crypto-wallet">加密钱包</SelectItem><SelectItem value="other">其他</SelectItem></SelectGroup></SelectContent></Select></div><Field label={editing ? (credentialKinds.includes(kind) ? "新密钥值" : "新内容") : credentialKinds.includes(kind) ? "密钥值" : "内容"} type="password" required={!editing} value={stringValue(values.secret)} placeholder={editing ? "留空则保留现有内容" : undefined} onChange={(value) => set("secret", value)} /><Field label="服务商" value={stringValue(values.provider)} placeholder="GitHub、OpenAI…" onChange={(value) => set("provider", value)} /><Field label="账号或项目" value={stringValue(values.account)} onChange={(value) => set("account", value)} /><Field label="环境" value={stringValue(values.environment)} placeholder="Production、Staging…" onChange={(value) => set("environment", value)} /><Field label="权限范围（逗号分隔）" value={stringValue(values.scopes)} onChange={(value) => set("scopes", value)} /><DateField label="到期日" value={stringValue(values.expiresAt)} onChange={(value) => set("expiresAt", value)} placeholder="选择到期日" /><Field label="网址" type="url" value={stringValue(values.website)} placeholder="https://github.com" onChange={(value) => set("website", value)} /></>;
}

function Field({ label, value, onChange, type = "text", required = false, placeholder, inputMode }: { label: string; value: string; onChange: (value: string) => void; type?: string; required?: boolean; placeholder?: string; inputMode?: React.HTMLAttributes<HTMLInputElement>["inputMode"] }) {
  return <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">{label}<input className="h-9 rounded-lg border bg-background px-2 text-sm text-foreground" type={type} required={required} value={value} placeholder={placeholder} inputMode={inputMode} onChange={(event) => onChange(event.target.value)} /></label>;
}

function SelectField({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  const labelId = "card-network-label";
  return <div className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground"><span id={labelId}>{label}</span><Select value={value || NO_CARD_NETWORK} onValueChange={(nextValue) => onChange(nextValue === NO_CARD_NETWORK || nextValue === null ? "" : nextValue)}><SelectTrigger className="h-9 w-full" aria-labelledby={labelId}><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value={NO_CARD_NETWORK}>未选择</SelectItem>{PAYMENT_CARD_NETWORK_OPTIONS.map((option) => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}</SelectGroup></SelectContent></Select></div>;
}

function DateField({ label, value, onChange, placeholder, endMonth, maxDate }: { label: string; value: string; onChange: (value: string) => void; placeholder: string; endMonth?: Date; maxDate?: Date }) {
  return <div className="flex flex-col gap-1.5"><span className="text-xs font-medium text-muted-foreground">{label}</span><DatePicker className="h-9" ariaLabel={label} value={value} onValueChange={onChange} placeholder={placeholder} endMonth={endMonth} maxDate={maxDate} /></div>;
}

function Area({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder?: string }) {
  return <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">{label}<textarea className="min-h-18 rounded-lg border bg-background px-2 py-1.5 text-sm text-foreground" value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} /></label>;
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="flex items-start gap-2 text-xs"><input className="mt-0.5 size-4 shrink-0 accent-primary" type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span>{label}</span></label>;
}

function canSubmit(kind: AddItemKind, values: Values, editing = false) {
  if (!stringValue(values.title).trim()) return false;
  if (kind === "login") return Boolean(stringValue(values.password));
  if (kind === "card") return Boolean(stringValue(values.cardholderName).trim() && (editing || stringValue(values.cardNumber).trim().length >= 12));
  if (kind === "ssh") return editing || Boolean(stringValue(values.password) || stringValue(values.publicKey) || stringValue(values.privateKey));
  if (kind === "secret") return editing || Boolean(stringValue(values.secret));
  return true;
}

function addOperation(kind: AddItemKind): Operation {
  return ({ login: "items.add", card: "cards.add", identity: "identities.add", ssh: "ssh.add", secret: "secrets.add" } as const)[kind];
}

function updateOperation(kind: AddItemKind): Operation {
  return ({ login: "items.update", card: "cards.update", identity: "identities.update", ssh: "ssh.update", secret: "secrets.update" } as const)[kind];
}

export function buildAddItemInput(kind: AddItemKind, values: Values): Record<string, unknown> {
  const nullable = (key: string) => stringValue(values[key]).trim() || null;
  const common = { title: stringValue(values.title).trim(), notes: nullable("notes"), folder: nullable("folder"), favorite: Boolean(values.favorite) };
  if (kind === "login") return { ...common, username: stringValue(values.username), password: stringValue(values.password), url: nullable("url"), totpSecret: nullable("totpSecret"), additionalUrls: lines(values.additionalUrls), autofillOnPageLoad: values.autofillOnPageLoad !== false, masterPasswordReprompt: Boolean(values.masterPasswordReprompt), customFields: lines(values.customFields).map((line) => { const [label, ...rest] = line.split("="); return { label: label!.trim(), value: rest.join("=") }; }).filter((item) => item.label) };
  if (kind === "card") return { ...common, cardholderName: stringValue(values.cardholderName).trim(), cardNumber: stringValue(values.cardNumber).trim(), expirationMonth: Number(values.expirationMonth), expirationYear: Number(values.expirationYear), securityCode: nullable("securityCode"), pin: nullable("pin"), issuer: nullable("issuer"), network: nullable("network"), billingAddress: nullable("billingAddress"), masterPasswordReprompt: Boolean(values.masterPasswordReprompt) };
  if (kind === "ssh") return { ...common, host: nullable("host"), port: Number(values.port || 22), username: stringValue(values.username), password: nullable("password"), publicKey: nullable("publicKey"), privateKey: nullable("privateKey"), keyPassphrase: nullable("keyPassphrase"), masterPasswordReprompt: Boolean(values.masterPasswordReprompt) };
  if (kind === "secret") return { ...common, kind: stringValue(values.secretKind), secret: stringValue(values.secret), provider: nullable("provider"), account: nullable("account"), environment: nullable("environment"), scopes: stringValue(values.scopes).split(/[,\n]/).map((value) => value.trim()).filter(Boolean), expiresAt: nullable("expiresAt"), website: nullable("website"), masterPasswordReprompt: Boolean(values.masterPasswordReprompt) };
  return { ...common, firstName: nullable("firstName"), middleName: nullable("middleName"), lastName: nullable("lastName"), birthDate: nullable("birthDate"), emails: identityValues(values.emails), phones: identityValues(values.phones), addresses: addressValues(values.addresses), organization: nullable("organization"), department: nullable("department"), jobTitle: nullable("jobTitle"), website: nullable("website") };
}

export function buildEditItemInput(kind: AddItemKind, id: string, values: Values): Record<string, unknown> {
  if (kind === "identity") return { id, ...buildAddItemInput(kind, values) };
  const nullable = (key: string) => stringValue(values[key]).trim() || null;
  const common = { id, title: stringValue(values.title).trim(), notes: nullable("notes"), folder: nullable("folder"), favorite: Boolean(values.favorite) };
  if (kind === "card") return {
    ...common, cardholderName: stringValue(values.cardholderName).trim(), cardNumber: nullable("cardNumber"),
    expirationMonth: Number(values.expirationMonth), expirationYear: Number(values.expirationYear),
    securityCode: nullable("securityCode"), clearSecurityCode: false, pin: nullable("pin"), clearPin: false,
    issuer: nullable("issuer"), network: nullable("network"), billingAddress: nullable("billingAddress"), masterPasswordReprompt: Boolean(values.masterPasswordReprompt),
  };
  if (kind === "ssh") return {
    ...common, host: nullable("host"), port: Number(values.port || 22), username: stringValue(values.username),
    password: nullable("password"), clearPassword: false, publicKey: nullable("publicKey"), clearPublicKey: false,
    privateKey: nullable("privateKey"), clearPrivateKey: false, keyPassphrase: nullable("keyPassphrase"), clearKeyPassphrase: false,
    masterPasswordReprompt: Boolean(values.masterPasswordReprompt),
  };
  if (kind === "secret") return {
    ...common, kind: stringValue(values.secretKind), secret: nullable("secret"), provider: nullable("provider"), account: nullable("account"),
    environment: nullable("environment"), scopes: stringValue(values.scopes).split(/[,\n]/).map((value) => value.trim()).filter(Boolean),
    expiresAt: nullable("expiresAt"), website: nullable("website"), masterPasswordReprompt: Boolean(values.masterPasswordReprompt),
  };
  return { id, ...buildAddItemInput(kind, values), password: nullable("password"), clearTotpSecret: false };
}

async function loadEditValues(kind: Exclude<AddItemKind, "login">, id: string): Promise<Values> {
  if (kind === "card") {
    const detail = await getCardDetail(id);
    return {
      ...defaults.card, title: detail.title, cardholderName: detail.cardholderName, existingCardNumber: detail.maskedNumber,
      expirationMonth: String(detail.expirationMonth), expirationYear: String(detail.expirationYear), hasSecurityCode: detail.hasSecurityCode,
      hasPin: detail.hasPin, issuer: detail.issuer ?? "", network: detail.network ?? "", billingAddress: detail.billingAddress ?? "",
      notes: detail.notes ?? "", folder: detail.folder ?? "", favorite: detail.favorite, masterPasswordReprompt: detail.masterPasswordReprompt,
    };
  }
  if (kind === "identity") {
    const detail = await getIdentityDetail(id);
    return {
      ...defaults.identity, title: detail.title, firstName: detail.firstName ?? "", middleName: detail.middleName ?? "", lastName: detail.lastName ?? "",
      birthDate: detail.birthDate ?? "", emails: detail.emails.map((value) => `${value.label}|${value.value}`).join("\n"),
      phones: detail.phones.map((value) => `${value.label}|${value.value}`).join("\n"),
      addresses: detail.addresses.map((value) => [value.label, value.addressLine1, value.addressLine2, value.city, value.region, value.postalCode, value.countryCode, value.country].map((part) => part ?? "").join("|")).join("\n"),
      organization: detail.organization ?? "", department: detail.department ?? "", jobTitle: detail.jobTitle ?? "", website: detail.website ?? "",
      notes: detail.notes ?? "", folder: detail.folder ?? "", favorite: detail.favorite,
    };
  }
  if (kind === "ssh") {
    const detail = await getSshDetail(id);
    return {
      ...defaults.ssh, title: detail.title, host: detail.host ?? "", port: String(detail.port), username: detail.username,
      hasPassword: detail.hasPassword, hasPublicKey: detail.hasPublicKey, hasPrivateKey: detail.hasPrivateKey, hasKeyPassphrase: detail.hasKeyPassphrase,
      notes: detail.notes ?? "", folder: detail.folder ?? "", favorite: detail.favorite, masterPasswordReprompt: detail.masterPasswordReprompt,
    };
  }
  const detail = await getSecretDetail(id);
  return {
    ...defaults.secret, title: detail.title, secretKind: detail.kind, provider: detail.provider ?? "", account: detail.account ?? "",
    environment: detail.environment ?? "", scopes: detail.scopes.join(", "), expiresAt: detail.expiresAt ?? "", website: detail.website ?? "",
    notes: detail.notes ?? "", folder: detail.folder ?? "", favorite: detail.favorite, masterPasswordReprompt: detail.masterPasswordReprompt,
  };
}

function identityValues(value: string | boolean | undefined) {
  return lines(value).map((line, index) => { const [label, ...rest] = line.split("|"); return { id: crypto.randomUUID(), label: rest.length ? label!.trim() : "", value: (rest.length ? rest.join("|") : label)!.trim(), preferred: index === 0 }; }).filter((item) => item.value);
}

function addressValues(value: string | boolean | undefined) {
  return lines(value).map((line, index) => {
    const parts = line.split("|");
    const [label, addressLine1] = parts;
    const [addressLine2, city, region, postalCode, countryCode, country] = parts.length >= 8 ? parts.slice(2) : ["", ...parts.slice(2)];
    return { id: crypto.randomUUID(), label: label?.trim() ?? "", addressLine1: addressLine1?.trim() ?? "", addressLine2: addressLine2?.trim() || null, city: city?.trim() || null, region: region?.trim() || null, postalCode: postalCode?.trim() || null, countryCode: countryCode?.trim() || null, country: country?.trim() || null, preferred: index === 0 };
  }).filter((item) => item.addressLine1);
}

function lines(value: string | boolean | undefined) { return stringValue(value).split(/\n/).map((line) => line.trim()).filter(Boolean); }
function stringValue(value: string | boolean | undefined) { return typeof value === "string" ? value : ""; }
