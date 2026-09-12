import { useEffect, useRef, useState } from "react";
import { ArrowLeftIcon, CameraIcon, CopyIcon, EyeIcon, EyeOffIcon, FileUpIcon, KeyRoundIcon, RefreshCwIcon, SaveIcon, Trash2Icon } from "lucide-react";

import { ToastMessage } from "@/components/ToastMessage";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { copyRecoveryCode, deletePasskey, desktopRpc, getLoginDetail, getPasskeysForLogin, getRecoveryCodes, importRecoveryCodesFile, type PasskeySummary } from "@/lib/desktop-rpc";
import type { TotpQrCode } from "@/lib/protocol";

type LoginForm = {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  folder: string;
  favorite: boolean;
  additionalUrls: string;
  customFields: string;
  autofillOnPageLoad: boolean;
  masterPasswordReprompt: boolean;
  totpSecret: string;
  recoveryCodes: string;
};

const EMPTY_FORM: LoginForm = {
  title: "", username: "", password: "", url: "", notes: "", folder: "", favorite: false,
  additionalUrls: "", customFields: "", autofillOnPageLoad: true, masterPasswordReprompt: false, totpSecret: "", recoveryCodes: "",
};
const EDIT_SESSION_LIFETIME_MS = 5 * 60_000;
const NATIVE_FILE_DIALOG_GRACE_MS = 45_000;

type RecoveryAction = { kind: "view" } | { kind: "copy"; index: number };

export function EditLoginPanel({ id, onCancel, onSaved, onPasskeysChanged, onScanTotp }: {
  id: string;
  onCancel: () => void;
  onSaved: () => void | Promise<void>;
  onPasskeysChanged: () => void | Promise<void>;
  onScanTotp: () => Promise<TotpQrCode | null>;
}) {
  const onCancelRef = useRef(onCancel);
  const nativeFileDialogUntil = useRef(0);
  const [form, setForm] = useState<LoginForm>(EMPTY_FORM);
  const [hasTotpSecret, setHasTotpSecret] = useState(false);
  const [clearTotpSecret, setClearTotpSecret] = useState(false);
  const [hasRecoveryCodes, setHasRecoveryCodes] = useState(false);
  const [clearRecoveryCodes, setClearRecoveryCodes] = useState(false);
  const [recognizedTotp, setRecognizedTotp] = useState<TotpQrCode | null>(null);
  const [passkeys, setPasskeys] = useState<PasskeySummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [deletingPasskeyId, setDeletingPasskeyId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [importingRecoveryCodes, setImportingRecoveryCodes] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [importNotice, setImportNotice] = useState<string | null>(null);
  const [importNoticeVariant, setImportNoticeVariant] = useState<'success' | 'info' | 'warning'>('success');
  const [revealedRecoveryCodes, setRevealedRecoveryCodes] = useState<string[]>([]);
  const [recoveryAction, setRecoveryAction] = useState<RecoveryAction | null>(null);
  const [recoveryMasterPassword, setRecoveryMasterPassword] = useState("");
  const [recoveryAccessBusy, setRecoveryAccessBusy] = useState(false);
  const [recoveryAccessError, setRecoveryAccessError] = useState<string | null>(null);
  const [recoveryAccessNotice, setRecoveryAccessNotice] = useState<string | null>(null);
  onCancelRef.current = onCancel;

  function expireEditor() {
    setForm(EMPTY_FORM); setRecognizedTotp(null); setRevealedRecoveryCodes([]); setRecoveryAction(null);
    setRecoveryMasterPassword(""); setRecoveryAccessError(null); setRecoveryAccessNotice(null); setImportNotice(null);
    onCancelRef.current();
  }

  useEffect(() => {
    let nativeDialogExpiry: ReturnType<typeof setTimeout> | null = null;
    const hidden = () => {
      if (!document.hidden) return;
      const remainingGrace = nativeFileDialogUntil.current - Date.now();
      if (remainingGrace > 0) {
        if (nativeDialogExpiry) clearTimeout(nativeDialogExpiry);
        nativeDialogExpiry = setTimeout(() => { if (document.hidden) expireEditor(); }, remainingGrace);
      } else {
        expireEditor();
      }
    };
    const timer = setTimeout(expireEditor, EDIT_SESSION_LIFETIME_MS);
    document.addEventListener("visibilitychange", hidden);
    return () => { clearTimeout(timer); if (nativeDialogExpiry) clearTimeout(nativeDialogExpiry); document.removeEventListener("visibilitychange", hidden); };
  }, [id]);

  useEffect(() => {
    let active = true;
    setForm(EMPTY_FORM);
    setClearTotpSecret(false);
    setClearRecoveryCodes(false);
    setImportNotice(null);
    setRevealedRecoveryCodes([]);
    setRecoveryAction(null);
    setRecoveryMasterPassword("");
    setRecoveryAccessError(null);
    setRecoveryAccessNotice(null);
    setLoading(true);
    void Promise.all([getLoginDetail(id), getPasskeysForLogin(id)]).then(([detail, linkedPasskeys]) => {
      if (!active) return;
      setForm({
        title: detail.title,
        username: detail.username,
        password: "",
        url: detail.url ?? "",
        notes: detail.notes ?? "",
        folder: detail.folder ?? "",
        favorite: detail.favorite,
        additionalUrls: detail.additionalUrls.join("\n"),
        customFields: detail.customFields.map((field) => `${field.label}=${field.value}`).join("\n"),
        autofillOnPageLoad: detail.autofillOnPageLoad,
        masterPasswordReprompt: detail.masterPasswordReprompt,
        totpSecret: "",
        recoveryCodes: "",
      });
      setHasTotpSecret(detail.hasTotpSecret);
      setHasRecoveryCodes(detail.hasRecoveryCodes);
      setPasskeys(linkedPasskeys);
      setLoading(false);
    }).catch((cause) => {
      if (!active) return;
      setError(cause instanceof Error ? cause.message : "无法读取登录信息。");
      setLoading(false);
    });
    return () => { active = false; };
  }, [id]);

  function set<K extends keyof LoginForm>(key: K, value: LoginForm[K]) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function scanTotp() {
    if (scanning) return;
    setScanning(true);
    setError(null);
    try {
      const recognized = await onScanTotp();
      if (!recognized) return;
      if (hasTotpSecret && !clearTotpSecret && !window.confirm("当前登录已有验证器密钥，是否在保存时替换？")) return;
      set("totpSecret", recognized.uri);
      setClearTotpSecret(false);
      setRecognizedTotp(recognized);
    } finally {
      setScanning(false);
    }
  }

  async function submit() {
    if (!form.title.trim() || busy || deletingPasskeyId) return;
    const recoveryCodes = recoveryCodeLines(form.recoveryCodes);
    setBusy(true);
    setError(null);
    try {
      await desktopRpc("items.update", {
        id,
        title: form.title.trim(),
        username: form.username,
        password: form.password || null,
        url: form.url.trim() || null,
        notes: form.notes.trim() || null,
        folder: form.folder.trim() || null,
        favorite: form.favorite,
        totpSecret: form.totpSecret.trim() || null,
        clearTotpSecret,
        recoveryCodes: recoveryCodes.length > 0 ? recoveryCodes : null,
        clearRecoveryCodes,
        additionalUrls: nonEmptyLines(form.additionalUrls),
        autofillOnPageLoad: form.autofillOnPageLoad,
        masterPasswordReprompt: form.masterPasswordReprompt,
        customFields: customFields(form.customFields),
      });
      closeRecoveryAccess();
      await onSaved();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法更新登录信息。");
    } finally {
      setBusy(false);
    }
  }

  function closeRecoveryAccess() {
    setRevealedRecoveryCodes([]);
    setRecoveryAction(null);
    setRecoveryMasterPassword("");
    setRecoveryAccessError(null);
  }

  function requestRecoveryAccess(action: RecoveryAction) {
    if (action.kind === "view") setRevealedRecoveryCodes([]);
    setRecoveryAction(action);
    setRecoveryMasterPassword("");
    setRecoveryAccessError(null);
    setRecoveryAccessNotice(null);
  }

  function closeRecoveryPrompt() {
    setRecoveryAction(null);
    setRecoveryMasterPassword("");
    setRecoveryAccessError(null);
  }

  async function confirmRecoveryAccess() {
    if (!recoveryAction || recoveryAccessBusy || recoveryMasterPassword.length < 8) return;
    setRecoveryAccessBusy(true);
    setRecoveryAccessError(null);
    setRecoveryAccessNotice(null);
    try {
      if (recoveryAction.kind === "view") {
        const codes = await getRecoveryCodes(id, recoveryMasterPassword);
        setRevealedRecoveryCodes(codes);
      } else {
        await copyRecoveryCode(id, recoveryAction.index, recoveryMasterPassword);
        setRecoveryAccessNotice("恢复码已复制；桌面端会按安全设置自动清空剪贴板。");
      }
      setRecoveryAction(null);
      setRecoveryMasterPassword("");
    } catch (cause) {
      setRevealedRecoveryCodes([]);
      setRecoveryAccessError(cause instanceof Error ? cause.message : "主密码不正确，或恢复码不可用。");
    } finally {
      setRecoveryAccessBusy(false);
    }
  }

  async function importRecoveryCodeFile() {
    if (importingRecoveryCodes) return;
    closeRecoveryAccess();
    setImportingRecoveryCodes(true);
    nativeFileDialogUntil.current = Date.now() + NATIVE_FILE_DIALOG_GRACE_MS;
    setError(null);
    setImportNotice(null);
    try {
      const result = await importRecoveryCodesFile();
      if (!result) return;
      set("recoveryCodes", result.codes.join("\n"));
      setClearRecoveryCodes(false);
      if (result.sourceFileStatus === "deleted") {
        setImportNoticeVariant("success");
        setImportNotice(`已从“${result.fileName}”导入 ${result.codes.length} 个恢复码，原文件已删除。`);
      } else if (result.sourceFileStatus === "kept") {
        setImportNoticeVariant("info");
        setImportNotice(`已从“${result.fileName}”导入 ${result.codes.length} 个恢复码，原文件已保留。`);
      } else {
        setImportNoticeVariant("warning");
        setImportNotice(`已导入 ${result.codes.length} 个恢复码，但原文件未能删除，请手动检查。`);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法导入恢复码文件。");
    } finally {
      nativeFileDialogUntil.current = 0;
      setImportingRecoveryCodes(false);
      if (document.hidden) expireEditor();
    }
  }

  async function removePasskey(passkey: PasskeySummary) {
    if (deletingPasskeyId) return;
    const website = hostname(passkey.website);
    if (!window.confirm(`确定从 VaultMesh 永久删除“${passkey.title}”吗？\n\n这只会删除本地 Passkey 私钥，无法恢复；${website ? `${website} 的` : "网站端的"}登记不会自动撤销，建议先在网站的账户安全设置中删除。`)) return;
    setDeletingPasskeyId(passkey.id);
    setError(null);
    try {
      await deletePasskey(passkey.id);
      setPasskeys((current) => current.filter((item) => item.id !== passkey.id));
      await onPasskeysChanged();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法删除 Passkey。");
    } finally {
      setDeletingPasskeyId(null);
    }
  }

  return (
    <section className="flex min-h-0 flex-1 flex-col gap-3" aria-label="编辑登录信息">
      <ToastMessage id="edit-login-error" message={error} variant="error" />
      <ToastMessage id="edit-login-recovery-code-import" message={importNotice} variant={importNoticeVariant} />
      <ToastMessage id="edit-login-recovery-code-access" message={recoveryAccessNotice} variant="success" />
      <Dialog
        open={Boolean(recoveryAction)}
        disablePointerDismissal={recoveryAccessBusy}
        onOpenChange={(open) => { if (!open && !recoveryAccessBusy) closeRecoveryPrompt(); }}
      >
        <DialogContent aria-label={recoveryAction?.kind === "copy" ? "验证后复制恢复码" : "验证后查看恢复码"}>
          <form className="flex flex-col gap-4" onSubmit={(event) => { event.preventDefault(); void confirmRecoveryAccess(); }}>
            <DialogHeader>
              <DialogTitle>{recoveryAction?.kind === "copy" ? "验证并复制恢复码" : "验证并查看恢复码"}</DialogTitle>
              <DialogDescription>
                {recoveryAction?.kind === "copy"
                  ? `再次输入主密码以复制第 ${(recoveryAction?.index ?? 0) + 1} 个恢复码。`
                  : "每次查看都必须重新输入主密码。"}
              </DialogDescription>
            </DialogHeader>
            <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">
              主密码
              <input
                className="h-9 rounded-lg border bg-background px-2 text-sm text-foreground outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                type="password"
                value={recoveryMasterPassword}
                minLength={8}
                maxLength={1_024}
                autoComplete="off"
                autoFocus
                aria-invalid={Boolean(recoveryAccessError)}
                placeholder="输入主密码"
                onChange={(event) => setRecoveryMasterPassword(event.target.value)}
              />
            </label>
            {recoveryAccessError ? <p className="text-xs text-destructive" role="alert">{recoveryAccessError}</p> : null}
            <DialogFooter>
              <DialogClose render={<Button variant="outline" type="button" disabled={recoveryAccessBusy} />}>取消</DialogClose>
              <Button type="submit" disabled={recoveryAccessBusy || recoveryMasterPassword.length < 8}>
                {recoveryAccessBusy ? <RefreshCwIcon className="animate-spin" data-icon="inline-start" /> : null}
                {recoveryAction?.kind === "copy" ? "验证并复制" : "验证并查看"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <ToastMessage
        id="edit-login-totp-recognized"
        message={recognizedTotp
          ? `已识别：${[recognizedTotp.issuer, recognizedTotp.account].filter(Boolean).join(" · ") || "TOTP 验证器"}。保存登录信息后生效。`
          : null}
        variant="success"
      />
      <header className="flex shrink-0 items-center gap-2">
        <Button variant="ghost" size="icon-sm" type="button" aria-label="返回密码库" onClick={() => { closeRecoveryAccess(); onCancel(); }}><ArrowLeftIcon /></Button>
        <span className="grid size-8 place-items-center rounded-lg bg-muted"><KeyRoundIcon size={16} /></span>
        <div><h1 className="text-sm font-semibold">编辑登录</h1><p className="text-xs text-muted-foreground">修改登录凭据和验证器密钥</p></div>
      </header>

      {loading ? <div className="grid min-h-0 flex-1 place-items-center text-sm text-muted-foreground"><RefreshCwIcon className="animate-spin" /></div> : (
        <ScrollArea className="-mr-3 min-h-0 flex-1">
          <div className="flex flex-col gap-3 p-px pr-4">
            <Card size="sm"><CardContent className="flex flex-col gap-3">
              <Field label="标题" required value={form.title} onChange={(value) => set("title", value)} />
              <Field label="用户名" value={form.username} onChange={(value) => set("username", value)} />
              <Field label="新密码" type="password" value={form.password} placeholder="留空则保留现有密码" onChange={(value) => set("password", value)} />
              <Field label="网址" type="url" value={form.url} placeholder="https://example.com" onChange={(value) => set("url", value)} />
            </CardContent></Card>

            <Card size="sm"><CardContent className="flex flex-col gap-3">
              <div className="flex items-center justify-between gap-2"><div><h2 className="text-sm font-semibold">验证器密钥</h2><p className="text-xs text-muted-foreground">保存到这条登录信息中</p></div>{hasTotpSecret && !clearTotpSecret ? <span className="text-xs text-emerald-600">已设置</span> : null}</div>
              <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">
                TOTP 密钥或 URI
                <span className="flex gap-2">
                  <input className="h-9 min-w-0 flex-1 rounded-lg border bg-background px-2 text-sm text-foreground" type="password" value={form.totpSecret} placeholder={hasTotpSecret && !clearTotpSecret ? "已保存；可输入或扫描新密钥替换" : "输入密钥或扫描当前网页二维码"} onChange={(event) => { set("totpSecret", event.target.value); setClearTotpSecret(false); setRecognizedTotp(null); }} />
                  <Button variant="outline" size="icon" type="button" disabled={scanning} title="从当前网页扫描验证器二维码" aria-label="从当前网页扫描验证器二维码" onClick={() => void scanTotp()}>{scanning ? <RefreshCwIcon className="animate-spin" size={16} /> : <CameraIcon size={16} />}</Button>
                </span>
              </label>
              {hasTotpSecret && !clearTotpSecret ? <Button className="self-start" variant="ghost" size="sm" type="button" onClick={() => { setClearTotpSecret(true); set("totpSecret", ""); setRecognizedTotp(null); }}><Trash2Icon data-icon="inline-start" />移除验证器密钥</Button> : null}
              {clearTotpSecret ? <p className="text-xs text-destructive">保存后将移除现有验证器密钥。</p> : null}
            </CardContent></Card>

            <Card size="sm"><CardContent className="flex flex-col gap-3">
              <div className="flex items-center justify-between gap-2"><div><h2 className="text-sm font-semibold">恢复码</h2><p className="text-xs text-muted-foreground">可粘贴或从 UTF-8 文件导入</p></div>{hasRecoveryCodes && !clearRecoveryCodes ? <span className="text-xs text-emerald-600">已保存</span> : null}</div>
              <div className="flex flex-wrap gap-2">
                {hasRecoveryCodes && !clearRecoveryCodes ? <Button variant="outline" size="sm" type="button" onClick={() => requestRecoveryAccess({ kind: "view" })}><EyeIcon data-icon="inline-start" />查看恢复码</Button> : null}
                <Button variant="outline" size="sm" type="button" disabled={importingRecoveryCodes} onClick={() => void importRecoveryCodeFile()}>
                  {importingRecoveryCodes ? <RefreshCwIcon className="animate-spin" data-icon="inline-start" /> : <FileUpIcon data-icon="inline-start" />}
                  {importingRecoveryCodes ? "正在读取…" : "选择恢复码文件"}
                </Button>
              </div>
              {revealedRecoveryCodes.length > 0 ? (
                <div className="flex flex-col gap-2 rounded-lg border bg-background p-2" aria-label="已解密恢复码">
                  <div className="flex items-center justify-between gap-2"><p className="text-xs text-muted-foreground">仅在当前弹窗中临时显示；每次复制仍需重新验证。</p><Button variant="ghost" size="sm" type="button" onClick={closeRecoveryAccess}><EyeOffIcon data-icon="inline-start" />隐藏</Button></div>
                  <ol className="flex flex-col gap-1.5">
                    {revealedRecoveryCodes.map((code, index) => (
                      <li className="flex items-center gap-2 rounded-md bg-muted/50 p-2" key={index}>
                        <code className="min-w-0 flex-1 break-all text-xs" data-recovery-code>{code}</code>
                        <Button variant="outline" size="icon-sm" type="button" aria-label={`复制第 ${index + 1} 个恢复码`} onClick={() => requestRecoveryAccess({ kind: "copy", index })}><CopyIcon /></Button>
                      </li>
                    ))}
                  </ol>
                </div>
              ) : null}
              <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">
                {hasRecoveryCodes && !clearRecoveryCodes ? "替换恢复码（可选）" : "恢复码（每行一个）"}
                <textarea className="min-h-24 rounded-lg border bg-background px-2 py-1.5 font-mono text-sm text-foreground" value={form.recoveryCodes} maxLength={25_600} spellCheck={false} autoComplete="off" placeholder={hasRecoveryCodes && !clearRecoveryCodes ? "已保存；可粘贴或选择文件替换" : "ABCD-EFGH"} onChange={(event) => { set("recoveryCodes", event.target.value); if (event.target.value) setClearRecoveryCodes(false); }} />
              </label>
              <p className="text-xs text-muted-foreground">解析文件后桌面端会询问是否删除原文件；保存前恢复码只保留在当前编辑会话。</p>
              {(hasRecoveryCodes && !clearRecoveryCodes) || form.recoveryCodes ? <Button className="self-start" variant="ghost" size="sm" type="button" onClick={() => { closeRecoveryAccess(); if (form.recoveryCodes) { set("recoveryCodes", ""); setClearRecoveryCodes(false); } else { setClearRecoveryCodes(true); } }}><Trash2Icon data-icon="inline-start" />{form.recoveryCodes ? "清除待保存恢复码" : "移除已保存恢复码"}</Button> : null}
              {clearRecoveryCodes ? <p className="text-xs text-destructive">保存后将移除现有恢复码。</p> : null}
            </CardContent></Card>

            <Card size="sm">
              <CardHeader>
                <CardTitle>Passkey</CardTitle>
                <CardDescription>删除只会永久移除 VaultMesh 中的私钥，不会自动撤销网站端的登记。</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-col gap-2">
                {passkeys.length === 0 ? <p className="text-xs text-muted-foreground">此登录信息尚未关联 Passkey。</p> : passkeys.map((passkey) => (
                  <div className="flex items-center gap-2 rounded-lg border bg-background p-2" key={passkey.id}>
                    <span className="grid size-8 shrink-0 place-items-center rounded-lg bg-muted"><KeyRoundIcon size={16} /></span>
                    <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{passkey.title}</p><p className="truncate text-xs text-muted-foreground">{[passkey.account, hostname(passkey.website)].filter(Boolean).join(" · ") || "Passkey"}</p></div>
                    <Button variant="destructive" size="icon-sm" type="button" disabled={Boolean(deletingPasskeyId)} aria-label={`从 VaultMesh 删除 ${passkey.title}`} title="仅从 VaultMesh 永久删除" onClick={() => void removePasskey(passkey)}>{deletingPasskeyId === passkey.id ? <RefreshCwIcon className="animate-spin" /> : <Trash2Icon />}</Button>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card size="sm"><CardContent className="flex flex-col gap-3">
              <Area label="附加网址（每行一个）" value={form.additionalUrls} onChange={(value) => set("additionalUrls", value)} />
              <Area label="自定义字段（标签=值，每行一个）" value={form.customFields} onChange={(value) => set("customFields", value)} />
              <Area label="备注" value={form.notes} onChange={(value) => set("notes", value)} />
              <Field label="文件夹" value={form.folder} onChange={(value) => set("folder", value)} />
              <Check label="收藏" checked={form.favorite} onChange={(value) => set("favorite", value)} />
              <Check label="页面加载后允许自动填充" checked={form.autofillOnPageLoad} onChange={(value) => set("autofillOnPageLoad", value)} />
              <Check label="访问敏感信息时重新验证主密码" checked={form.masterPasswordReprompt} onChange={(value) => set("masterPasswordReprompt", value)} />
            </CardContent></Card>
          </div>
        </ScrollArea>
      )}

      <div className="grid shrink-0 grid-cols-[auto_1fr] gap-2 border-t pt-3">
        <Button variant="outline" type="button" disabled={busy || Boolean(deletingPasskeyId)} onClick={() => { closeRecoveryAccess(); onCancel(); }}>取消</Button>
        <Button type="button" disabled={loading || busy || Boolean(deletingPasskeyId) || !form.title.trim()} onClick={() => void submit()}><SaveIcon data-icon="inline-start" />{busy ? "正在保存…" : "保存登录信息"}</Button>
      </div>
    </section>
  );
}

function Field({ label, value, onChange, type = "text", required = false, placeholder }: { label: string; value: string; onChange: (value: string) => void; type?: string; required?: boolean; placeholder?: string }) {
  return <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">{label}<input className="h-9 rounded-lg border bg-background px-2 text-sm text-foreground" type={type} required={required} value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} /></label>;
}

function Area({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  return <label className="flex flex-col gap-1.5 text-xs font-medium text-muted-foreground">{label}<textarea className="min-h-18 rounded-lg border bg-background px-2 py-1.5 text-sm text-foreground" value={value} onChange={(event) => onChange(event.target.value)} /></label>;
}

function Check({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="flex items-start gap-2 text-xs"><input className="mt-0.5 size-4 shrink-0 accent-primary" type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} /><span>{label}</span></label>;
}

function nonEmptyLines(value: string): string[] {
  return value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
}

function recoveryCodeLines(value: string): string[] {
  return value.split(/\r?\n/).filter((line) => line.trim().length > 0);
}

function customFields(value: string) {
  return nonEmptyLines(value).map((line) => {
    const [label, ...rest] = line.split("=");
    return { label: label!.trim(), value: rest.join("=") };
  }).filter((field) => field.label);
}

function hostname(value: string | null): string | null {
  if (!value) return null;
  try { return new URL(value).hostname; } catch { return value; }
}
