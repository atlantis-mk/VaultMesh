import { useEffect, useMemo, useRef, useState } from "react";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import {
  BracesIcon,
  CheckIcon,
  CopyIcon,
  CreditCardIcon,
  FolderKeyIcon,
  FingerprintIcon,
  EllipsisVerticalIcon,
  ExternalLinkIcon,
  KeyRoundIcon,
  LockKeyholeIcon,
  MailIcon,
  PlusIcon,
  PencilIcon,
  RefreshCwIcon,
  ScanSearchIcon,
  SearchIcon,
  SettingsIcon,
  SparklesIcon,
  TerminalIcon,
  Trash2Icon,
} from "lucide-react";

import { ToastMessage, type ToastVariant } from "@/components/ToastMessage";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { confirmedDesktopRpc, desktopRpc, DesktopRpcError, getDesktopStatus, getEmailOtpCandidates, pollDesktopEvents, type DesktopState, type EmailOtpCandidate, type FillEvent, type Operation, type WorkspaceSnapshot } from "@/lib/desktop-rpc";
import { requiresFillConfirmation } from "@/lib/autofill-selection";
import { PageInformationDetectionResponseSchema, PageInformationSaveResponseSchema, SaveCaptureDecisionResponseSchema, SaveCapturePendingResponseSchema, TotpQrScanResponseSchema, type PageInformationDetectionResponse, type SaveCaptureQueuedResponse, type TotpQrCode } from "@/lib/protocol";
import { loginCopyOptions } from "@/lib/login-copy-options";
import { loadCachedPopupWorkspace, loadPopupSuggestionIds, loadPopupWorkspace, popupSessionInvalidation, shouldShowDesktopConnection } from "@/lib/popup-workspace";
import { saveCaptureCountdown } from "@/lib/save-capture-countdown";
import { saveCapturePromptActionLabel, saveCapturePromptTitle } from "@/lib/save-capture-prompt";
import { paginateVaultItems } from "@/lib/vault-pagination";
import { GeneratorPanel } from "./generator-panel";
import { ADD_ITEM_OPTIONS, AddItemPanel, type AddItemKind } from "./add-item-panel";
import { PageInformationPanel } from "./page-information-panel";
import { EditLoginPanel } from "./edit-login-panel";
import { SettingsPanel } from "./settings-panel";
import type { RecoveryTarget } from "./recovery-panel";

type FillState = "idle" | "pending" | "sent" | "unavailable" | "locked" | "cancelled" | "no-fields" | "unsupported";
type Tab = "vault" | "generator" | "settings";
type VaultItemType = "全部" | "登录" | "身份" | "支付卡" | "SSH" | "机密";

type VaultItem = {
  id: string;
  title: string;
  detail: string;
  type: Exclude<VaultItemType, "全部">;
  suggested?: boolean;
  masterPasswordReprompt?: boolean;
  passkeyOnly?: boolean;
  passkeyCount?: number;
  username?: string;
  hasPassword?: boolean;
  hasTotpSecret?: boolean;
  url?: string;
  hasSecurityCode?: boolean;
  hasPin?: boolean;
  hasSshPassword?: boolean;
  hasPublicKey?: boolean;
  hasPrivateKey?: boolean;
  hasKeyPassphrase?: boolean;
};
type DetectedPageInformation = Extract<PageInformationDetectionResponse, { status: "detected" }>;
type InitialPopupWorkspace = NonNullable<Awaited<ReturnType<typeof loadCachedPopupWorkspace>>>;

const typeTabs: VaultItemType[] = ["全部", "登录", "身份", "支付卡", "SSH", "机密"];

export function PopupApp({ initialWorkspace = null }: { initialWorkspace?: InitialPopupWorkspace | null }) {
  const workspaceLoadSequence = useRef(0);
  const fillConfirmationTokenRef = useRef<string | null>(null);
  const [query, setQuery] = useState("");
  const [activeType, setActiveType] = useState<VaultItemType>("全部");
  const [activeTab, setActiveTab] = useState<Tab>(() => {
    const tab = new URLSearchParams(window.location.search).get("tab");
    return tab === "generator" || tab === "settings" ? tab : "vault";
  });
  const [fillState, setFillState] = useState<FillState>("idle");
  const [fillOutcome, setFillOutcome] = useState<string | null>(null);
  const [notice, setNoticeState] = useState<{ message: string; variant: ToastVariant } | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<VaultItem[]>(() => initialWorkspace ? toVaultItems(initialWorkspace.snapshot) : []);
  const [desktopState, setDesktopState] = useState<DesktopState>(initialWorkspace ? "ready" : "unavailable");
  const [hasVault, setHasVault] = useState(initialWorkspace?.hasVault ?? false);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState<AddItemKind | null>(null);
  const [fillConfirmation, setFillConfirmation] = useState<VaultItem | null>(null);
  const [fillConfirmationToken, setFillConfirmationToken] = useState<string | null>(null);
  const [fillConfirmationPassword, setFillConfirmationPassword] = useState("");
  const [fillConfirmationError, setFillConfirmationError] = useState<string | null>(null);
  const [fillConfirmationBusy, setFillConfirmationBusy] = useState(false);
  const [copyConfirmation, setCopyConfirmation] = useState<{ item: VaultItem; option: string } | null>(null);
  const [copyConfirmationPassword, setCopyConfirmationPassword] = useState("");
  const [copyConfirmationError, setCopyConfirmationError] = useState<string | null>(null);
  const [copyConfirmationBusy, setCopyConfirmationBusy] = useState(false);
  const [fillHistory, setFillHistory] = useState<FillEvent[]>([]);
  const [pageInformation, setPageInformation] = useState<{ tabId: number; capture: DetectedPageInformation } | null>(null);
  const [pageInformationBusy, setPageInformationBusy] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null);
  const [emailOtpCandidates, setEmailOtpCandidates] = useState<EmailOtpCandidate[]>([]);
  const [emailOtpBoostExpiresAt, setEmailOtpBoostExpiresAt] = useState(0);
  const [emailOtpFillingId, setEmailOtpFillingId] = useState<string | null>(null);
  const [saveCapturePrompt, setSaveCapturePrompt] = useState<SaveCaptureQueuedResponse | null>(null);
  const [saveCaptureBusy, setSaveCaptureBusy] = useState(false);
  const [saveCaptureError, setSaveCaptureError] = useState<string | null>(null);
  const [saveCaptureClock, setSaveCaptureClock] = useState(() => saveCaptureCountdown(0));

  function setNotice(message: string | null, variant: ToastVariant = "default") {
    setNoticeState(message ? { message, variant } : null);
  }

  function invalidatePopupSession(state: Extract<DesktopState, "locked" | "unavailable">) {
    workspaceLoadSequence.current += 1;
    const token = fillConfirmationTokenRef.current;
    if (token) void browser.runtime.sendMessage({ kind: "vaultmesh.fill-confirmation.cancel", fillConfirmationToken: token }).catch(() => undefined);
    fillConfirmationTokenRef.current = null;
    setDesktopState(state); setActiveTab("vault"); setItems([]); setSelectedIds(new Set()); setPage(1); setQuery(""); setActiveType("全部");
    setAdding(null); setEditingItem(null); setPageInformation(null); setPageInformationBusy(false); setEmailOtpCandidates([]); setEmailOtpBoostExpiresAt(0); setEmailOtpFillingId(null);
    setFillConfirmation(null); setFillConfirmationToken(null); setFillConfirmationPassword(""); setFillConfirmationError(null);
    setFillConfirmationBusy(false); setFillState("idle"); setFillOutcome(null);
    setCopyConfirmation(null); setCopyConfirmationPassword(""); setCopyConfirmationError(null); setCopyConfirmationBusy(false);
    setSaveCapturePrompt(null); setSaveCaptureError(null); setSaveCaptureBusy(false); setFillHistory([]); setNotice(null);
  }

  async function refreshWorkspace(options: { assumeUnlocked?: boolean; preferCached?: boolean } = {}) {
    const loadSequence = ++workspaceLoadSequence.current;
    setLoading(true);
    setSelectedIds(new Set());
    setNotice(null);
    try {
      const freshWorkspace = loadPopupWorkspace(options).then(
        (result) => ({ result, error: null }),
        (error: unknown) => ({ result: null, error }),
      );
      if (options.preferCached) {
        const cached = await loadCachedPopupWorkspace();
        if (cached && loadSequence === workspaceLoadSequence.current) {
          setHasVault(cached.hasVault);
          setItems(toVaultItems(cached.snapshot));
          setDesktopState("ready");
        }
      }
      const fresh = await freshWorkspace;
      if (loadSequence !== workspaceLoadSequence.current) return false;
      if (fresh.error) throw fresh.error;
      const result = fresh.result;
      if (!result) throw new Error("无法读取保险库。");
      setHasVault(result.hasVault);
      if (result.state === "locked") {
        setDesktopState("locked");
        setItems([]);
        setFillHistory([]);
        return false;
      }
      setItems(toVaultItems(result.snapshot));
      setFillHistory(result.history);
      setDesktopState("ready");
      void loadPopupSuggestionIds().then((suggestedIds) => {
        if (!suggestedIds || loadSequence !== workspaceLoadSequence.current) return;
        setItems(toVaultItems(result.snapshot, suggestedIds));
      });
      return true;
    } catch (error) {
      if (loadSequence !== workspaceLoadSequence.current) return false;
      if (error instanceof DesktopRpcError && error.code === "unlock-required") {
        setDesktopState("locked");
        setItems([]);
        setFillHistory([]);
      } else {
        try {
          const status = await getDesktopStatus();
          setHasVault(status.hasVault);
          setDesktopState(status.unlocked ? "error" : "locked");
        } catch {
          setDesktopState("unavailable");
        }
        setItems([]);
        setFillHistory([]);
      }
      return false;
    } finally {
      if (loadSequence === workspaceLoadSequence.current) setLoading(false);
    }
  }

  useEffect(() => {
    let active = true;
    if (new URLSearchParams(window.location.search).get("tab") !== "generator") {
      void refreshWorkspace({ preferCached: !initialWorkspace });
    } else {
      setLoading(false);
      void getDesktopStatus().then((status) => {
        if (!active) return;
        setHasVault(status.hasVault);
        setDesktopState(status.unlocked ? "ready" : "locked");
      }).catch(() => { if (active) setDesktopState("unavailable"); });
    }
    void browser.runtime.sendMessage({ kind: "vaultmesh.fill-confirmation.get" }).then((response) => {
      if (!active || !response || typeof response !== "object") return;
      const pending = response as { fillConfirmationToken?: unknown; requiresPassword?: unknown; selectedItem?: { id?: unknown; title?: unknown; kind?: unknown } };
      if (typeof pending.fillConfirmationToken !== "string" || !["login", "card", "identity", "secret", "ssh"].includes(String(pending.selectedItem?.kind)) || typeof pending.selectedItem?.id !== "string" || typeof pending.selectedItem.title !== "string") return;
      const type = itemTypeForKind(pending.selectedItem.kind as "login" | "card" | "identity" | "secret" | "ssh");
      setFillConfirmationToken(pending.fillConfirmationToken);
      setFillConfirmation({ id: pending.selectedItem.id, title: pending.selectedItem.title, detail: type, type, masterPasswordReprompt: pending.requiresPassword === true });
      setFillConfirmationPassword("");
      setFillConfirmationError(null);
    }).catch(() => undefined);
    return () => { active = false; workspaceLoadSequence.current += 1; setItems([]); setSelectedIds(new Set()); };
  }, []);

  useEffect(() => {
    fillConfirmationTokenRef.current = fillConfirmationToken;
  }, [fillConfirmationToken]);

  useEffect(() => {
    const clearSensitivePrompt = () => {
      if (!document.hidden) return;
      if (fillConfirmationToken) void browser.runtime.sendMessage({ kind: "vaultmesh.fill-confirmation.cancel", fillConfirmationToken }).catch(() => undefined);
      setFillConfirmation(null); setFillConfirmationToken(null); setFillConfirmationPassword(""); setFillConfirmationError(null);
      setCopyConfirmation(null); setCopyConfirmationPassword(""); setCopyConfirmationError(null);
    };
    document.addEventListener("visibilitychange", clearSensitivePrompt);
    return () => document.removeEventListener("visibilitychange", clearSensitivePrompt);
  }, [fillConfirmationToken]);

  useEffect(() => {
    if (desktopState !== "ready") return;
    let active = true;
    let inFlight = false;
    let after = 0;
    let initialized = false;
    const poll = async () => {
      if (inFlight) return;
      inFlight = true;
      try {
        if (!initialized) {
          after = (await pollDesktopEvents(0)).sequence;
          initialized = true;
        }
        const [status, eventBatch] = await Promise.all([getDesktopStatus(), pollDesktopEvents(after)]);
        if (!active) return;
        after = eventBatch.sequence;
        const invalidation = popupSessionInvalidation(status, eventBatch.events);
        if (invalidation) invalidatePopupSession(invalidation);
      } catch {
        if (active) invalidatePopupSession("unavailable");
      } finally {
        inFlight = false;
      }
    };
    void poll();
    const timer = setInterval(poll, 1_500);
    return () => { active = false; clearInterval(timer); };
  }, [desktopState]);

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      const response = SaveCapturePendingResponseSchema.safeParse(
        await browser.runtime.sendMessage({ kind: "vaultmesh.save-capture-popup.get" }).catch(() => null),
      );
      if (!active || !response.success) return;
      if (response.data.status === "queued") {
        const prompt = response.data;
        setSaveCapturePrompt((current) => current?.captureId === prompt.captureId && current.expiresAt === prompt.expiresAt ? current : prompt);
      } else if (response.data.status === "none") {
        setSaveCapturePrompt((current) => current && current.expiresAt <= Date.now() ? null : current);
      }
    };
    void refresh();
    const timer = setInterval(refresh, 500);
    return () => { active = false; clearInterval(timer); };
  }, []);

  useEffect(() => {
    if (!saveCapturePrompt) {
      setSaveCaptureClock(saveCaptureCountdown(0));
      return;
    }
    const updateCountdown = () => setSaveCaptureClock(saveCaptureCountdown(saveCapturePrompt.expiresAt));
    updateCountdown();
    const countdown = setInterval(updateCountdown, 100);
    const timeout = setTimeout(() => void decideSaveCapture("ignore"), Math.max(0, saveCapturePrompt.expiresAt - Date.now()));
    return () => { clearInterval(countdown); clearTimeout(timeout); };
  }, [saveCapturePrompt?.captureId, saveCapturePrompt?.expiresAt]);

  useEffect(() => {
    if (desktopState !== "ready" || activeTab !== "vault") {
      setEmailOtpCandidates([]);
      setEmailOtpBoostExpiresAt(0);
      return;
    }
    let active = true;
    const refresh = async () => {
      try {
        const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
        const origin = httpOrigin(tab?.url);
        if (!origin) throw new Error("unsupported page");
        const result = await getEmailOtpCandidates(origin);
        if (!active) return;
        setEmailOtpCandidates(result.candidates);
        setEmailOtpBoostExpiresAt(result.boostExpiresAt);
      } catch {
        if (!active) return;
        setEmailOtpCandidates([]);
        setEmailOtpBoostExpiresAt(0);
      }
    };
    void refresh();
    const timer = setInterval(refresh, 3_000);
    return () => {
      active = false;
      clearInterval(timer);
      setEmailOtpCandidates([]);
      setEmailOtpBoostExpiresAt(0);
    };
  }, [activeTab, desktopState]);

  const filteredItems = useMemo(() => {
    const term = query.trim().toLocaleLowerCase();
    return items.filter((item) => {
      const typeMatches = activeType === "全部" || item.type === activeType;
      return typeMatches && (!term || `${item.title} ${item.detail}`.toLocaleLowerCase().includes(term));
    });
  }, [activeType, items, query]);

  const pagination = useMemo(() => paginateVaultItems(filteredItems, page), [filteredItems, page]);
  const pageItems = pagination.items;
  const suggestedItems = pageItems.filter((item) => item.suggested);
  const otherItems = pageItems.filter((item) => !item.suggested);
  const allPageSelected = pageItems.length > 0 && pageItems.every((item) => selectedIds.has(item.id));

  useEffect(() => { setPage(1); setSelectedIds(new Set()); }, [activeType, query]);
  useEffect(() => { if (page !== pagination.page) setPage(pagination.page); }, [page, pagination.page]);

  if (desktopState === "locked" && activeTab === "vault") {
    return <PopupUnlockPage hasVault={hasVault} onUnlocked={() => refreshWorkspace({ assumeUnlocked: true })} />;
  }

  function toggleSelection(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (allPageSelected) pageItems.forEach((item) => next.delete(item.id));
      else pageItems.forEach((item) => next.add(item.id));
      return next;
    });
  }

  async function deleteSelectedItems() {
    const selected = items.filter((entry) => selectedIds.has(entry.id));
    const includesSecret = selected.some((entry) => entry.type === "机密" || entry.passkeyOnly);
    if (selectedIds.size === 0 || !window.confirm(includesSecret ? `确定删除选中的 ${selectedIds.size} 个项目？其中的机密项目会被永久删除，无法恢复。` : `确定删除选中的 ${selectedIds.size} 个项目？`)) return;
    try {
      for (const item of selected) await confirmedDesktopRpc(`${item.passkeyOnly ? "secrets" : operationPrefix(item.type)}.delete` as Operation, { id: item.id });
      setSelectedIds(new Set());
      await refreshWorkspace();
      setNotice(includesSecret ? "选中项目已删除；机密项目已永久删除，其余项目已移到加密回收站。" : "选中项目已移到加密回收站。", "success");
    } catch (error) { setNotice(error instanceof Error ? error.message : "删除失败。", "error"); }
  }

  async function deleteItem(item: VaultItem) {
    const permanent = item.type === "机密" || item.passkeyOnly;
    if (!window.confirm(permanent
      ? `永久删除“${item.title}”？此项目不会进入回收站，操作无法撤销。`
      : `删除“${item.title}”？项目会移到加密回收站。`)) return;
    try {
      await confirmedDesktopRpc(`${item.passkeyOnly ? "secrets" : operationPrefix(item.type)}.delete` as Operation, { id: item.id });
      setSelectedIds((current) => { const next = new Set(current); next.delete(item.id); return next; });
      await refreshWorkspace();
      setNotice(permanent ? "项目已永久删除。" : "项目已移到加密回收站。", "success");
    } catch (error) { setNotice(error instanceof Error ? error.message : "删除失败。", "error"); }
  }

  async function copyItem(item: VaultItem, option: string) {
    if (item.masterPasswordReprompt) {
      setCopyConfirmation({ item, option });
      setCopyConfirmationPassword("");
      setCopyConfirmationError(null);
      return;
    }
    try { await executeCopy(item, option); setNotice("已复制，桌面端将自动清除剪贴板。", "success"); }
    catch (error) { setNotice(error instanceof Error ? error.message : "复制失败。", "error"); }
  }

  async function executeCopy(item: VaultItem, option: string, masterPassword?: string) {
    const operation = item.type === "登录" ? option === "用户名" ? "items.copy-username" : option === "验证码" ? "items.copy-totp" : "items.copy-password" : item.type === "支付卡" ? option === "卡号" ? "cards.copy-number" : option === "安全码" ? "cards.copy-security-code" : "cards.copy-pin" : item.type === "机密" ? "secrets.copy-value" : option === "密码" ? "ssh.copy-password" : option === "公钥" ? "ssh.copy-public-key" : option === "口令" ? "ssh.copy-key-passphrase" : "ssh.copy-private-key";
    await desktopRpc(operation, { id: item.id, masterPassword: masterPassword ?? null });
  }

  async function confirmCopy() {
    if (!copyConfirmation || copyConfirmationBusy || copyConfirmationPassword.length < 8) return;
    const pending = copyConfirmation;
    const password = copyConfirmationPassword;
    setCopyConfirmationPassword("");
    setCopyConfirmationBusy(true);
    setCopyConfirmationError(null);
    try {
      await executeCopy(pending.item, pending.option, password);
      setNotice("已复制，桌面端将自动清除剪贴板。", "success");
      setCopyConfirmation(null);
    } catch (error) {
      setCopyConfirmationError(error instanceof Error ? error.message : "复制失败。");
    } finally { setCopyConfirmationBusy(false); }
  }

  async function openItemWebsite(item: VaultItem) {
    if (!item.url || !isHttpUrl(item.url)) return;
    try { await browser.tabs.create({ url: item.url }); }
    catch { setNotice("无法打开条目网站。", "error"); }
  }

  async function requestFill(item: VaultItem) {
    if (!requiresFillPassword(item)) {
      await executeFill(item);
      return;
    }
    setFillConfirmation(item);
    setFillConfirmationToken(null);
    setFillConfirmationPassword("");
    setFillConfirmationError(null);
  }

  async function fillEmailOtp(candidate: EmailOtpCandidate) {
    if (emailOtpFillingId) return;
    setEmailOtpFillingId(candidate.id);
    setNotice(null);
    try {
      const response = await browser.runtime.sendMessage({ kind: "vaultmesh.email-otp-fill", candidateId: candidate.id });
      if (response?.status === "filled") {
        setEmailOtpCandidates((current) => current.filter((entry) => entry.id !== candidate.id));
        setNotice("邮箱验证码已填入当前网页，VaultMesh 未提交表单。", "success");
      } else if (response?.status === "no-supported-fields") {
        setNotice("当前网页没有可安全填入的空验证码字段。", "warning");
      } else {
        setNotice(typeof response?.errorMessage === "string" ? response.errorMessage : "邮箱验证码填入失败，请重试。", "error");
      }
    } catch {
      setNotice("无法连接当前网页或 VaultMesh 桌面端。", "error");
    } finally {
      setEmailOtpFillingId(null);
    }
  }

  async function executeFill(item: VaultItem, masterPassword?: string, confirmationToken?: string) {
    setNotice(null);
    setFillOutcome(null);
    setFillState("pending");
    try {
      const kind = itemKindForType(item.type);
      const response = await browser.runtime.sendMessage({
        kind: "vaultmesh.start-fill",
        selectedItem: { kind, id: item.id, title: item.title },
        ...(masterPassword ? { masterPassword } : {}),
        ...(confirmationToken ? { fillConfirmationToken: confirmationToken } : {}),
      });
      if (response?.status === "filled") setFillState("sent");
      else if (response?.status === "desktop-unavailable") setFillState("unavailable");
      else if (response?.status === "unlock-required") setFillState("locked");
      else if (response?.status === "cancelled") setFillState("cancelled");
      else if (response?.status === "no-supported-fields") setFillState("no-fields");
      else setFillState("unsupported");
      if (response?.topOrigin) setFillOutcome(`${response.topOrigin} · ${item.title} · ${response.assignmentCount ?? 0} 个字段`);
      return response;
    } catch {
      setFillState("unsupported");
      return null;
    }
  }

  async function confirmFill() {
    if (!fillConfirmation || (requiresFillPassword(fillConfirmation) && fillConfirmationPassword.length < 8) || fillConfirmationBusy) return;
    const password = requiresFillPassword(fillConfirmation) ? fillConfirmationPassword : undefined;
    setFillConfirmationBusy(true);
    setFillConfirmationError(null);
    const response = await executeFill(fillConfirmation, password, fillConfirmationToken ?? undefined);
    setFillConfirmationPassword("");
    setFillConfirmationBusy(false);
    if (response?.status === "filled") {
      setFillConfirmation(null);
      setFillConfirmationToken(null);
      window.close();
      return;
    }
    setFillConfirmationError(typeof response?.errorMessage === "string" ? response.errorMessage : `${fillConfirmation.type}填充失败，请重试。`);
  }

  async function decideSaveCapture(decision: "save" | "ignore") {
    if (!saveCapturePrompt || saveCaptureBusy) return;
    const captureId = saveCapturePrompt.captureId;
    setSaveCaptureBusy(true);
    setSaveCaptureError(null);
    const response = SaveCaptureDecisionResponseSchema.safeParse(await browser.runtime.sendMessage({
      kind: "vaultmesh.save-capture-popup.decision",
      captureId,
      decision,
    }).catch(() => null));
    if (response.success && ["saved", "discarded", "expired"].includes(response.data.status)) {
      setSaveCapturePrompt(null);
      setSaveCaptureBusy(false);
      window.close();
      return;
    }
    setSaveCaptureBusy(false);
    setSaveCaptureError(response.success && response.data.status === "unsupported-page"
      ? "此确认请求不属于当前扩展页面。"
      : "保存失败。请先解锁 VaultMesh，然后重新登录。"
    );
  }

  function cancelFill() {
    if (fillConfirmationBusy) return;
    if (fillConfirmationToken) void browser.runtime.sendMessage({ kind: "vaultmesh.fill-confirmation.cancel", fillConfirmationToken }).catch(() => undefined);
    setFillConfirmation(null);
    setFillConfirmationToken(null);
    setFillConfirmationPassword("");
    setFillConfirmationError(null);
  }

  async function recognizeCurrentPage() {
    if (pageInformationBusy) return;
    setPageInformationBusy(true);
    setNotice(null);
    try {
      const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
      if (tab?.id == null || !isHttpUrl(tab.url)) {
        setPageInformation(null);
        setNotice("只能识别普通 HTTP(S) 网页中的信息。", "warning");
        return;
      }
      const response = PageInformationDetectionResponseSchema.safeParse(await browser.tabs.sendMessage(
        tab.id,
        { kind: "vaultmesh.detect-page-information" },
        { frameId: 0 },
      ));
      if (!response.success || response.data.status === "unsupported-page") {
        setPageInformation(null);
        setNotice("当前页面暂不支持识别，请重新加载网页和 VaultMesh 扩展后重试。", "warning");
      } else if (response.data.status === "empty") {
        setPageInformation(null);
        setNotice("当前页面没有识别到可保存的登录、个人资料、支付卡、机密信息或 SSH 凭据。", "info");
      } else {
        setAdding(null);
        setPageInformation({ tabId: tab.id, capture: response.data });
      }
    } catch {
      setPageInformation(null);
      setNotice("无法读取当前页面。请确认 VaultMesh 拥有该网站权限，并重新加载网页。", "error");
    } finally {
      setPageInformationBusy(false);
    }
  }

  async function scanCurrentPageTotp(): Promise<TotpQrCode | null> {
    setNotice(null);
    try {
      const [tab] = await browser.tabs.query({ active: true, lastFocusedWindow: true });
      if (tab?.id == null || !isHttpUrl(tab.url)) {
        setNotice("只能扫描普通 HTTP(S) 网页中的验证器二维码。", "warning");
        return null;
      }
      const frames = await browser.webNavigation.getAllFrames({ tabId: tab.id }).catch(() => null);
      const frameIds = frames?.length ? frames.map((frame) => frame.frameId) : [0];
      const responses = await Promise.all(frameIds.map(async (frameId) => {
        try {
          return TotpQrScanResponseSchema.safeParse(await browser.tabs.sendMessage(
            tab.id!,
            { kind: "vaultmesh.scan-totp-qr" },
            { frameId },
          ));
        } catch {
          return null;
        }
      }));
      const values = uniqueTotpQrCodes(responses.flatMap((response) => response?.success && response.data.status === "found" ? response.data.values : []));
      if (!values.length) {
        setNotice("当前网页没有识别到 TOTP 验证器二维码。请让二维码保持可见后重试。", "info");
        return null;
      }
      return chooseTotpQrCode(values);
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "扫描或保存验证器密钥失败。", "error");
      return null;
    }
  }

  async function saveCurrentPageInformation(data: DetectedPageInformation["data"]) {
    if (!pageInformation || pageInformationBusy) return;
    setPageInformationBusy(true);
    setNotice(null);
    try {
      const response = PageInformationSaveResponseSchema.safeParse(await browser.tabs.sendMessage(
        pageInformation.tabId,
        {
          kind: "vaultmesh.save-page-information",
          captureId: pageInformation.capture.captureId,
          pageUrl: pageInformation.capture.pageUrl,
          data,
        },
        { frameId: 0 },
      ));
      if (!response.success) {
        setNotice("保存结果无法确认，请重新识别后再试。", "error");
      } else if (response.data.status === "saved") {
        setPageInformation(null);
        await refreshWorkspace();
        setNotice("识别到的信息已保存到保险库。", "success");
      } else if (response.data.status === "unchanged") {
        setPageInformation(null);
        setNotice("保险库中已有相同信息，无需重复保存。", "info");
      } else if (response.data.status === "account-check-failed" || response.data.status === "save-check-failed") {
        setNotice("无法核对保险库中的已有项目。请确认插件已解锁后重试。", "error");
      } else if (response.data.status === "unsupported-page") {
        setNotice("页面已切换或来源不一致，请重新识别当前页面。", "warning");
      } else if (response.data.status === "expired") {
        setNotice("本次识别结果已过期，请重新识别后保存。", "warning");
      } else if (response.data.status === "failed") {
        const item = response.data.failedItem ? `“${response.data.failedItem}”` : "识别到的信息";
        const reason = saveFailureReason(response.data.errorCode, response.data.errorMessage);
        setNotice(`${item}保存失败：${reason}`, "error");
      } else {
        setNotice("保存失败，请重新识别后再试。", "error");
      }
    } catch {
      setNotice("保存请求未完成。请保持当前网页打开并重试。", "error");
    } finally {
      setPageInformationBusy(false);
    }
  }

  return (
    <main className="relative flex h-full w-full flex-col gap-3 overflow-hidden p-3">
      <section className="flex min-h-0 flex-1 flex-col gap-3" aria-busy={activeTab === "vault" && loading}>
        {activeTab === "vault" && pageInformation ? <PageInformationPanel capture={pageInformation.capture} busy={pageInformationBusy} onCancel={() => setPageInformation(null)} onRescan={() => void recognizeCurrentPage()} onSave={(data) => void saveCurrentPageInformation(data)} /> : activeTab === "vault" && editingItem?.type === "登录" ? <EditLoginPanel id={editingItem.id} onCancel={() => setEditingItem(null)} onPasskeysChanged={async () => { await refreshWorkspace(); setNotice("Passkey 已从 VaultMesh 永久删除；网站端登记不会自动撤销。", "success"); }} onScanTotp={scanCurrentPageTotp} onSaved={async () => { setEditingItem(null); await refreshWorkspace(); setNotice("登录信息已更新。", "success"); }} /> : activeTab === "vault" && editingItem ? <AddItemPanel kind={addKindForType(editingItem.type)} editId={editingItem.id} onCancel={() => setEditingItem(null)} onSaved={async () => { const type = editingItem.type; setEditingItem(null); await refreshWorkspace(); setNotice(`${type}已更新。`, "success"); }} /> : activeTab === "vault" && adding ? <AddItemPanel kind={adding} onCancel={() => setAdding(null)} onSaved={async () => { setAdding(null); await refreshWorkspace(); setNotice("项目已保存到保险库。", "success"); }} /> : activeTab === "vault" ? (
          <>
          {shouldShowDesktopConnection(desktopState, loading) ? <DesktopConnection state={desktopState} /> : null}
          <div className="flex shrink-0 items-center gap-2">
            <Tabs className="min-w-0 flex-1" value={activeType} onValueChange={(value) => setActiveType(value as VaultItemType)}>
              <TabsList className="w-full justify-start overflow-x-auto">
                {typeTabs.map((type) => <TabsTrigger key={type} size="sm" value={type}>{type}</TabsTrigger>)}
              </TabsList>
            </Tabs>
            <Button aria-label="刷新保险库" size="icon-sm" variant="ghost" type="button" disabled={loading} onClick={() => void refreshWorkspace()}><RefreshCwIcon /></Button>
          </div>

          <div className="flex shrink-0 gap-2">
            <label className="flex min-w-0 flex-1 items-center gap-2 rounded-lg border border-input bg-transparent px-2.5">
              <SearchIcon size={16} aria-hidden="true" />
              <input className="h-8 min-w-0 flex-1 bg-transparent text-sm outline-none" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索" aria-label="搜索密码库" />
            </label>
            <Button size="sm" variant="outline" type="button" disabled={pageInformationBusy || desktopState !== "ready"} onClick={() => void recognizeCurrentPage()}>
              <ScanSearchIcon data-icon="inline-start" aria-hidden="true" />
              {pageInformationBusy ? "识别中" : "识别"}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger render={<Button size="sm" type="button"><PlusIcon data-icon="inline-start" aria-hidden="true" />添加</Button>} />
              <DropdownMenuContent>
                {ADD_ITEM_OPTIONS.map((option) => { const Icon = option.icon; return <DropdownMenuItem key={option.kind} onClick={() => setAdding(option.kind)}><Icon />{option.label}</DropdownMenuItem>; })}
                <DropdownMenuItem onClick={() => setNotice("请在网站的账户安全设置中选择“创建 Passkey”。VaultMesh 会接管注册并自动加密保存，Passkey 必须由网站挑战绑定，不能脱离网站手动生成。", "info")}><FingerprintIcon />Passkey</DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>

          {loading && desktopState !== "ready" ? <VaultWorkspaceSkeleton /> : <ScrollArea className="-mr-3 min-h-0 flex-1">
            <div className="flex flex-col gap-4 pr-4">
              {emailOtpCandidates.length > 0 || emailOtpBoostExpiresAt > Math.floor(Date.now() / 1_000) ? (
                <section className="flex flex-col gap-2" aria-label="邮箱验证码">
                  <div className="flex items-center justify-between gap-2">
                    <ListHeading title="邮箱验证码" count={emailOtpCandidates.length} />
                    {emailOtpBoostExpiresAt > Math.floor(Date.now() / 1_000) ? <Badge variant="secondary">高频监听中</Badge> : null}
                  </div>
                  {emailOtpCandidates.map((candidate) => (
                    <div key={candidate.id} className="flex items-center gap-3 rounded-lg border border-input px-3 py-2">
                      <span className="grid size-9 shrink-0 place-items-center rounded-lg bg-muted"><MailIcon size={18} /></span>
                      <div className="min-w-0 flex-1">
                        <div className="font-mono text-base font-semibold tracking-wider">{candidate.code}</div>
                        <div className="truncate text-xs text-muted-foreground">{candidate.sourceDomain} · {formatOtpReceivedAt(candidate.receivedAt)}</div>
                      </div>
                      <Button size="sm" type="button" disabled={emailOtpFillingId !== null} onClick={() => void fillEmailOtp(candidate)}>{emailOtpFillingId === candidate.id ? "填入中" : "填入"}</Button>
                    </div>
                  ))}
                  {emailOtpCandidates.length === 0 ? <EmptyList>正在等待新的邮箱验证码…</EmptyList> : null}
                </section>
              ) : null}
              {suggestedItems.length > 0 ? <section className="flex flex-col gap-2">
                <ListHeading title="自动填充建议" count={suggestedItems.length} />
                {suggestedItems.map((item) => <VaultRow key={item.id} item={item} showFill fillState={fillState} onEdit={() => setEditingItem(item)} onDelete={() => void deleteItem(item)} onOpen={() => void openItemWebsite(item)} onFill={() => void requestFill(item)} onCopy={(option) => void copyItem(item, option)} />)}
                <FillNotice state={fillState} outcome={fillOutcome} />
              </section> : <FillNotice state={fillState} outcome={fillOutcome} />}

              <section className="flex flex-col gap-2">
                <div className="flex items-center justify-between gap-2">
                  <ListHeading title={suggestedItems.length > 0 ? "本页其他项目" : "所有项目"} count={otherItems.length} />
                  <Button size="sm" variant="ghost" type="button" onClick={toggleSelectAll} disabled={pageItems.length === 0}><CheckIcon data-icon="inline-start" aria-hidden="true" />{allPageSelected ? "取消本页" : "全选本页"}</Button>
                </div>
                {selectedIds.size > 0 ? (
                  <div className="flex items-center justify-between rounded-lg border border-input bg-muted/50 px-2.5 py-2">
                    <span className="text-sm">已选择 {selectedIds.size} 项</span>
                    <div className="flex gap-1">
                      <Button size="xs" variant="ghost" type="button" onClick={() => void deleteSelectedItems()}>删除</Button>
                      <Button size="xs" variant="ghost" type="button" onClick={() => setSelectedIds(new Set())}>取消选择</Button>
                    </div>
                  </div>
                ) : null}
                {otherItems.map((item) => <VaultRow key={item.id} item={item} selected={selectedIds.has(item.id)} selectable showFill fillState={fillState} onToggle={() => toggleSelection(item.id)} onEdit={() => setEditingItem(item)} onDelete={() => void deleteItem(item)} onOpen={() => void openItemWebsite(item)} onFill={() => void requestFill(item)} onCopy={(option) => void copyItem(item, option)} />)}
                {filteredItems.length === 0 ? <EmptyList>{desktopState === "ready" ? "没有匹配的密码库项目。" : "连接桌面端并在插件中解锁后即可查看保险库。"}</EmptyList> : null}
                {filteredItems.length > 0 ? <div className="flex items-center justify-between gap-2 border-t pt-2" aria-label="密码库分页">
                  <Button size="sm" variant="outline" type="button" disabled={pagination.page <= 1} onClick={() => setPage((current) => current - 1)}>上一页</Button>
                  <span className="text-xs text-muted-foreground">第 {pagination.page} / {pagination.pageCount} 页 · 共 {filteredItems.length} 项</span>
                  <Button size="sm" variant="outline" type="button" disabled={pagination.page >= pagination.pageCount} onClick={() => setPage((current) => current + 1)}>下一页</Button>
                </div> : null}
              </section>
            </div>
          </ScrollArea>}
          </>
        ) : activeTab === "generator" ? <GeneratorPanel onNotice={setNotice} /> : <SettingsPanel fillHistory={fillHistory} recoveryTargets={recoveryTargets(items)} onRecoveryChanged={async () => { await refreshWorkspace(); }} onNotice={setNotice} onLocked={() => { setActiveTab("vault"); void refreshWorkspace(); }} />}
      </section>

      <ToastMessage id="popup-notice" message={notice?.message ?? null} variant={notice?.variant ?? "default"} />
      <nav className="-mx-3 -mb-3 mt-auto grid shrink-0 grid-cols-3 bg-muted/70 px-3 py-1" aria-label="密码库导航">
        <BottomNavigationItem active={activeTab === "vault"} icon={LockKeyholeIcon} label="密码库" onClick={() => { setAdding(null); setEditingItem(null); setActiveTab("vault"); }} />
        <BottomNavigationItem active={activeTab === "generator"} icon={SparklesIcon} label="生成器" onClick={() => { setAdding(null); setEditingItem(null); setActiveTab("generator"); }} />
        <BottomNavigationItem active={activeTab === "settings"} icon={SettingsIcon} label="设置" onClick={() => { setAdding(null); setEditingItem(null); setActiveTab("settings"); }} />
      </nav>
      {fillConfirmation ? (
        <div className="absolute inset-0 z-10 grid place-items-center bg-background/90 p-3 backdrop-blur-sm">
          <Card className="w-full">
            <CardContent className="flex flex-col gap-4">
              <span className="grid size-12 place-items-center rounded-xl bg-muted"><FillItemIcon item={fillConfirmation} /></span>
              <div>
                <h2 className="text-lg font-semibold">确认填充{fillConfirmation.type}</h2>
                <p className="text-sm text-muted-foreground">{requiresFillPassword(fillConfirmation) ? "输入主密码后，" : "确认后，"}将把 {fillConfirmation.title} 填充到当前网页的空字段，已有内容会保留。</p>
              </div>
              {requiresFillPassword(fillConfirmation) ? <input
                className="h-10 rounded-md border border-input bg-background px-3 text-sm"
                type="password"
                value={fillConfirmationPassword}
                autoFocus
                autoComplete="current-password"
                onChange={(event) => setFillConfirmationPassword(event.target.value)}
                onKeyDown={(event) => { if (event.key === "Enter") void confirmFill(); }}
                placeholder="主密码（至少 8 位）"
                disabled={fillConfirmationBusy}
              /> : null}
              <ToastMessage id="fill-confirmation-error" message={fillConfirmationError} variant="error" />
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" disabled={fillConfirmationBusy} onClick={cancelFill}>取消</Button>
                <Button type="button" disabled={fillConfirmationBusy || (requiresFillPassword(fillConfirmation) && fillConfirmationPassword.length < 8)} onClick={() => void confirmFill()}>{fillConfirmationBusy ? "正在确认…" : "确认并填充"}</Button>
              </div>
            </CardContent>
          </Card>
        </div>
      ) : null}
      {copyConfirmation ? (
        <div className="absolute inset-0 z-20 grid place-items-center bg-background/90 p-3 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="copy-confirmation-title">
          <Card className="w-full"><CardContent className="flex flex-col gap-4">
            <div><h2 id="copy-confirmation-title" className="text-lg font-semibold">确认复制{copyConfirmation.option}</h2><p className="text-sm text-muted-foreground">“{copyConfirmation.item.title}”要求主密码重新验证；值只会写入桌面安全剪贴板。</p></div>
            <input className="h-10 rounded-md border border-input bg-background px-3 text-sm" type="password" value={copyConfirmationPassword} autoFocus autoComplete="current-password" onChange={(event) => setCopyConfirmationPassword(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") void confirmCopy(); }} placeholder="主密码（至少 8 位）" disabled={copyConfirmationBusy} />
            <ToastMessage id="copy-confirmation-error" message={copyConfirmationError} variant="error" />
            <div className="flex justify-end gap-2"><Button variant="ghost" disabled={copyConfirmationBusy} onClick={() => { setCopyConfirmation(null); setCopyConfirmationPassword(""); setCopyConfirmationError(null); }}>取消</Button><Button disabled={copyConfirmationBusy || copyConfirmationPassword.length < 8} onClick={() => void confirmCopy()}>{copyConfirmationBusy ? "正在验证…" : "确认并复制"}</Button></div>
          </CardContent></Card>
        </div>
      ) : null}
      {saveCapturePrompt ? (
        <div className="absolute inset-0 z-20 grid place-items-center bg-background/95 p-3 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="save-capture-popup-title">
          <Card className="w-full">
            <CardContent className="flex flex-col gap-4">
              <span className="grid size-12 place-items-center rounded-xl bg-primary text-primary-foreground"><KeyRoundIcon /></span>
              <div className="space-y-1">
                <h2 id="save-capture-popup-title" className="text-lg font-semibold">{saveCapturePromptTitle(saveCapturePrompt)}</h2>
                <p className="text-sm text-muted-foreground">{saveCapturePrompt.hostname} · {saveCapturePrompt.labels.join("、")}</p>
                <p className="text-sm text-muted-foreground">请在 {saveCaptureClock.seconds} 秒内确认；未确认不会写入保险库。</p>
              </div>
              <div className="h-1 overflow-hidden rounded-full bg-muted" aria-hidden="true"><div className="h-full origin-left bg-primary transition-transform duration-100 ease-linear" style={{ transform: `scaleX(${saveCaptureClock.progress})` }} /></div>
              <ToastMessage id="save-capture-error" message={saveCaptureError} variant="error" />
              <div className="flex justify-end gap-2">
                <Button type="button" variant="ghost" disabled={saveCaptureBusy} onClick={() => void decideSaveCapture("ignore")}>忽略</Button>
                <Button type="button" disabled={saveCaptureBusy} autoFocus onClick={() => void decideSaveCapture("save")}>{saveCaptureBusy ? "正在处理…" : saveCapturePromptActionLabel(saveCapturePrompt)}</Button>
              </div>
            </CardContent>
          </Card>
        </div>
      ) : null}
    </main>
  );
}

function saveFailureReason(code?: string, message?: string): string {
  if (code === "unlock-required") return "桌面端保险库已锁定，请解锁后重试。";
  if (code === "desktop-unavailable") return "无法连接桌面端，请确认 VaultMesh 正在运行。";
  if (message && message !== "桌面端无法完成该操作。") return `${message}（${code ?? "未知错误"}）。`;
  if (code === "invalid-input" || code === "validation-error") return "内容未通过保险库格式校验。";
  if (code === "confirmation-required") return "桌面端未确认本次写入。";
  return code ? `桌面端返回错误 ${code}，请重试。` : "请重试。";
}

type UnlockPhase = "idle" | "authenticating" | "loading";

function PopupUnlockPage({ hasVault, onUnlocked }: { hasVault: boolean; onUnlocked: () => Promise<boolean> }) {
  const [credential, setCredential] = useState("");
  const [useMasterPassword, setUseMasterPassword] = useState(false);
  const [biometric, setBiometric] = useState<{ available: boolean; enabled: boolean } | null>(null);
  const [pin, setPin] = useState<{ enabled: boolean; locked: boolean; remainingAttempts: number } | null>(null);
  const [message, setMessage] = useState(hasVault ? "在插件中解锁本机保险库。" : "尚未创建保险库，请先在 VaultMesh 桌面端创建。" );
  const [phase, setPhase] = useState<UnlockPhase>("idle");

  useEffect(() => {
    if (!hasVault) return;
    void Promise.all([desktopRpc("biometric.status"), desktopRpc("pin.status")]).then(([nextBiometric, nextPin]) => { setBiometric(nextBiometric as { available: boolean; enabled: boolean }); setPin(nextPin as { enabled: boolean; locked: boolean; remainingAttempts: number }); }).catch(() => { setBiometric(null); setPin(null); });
  }, [hasVault]);

  const pinPreferred = Boolean(pin?.enabled && !pin.locked && !useMasterPassword);
  const busy = phase !== "idle";

  async function unlock(providedValue?: string) {
    if (busy) return;
    const value = providedValue ?? credential;
    setCredential("");
    setPhase("authenticating");
    let completed = false;
    try {
      if (pinPreferred) await desktopRpc("pin.unlock", { pin: value });
      else await desktopRpc("vault.unlock", { masterPassword: value });
      setPhase("loading");
      completed = await onUnlocked();
      if (!completed) setMessage("验证已完成，但保险库状态发生变化，请重试。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "解锁失败，请重试。");
      if (pinPreferred) void desktopRpc("pin.status").then((next) => setPin(next as typeof pin));
    } finally {
      if (!completed) setPhase("idle");
    }
  }

  async function unlockWithBiometrics() {
    if (busy) return;
    setPhase("authenticating");
    let completed = false;
    try {
      await desktopRpc("biometric.unlock");
      setPhase("loading");
      completed = await onUnlocked();
      if (!completed) setMessage("验证已完成，但保险库状态发生变化，请重试。");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "生物识别解锁失败。");
    } finally {
      if (!completed) setPhase("idle");
    }
  }

  const progressText = phase === "authenticating" ? "正在安全验证…" : phase === "loading" ? "验证成功，正在读取保险库…" : null;

  return <main className="flex h-full w-full items-center p-3"><Card className="w-full"><CardContent className="flex flex-col gap-3"><span className="grid size-12 place-items-center rounded-xl bg-muted"><LockKeyholeIcon /></span><div><h1 className="text-lg font-semibold">{hasVault ? "解锁 VaultMesh 插件" : "创建 VaultMesh 保险库"}</h1><p className="text-sm text-muted-foreground">{pinPreferred ? `输入 6 位插件 PIN 后自动解锁，还可尝试 ${pin?.remainingAttempts ?? 0} 次。` : pin?.locked ? "插件 PIN 已锁定，请使用主密码解锁。" : message}</p></div>{hasVault ? <>{pinPreferred ? <InputOTP value={credential} maxLength={6} pattern={REGEXP_ONLY_DIGITS} autoComplete="off" pushPasswordManagerStrategy="none" autoFocus disabled={busy} containerClassName="justify-center" aria-label="6 位插件 PIN" onChange={setCredential} onComplete={(value) => void unlock(value)}><InputOTPGroup><InputOTPSlot index={0} mask /><InputOTPSlot index={1} mask /><InputOTPSlot index={2} mask /></InputOTPGroup><InputOTPSeparator /><InputOTPGroup><InputOTPSlot index={3} mask /><InputOTPSlot index={4} mask /><InputOTPSlot index={5} mask /></InputOTPGroup></InputOTP> : <input className="h-10 rounded-md border border-input bg-background px-3 text-sm" type="password" inputMode="text" maxLength={1_024} value={credential} autoFocus onChange={(event) => setCredential(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && credential.length >= 8 && !busy) void unlock(); }} placeholder="主密码（至少 8 位）" />}<div className={`flex min-h-5 items-center justify-center gap-2 text-sm text-muted-foreground transition-opacity duration-150 ${progressText ? "opacity-100" : "opacity-0"}`} role="status" aria-live="polite">{progressText ? <><RefreshCwIcon className="animate-spin" size={16} aria-hidden="true" /><span>{progressText}</span></> : null}</div>{!pinPreferred ? <Button disabled={busy || credential.length < 8} onClick={() => void unlock()}>{phase === "authenticating" ? "正在安全验证…" : phase === "loading" ? "正在读取保险库…" : "使用主密码解锁插件"}</Button> : null}{pin?.enabled && !pin.locked ? <Button variant="secondary" disabled={busy} onClick={() => { setCredential(""); setUseMasterPassword(pinPreferred); }}>{pinPreferred ? "改用主密码" : "改用 PIN"}</Button> : null}{biometric?.available && biometric.enabled ? <Button variant="secondary" disabled={busy} onClick={() => void unlockWithBiometrics()}>{phase === "authenticating" ? "正在等待系统验证…" : "使用生物识别解锁插件"}</Button> : null}</> : null}</CardContent></Card></main>;
}

function VaultWorkspaceSkeleton() {
  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-hidden" role="status" aria-live="polite">
      <span className="sr-only">正在读取保险库…</span>
      {["自动填充建议", "所有项目"].map((title, sectionIndex) => (
        <section key={title} className="flex flex-col gap-2" aria-hidden="true">
          <div className="flex items-center justify-between">
            <div className="h-4 w-24 animate-pulse rounded bg-muted" />
            <div className="h-4 w-8 animate-pulse rounded bg-muted" />
          </div>
          {Array.from({ length: sectionIndex + 2 }, (_, index) => (
            <div key={index} className="flex h-14 items-center gap-3 rounded-lg border border-input px-3">
              <div className="size-8 shrink-0 animate-pulse rounded-lg bg-muted" />
              <div className="flex min-w-0 flex-1 flex-col gap-2">
                <div className="h-3 w-2/5 animate-pulse rounded bg-muted" />
                <div className="h-3 w-3/5 animate-pulse rounded bg-muted" />
              </div>
            </div>
          ))}
        </section>
      ))}
    </div>
  );
}

function DesktopConnection({ state }: { state: DesktopState }) {
  const text = state === "locked" ? "插件已锁定，需要单独解锁。" : state === "error" ? "无法读取桌面端保险库。" : "未连接 VaultMesh 桌面端。";
  return <ToastMessage id="desktop-connection" message={text} variant={state === "error" ? "error" : "warning"} />;
}

function toVaultItems(snapshot: WorkspaceSnapshot, suggestedIds?: ReadonlySet<string>): VaultItem[] {
  const passkeys = snapshot.secrets.filter((item) => item.isPasskey);
  const loginIds = new Set(snapshot.items.map((item) => item.id));
  const passkeyCounts = new Map<string, number>();
  for (const passkey of passkeys) if (passkey.loginId && loginIds.has(passkey.loginId)) passkeyCounts.set(passkey.loginId, (passkeyCounts.get(passkey.loginId) ?? 0) + 1);
  return [
    ...snapshot.items.map((item) => { const passkeyCount = passkeyCounts.get(item.id) ?? 0; return { id: item.id, title: item.title, detail: [item.username || item.url || "登录信息", item.hasTotpSecret ? "验证器" : "", passkeyCount ? `${passkeyCount} 个 Passkey` : ""].filter(Boolean).join(" · "), type: "登录" as const, suggested: suggestedIds?.has(item.id) ?? false, masterPasswordReprompt: item.masterPasswordReprompt, username: item.username, hasPassword: item.hasPassword, hasTotpSecret: item.hasTotpSecret, passkeyCount, url: item.url ?? undefined }; }),
    ...passkeys.filter((item) => !item.loginId || !loginIds.has(item.loginId)).map((item) => ({ id: item.id, title: item.title, detail: [item.account, safeHostname(item.website), "仅 Passkey"].filter(Boolean).join(" · "), type: "登录" as const, suggested: false, passkeyOnly: true, passkeyCount: 1 })),
    ...snapshot.identities.map((item) => ({ id: item.id, title: item.title, detail: item.displayName || item.organization || "身份信息", type: "身份" as const, suggested: suggestedIds?.has(item.id) ?? false })),
    ...snapshot.cards.map((item) => ({ id: item.id, title: item.title, detail: `${item.cardholderName} · ${item.maskedNumber}`, type: "支付卡" as const, suggested: suggestedIds?.has(item.id) ?? false, masterPasswordReprompt: item.masterPasswordReprompt, hasSecurityCode: item.hasSecurityCode, hasPin: item.hasPin })),
    ...snapshot.sshCredentials.map((item) => ({ id: item.id, title: item.title, detail: item.host ? `${item.username}@${item.host}` : item.username || "SSH 凭据", type: "SSH" as const, suggested: suggestedIds?.has(item.id) ?? false, masterPasswordReprompt: item.masterPasswordReprompt, hasSshPassword: item.hasPassword, hasPublicKey: item.hasPublicKey, hasPrivateKey: item.hasPrivateKey, hasKeyPassphrase: item.hasKeyPassphrase })),
    ...snapshot.secrets.filter((item) => !item.isPasskey).map((item) => ({ id: item.id, title: item.title, detail: [secretSummaryLabel(item.kind), item.provider, item.account, item.environment].filter(Boolean).join(" · "), type: "机密" as const, suggested: suggestedIds?.has(item.id) ?? false, masterPasswordReprompt: item.masterPasswordReprompt, url: item.website ?? undefined })),
  ];
}

function recoveryTargets(items: VaultItem[]): RecoveryTarget[] {
  return items.flatMap((item) => {
    if (item.passkeyOnly || item.type === "机密") return [];
    const kind = item.type === "登录" ? "login" : item.type === "支付卡" ? "card" : item.type === "身份" ? "identity" : "ssh";
    return [{ id: item.id, kind, title: item.title, detail: item.detail }];
  });
}

function secretSummaryLabel(kind: string): string {
  const labels: Record<string, string> = {
    "api-key": "API Key", "access-token": "访问令牌", "authenticator-key": "认证密钥", "client-secret": "客户端密钥",
    "webhook-secret": "Webhook 密钥", "database-credential": "数据库凭据", "recovery-codes": "恢复码", certificate: "证书与 PEM",
    "software-license": "软件许可证", "identity-document": "身份证件", "secure-note": "安全笔记", "crypto-wallet": "加密钱包", other: "其他机密",
  };
  return labels[kind] ?? "机密信息";
}

function safeHostname(value: string | null) {
  if (!value) return null;
  try { return new URL(value).hostname; } catch { return null; }
}

function isHttpUrl(value?: string): boolean {
  if (!value) return false;
  try { return ["http:", "https:"].includes(new URL(value).protocol); } catch { return false; }
}

function httpOrigin(value?: string): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    return ["http:", "https:"].includes(url.protocol) ? url.origin : null;
  } catch {
    return null;
  }
}

function formatOtpReceivedAt(receivedAt: number): string {
  const elapsed = Math.max(0, Math.floor(Date.now() / 1_000) - receivedAt);
  if (elapsed < 10) return "刚刚收到";
  if (elapsed < 60) return `${elapsed} 秒前`;
  return `${Math.floor(elapsed / 60)} 分钟前`;
}

function ListHeading({ title, count }: { title: string; count: number }) {
  return <div className="flex min-w-0 items-center gap-2"><h2 className="text-sm font-medium">{title}</h2><Badge variant="secondary">{count}</Badge></div>;
}

function EmptyList({ children }: { children: string }) {
  return <ToastMessage id="empty-vault-list" message={children} variant="info" />;
}

function itemTypeForKind(kind: "login" | "card" | "identity" | "secret" | "ssh"): VaultItem["type"] {
  return kind === "login" ? "登录" : kind === "card" ? "支付卡" : kind === "identity" ? "身份" : kind === "secret" ? "机密" : "SSH";
}

function itemKindForType(type: VaultItem["type"]): "login" | "card" | "identity" | "secret" | "ssh" {
  return type === "登录" ? "login" : type === "支付卡" ? "card" : type === "身份" ? "identity" : type === "机密" ? "secret" : "ssh";
}

export function requiresFillPassword(item: Pick<VaultItem, "type" | "masterPasswordReprompt">): boolean {
  return requiresFillConfirmation({
    kind: itemKindForType(item.type),
    masterPasswordReprompt: item.masterPasswordReprompt,
  });
}

function FillItemIcon({ item }: { item: VaultItem }) {
  const Icon = item.passkeyOnly ? FingerprintIcon : item.type === "登录" ? KeyRoundIcon : item.type === "身份" ? FolderKeyIcon : item.type === "支付卡" ? CreditCardIcon : item.type === "机密" ? BracesIcon : TerminalIcon;
  return <Icon />;
}

function VaultRow({ item, selectable = false, selected = false, showFill = false, fillState, onToggle, onEdit, onDelete, onOpen, onFill, onCopy }: { item: VaultItem; selectable?: boolean; selected?: boolean; showFill?: boolean; fillState: FillState; onToggle?: () => void; onEdit: () => void; onDelete: () => void; onOpen: () => void; onFill: () => void; onCopy: (option: string) => void }) {
  const Icon = item.passkeyOnly ? FingerprintIcon : item.type === "登录" ? KeyRoundIcon : item.type === "身份" ? FolderKeyIcon : item.type === "支付卡" ? CreditCardIcon : item.type === "机密" ? BracesIcon : TerminalIcon;
  return (
    <div className="flex w-full min-w-0 items-center gap-1.5 overflow-hidden rounded-lg border border-input p-2.5">
      {selectable ? <label className="grid size-6 shrink-0 cursor-pointer place-items-center"><input className="size-3.5 accent-primary" type="checkbox" checked={selected} onChange={onToggle} aria-label={`选择 ${item.title}`} /></label> : null}
      <span className="grid size-7 shrink-0 place-items-center rounded-md bg-muted" aria-hidden="true"><Icon size={14} /></span>
      <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{item.title}</p><p className="truncate text-sm text-muted-foreground">{item.detail}</p></div>
      {showFill && !item.passkeyOnly ? <Button className="h-6 px-1.5 text-[11px]" size="xs" type="button" disabled={fillState === "pending"} onClick={onFill}>{fillState === "pending" ? "检查中" : "填充"}</Button> : null}
      <CopyMenu item={item} onCopy={onCopy} />
      <DropdownMenu><DropdownMenuTrigger render={<Button variant="ghost" size="icon-xs" type="button" aria-label={`${item.title} 的更多操作`} title="更多"><EllipsisVerticalIcon size={14} aria-hidden="true" /></Button>} /><DropdownMenuContent>{item.url && isHttpUrl(item.url) ? <DropdownMenuItem onClick={onOpen}><ExternalLinkIcon />打开网站</DropdownMenuItem> : null}{!item.passkeyOnly ? <DropdownMenuItem onClick={onEdit}><PencilIcon />编辑</DropdownMenuItem> : null}<DropdownMenuItem className="text-destructive" onClick={onDelete}><Trash2Icon />{item.type === "机密" || item.passkeyOnly ? "永久删除" : "删除"}</DropdownMenuItem></DropdownMenuContent></DropdownMenu>
    </div>
  );
}

function uniqueTotpQrCodes(values: TotpQrCode[]): TotpQrCode[] {
  return values.filter((value, index) => values.findIndex((candidate) => candidate.uri === value.uri) === index).slice(0, 20);
}

function chooseTotpQrCode(values: TotpQrCode[]): TotpQrCode | null {
  if (values.length === 1) return values[0]!;
  const options = values.map((value, index) => `${index + 1}. ${totpQrLabel(value)}`).join("\n");
  const choice = window.prompt(`当前网页识别到 ${values.length} 个验证器二维码，请输入要保存的序号：\n${options}`, "1");
  if (choice == null) return null;
  const index = Number.parseInt(choice.trim(), 10) - 1;
  return Number.isInteger(index) && values[index] ? values[index]! : null;
}

function totpQrLabel(value: TotpQrCode): string {
  return [value.issuer, value.account].filter(Boolean).join(" · ") || "当前网页";
}

function CopyMenu({ item, onCopy }: { item: VaultItem; onCopy: (option: string) => void }) {
  if (item.passkeyOnly) return null;
  const options = copyOptions(item);
  if (options.length === 0) return null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" size="icon-xs" type="button" aria-label={`复制 ${item.title}`}><CopyIcon size={12} aria-hidden="true" /></Button>} />
      <DropdownMenuContent>
        {options.map((option) => <DropdownMenuItem key={option} onClick={() => onCopy(option)}>{option}</DropdownMenuItem>)}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function copyOptions(item: VaultItem): string[] {
  if (item.type === "登录") return loginCopyOptions({ username: item.username ?? "", hasPassword: item.hasPassword === true, hasTotpSecret: item.hasTotpSecret === true });
  if (item.type === "身份") return [];
  if (item.type === "支付卡") return ["卡号", item.hasSecurityCode ? "安全码" : "", item.hasPin ? "PIN" : ""].filter(Boolean);
  if (item.type === "机密") return ["内容"];
  return [item.hasSshPassword ? "密码" : "", item.hasPublicKey ? "公钥" : "", item.hasPrivateKey ? "私钥" : "", item.hasKeyPassphrase ? "口令" : ""].filter(Boolean);
}

function operationPrefix(type: VaultItem["type"]) { return type === "登录" ? "items" : type === "支付卡" ? "cards" : type === "身份" ? "identities" : type === "机密" ? "secrets" : "ssh"; }

function addKindForType(type: VaultItem["type"]): AddItemKind {
  return type === "登录" ? "login" : type === "支付卡" ? "card" : type === "身份" ? "identity" : type === "机密" ? "secret" : "ssh";
}

function BottomNavigationItem({ active, icon: Icon, label, onClick }: { active: boolean; icon: typeof LockKeyholeIcon; label: string; onClick: () => void }) {
  return <button className={active ? "grid justify-items-center gap-0.5 rounded-lg px-1 text-[11px] leading-none font-medium text-primary" : "grid justify-items-center gap-0.5 rounded-lg px-1 text-[11px] leading-none text-muted-foreground hover:bg-muted hover:text-foreground"} type="button" aria-current={active ? "page" : undefined} onClick={onClick}><span className={active ? "grid h-6 w-10 place-items-center rounded-full bg-primary text-primary-foreground" : "grid h-6 w-10 place-items-center rounded-full"}><Icon size={14} aria-hidden="true" /></span><span>{label}</span></button>;
}

function FillNotice({ state, outcome }: { state: FillState; outcome: string | null }) {
  if (state === "idle" || state === "pending") return null;
  const copy = state === "sent" ? "已完成填充。" : state === "unavailable" ? "尚未连接 VaultMesh 桌面端。" : state === "locked" ? "请先在 VaultMesh 插件中单独解锁。" : state === "cancelled" ? "本次填充已取消。" : state === "no-fields" ? "当前页面没有可安全填充的字段。" : "仅支持普通 HTTP(S) 页面中的表单。";
  return <ToastMessage id="fill-notice" message={`${copy}${outcome ? ` ${outcome}` : ""}`} variant={state === "sent" ? "success" : state === "cancelled" ? "info" : "warning"} />;
}
