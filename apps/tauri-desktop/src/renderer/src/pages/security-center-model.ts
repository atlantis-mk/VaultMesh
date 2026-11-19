import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { toast } from 'sonner';

import { PinSettingsDomainFactory, type PinSettingsDomain } from '@/lib/pin-settings-adapter';
import { useVaultStore } from '@/stores/vault-store';
import type {
  AgentBrokerStatus,
  IdentityRevisionSummary,
  IdentityTrashSummary,
  LoginItemRevisionSummary,
  LoginItemSummary,
  PasswordHealthReport,
  PaymentCardRevisionSummary,
  PaymentCardTrashSummary,
  PinStatus,
  SecuritySettings,
  SshCredentialRevisionSummary,
  SshCredentialTrashSummary,
  TrashItemSummary,
} from '../../../shared/contracts';

export type DomainPinStatuses = Record<PinSettingsDomain, PinStatus | null>;

const INITIAL_PIN_STATUSES: DomainPinStatuses = {
  desktop: null,
  browser: null,
  agent: null,
};

function displayDomain(url: string): string {
  try {
    return new URL(url.includes('://') ? url : `https://${url}`).hostname.replace(/^www\./i, '');
  } catch {
    return url.replace(/^https?:\/\//i, '').split('/')[0] || url;
  }
}

function duplicateLoginKey(item: LoginItemSummary): string | null {
  const username = item.username.trim().toLowerCase();
  if (!username || !item.url) return null;
  try {
    const url = new URL(item.url.includes('://') ? item.url : `https://${item.url}`);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    const host = url.hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
    return host ? `${username}\u0000${host}` : null;
  } catch {
    return null;
  }
}

async function fetchAllDomainPinStatuses(): Promise<DomainPinStatuses> {
  const adapters = PinSettingsDomainFactory.all();
  const results = await Promise.all(adapters.map(async (adapter) => [adapter.domain, await adapter.getStatus()] as const));
  return Object.fromEntries(results) as DomainPinStatuses;
}

export function useSecurityCenterModel() {
  const items = useVaultStore((state) => state.items);
  const cards = useVaultStore((state) => state.cards);
  const sshCredentials = useVaultStore((state) => state.sshCredentials);
  const identities = useVaultStore((state) => state.identities);
  const refreshVault = useVaultStore((state) => state.refresh);
  const getItemDetail = useVaultStore((state) => state.getItemDetail);
  const updateItem = useVaultStore((state) => state.updateItem);
  const deleteItems = useVaultStore((state) => state.deleteItems);
  const [health, setHealth] = useState<PasswordHealthReport | null>(null);
  const [trash, setTrash] = useState<TrashItemSummary[]>([]);
  const [cardTrash, setCardTrash] = useState<PaymentCardTrashSummary[]>([]);
  const [sshTrash, setSshTrash] = useState<SshCredentialTrashSummary[]>([]);
  const [identityTrash, setIdentityTrash] = useState<IdentityTrashSummary[]>([]);
  const [historyItemId, setHistoryItemId] = useState(items[0]?.id ?? '');
  const [history, setHistory] = useState<LoginItemRevisionSummary[]>([]);
  const [cardHistoryItemId, setCardHistoryItemId] = useState(cards[0]?.id ?? '');
  const [cardHistory, setCardHistory] = useState<PaymentCardRevisionSummary[]>([]);
  const [sshHistoryItemId, setSshHistoryItemId] = useState(sshCredentials[0]?.id ?? '');
  const [sshHistory, setSshHistory] = useState<SshCredentialRevisionSummary[]>([]);
  const [identityHistoryItemId, setIdentityHistoryItemId] = useState(identities[0]?.id ?? '');
  const [identityHistory, setIdentityHistory] = useState<IdentityRevisionSummary[]>([]);
  const [securitySettings, setSecuritySettings] = useState<SecuritySettings | null>(null);
  const [securityDraft, setSecurityDraft] = useState<SecuritySettings | null>(null);
  const [pinStatuses, setPinStatuses] = useState<DomainPinStatuses>(INITIAL_PIN_STATUSES);
  const [agentStatus, setAgentStatus] = useState<AgentBrokerStatus | null>(null);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [restorePassword, setRestorePassword] = useState('');
  const [mergePrimaryIds, setMergePrimaryIds] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);

  const issueMap = useMemo(() => {
    const result = new Map<string, string[]>();
    if (!health) return result;
    for (const [ids, label] of [
      [health.weakItemIds, '弱密码'],
      [health.reusedItemIds, '重复使用'],
      [health.oldItemIds, '超过 180 天'],
    ] as const) {
      for (const id of ids) result.set(id, [...(result.get(id) ?? []), label]);
    }
    return result;
  }, [health]);

  const duplicateGroups = useMemo(() => {
    const grouped = new Map<string, LoginItemSummary[]>();
    for (const item of items) {
      const key = duplicateLoginKey(item);
      if (key) grouped.set(key, [...(grouped.get(key) ?? []), item]);
    }
    return [...grouped.entries()].filter(([, group]) => group.length > 1).map(([key, group]) => ({
      key,
      items: group,
      label: `${displayDomain(group[0]?.url ?? '')} · ${group[0]?.username ?? ''}`,
    }));
  }, [items]);

  const setPinStatusForDomain = (domain: PinSettingsDomain, next: PinStatus): void => {
    setPinStatuses((current) => ({ ...current, [domain]: next }));
    if (domain === 'desktop') {
      useVaultStore.setState({ pin: next });
    } else if (domain === 'agent') {
      setAgentStatus((current) => (current ? { ...current, pin: next } : current));
    }
  };

  const refreshPinStatuses = async (): Promise<void> => {
    const nextPinStatuses = await fetchAllDomainPinStatuses();
    setPinStatuses(nextPinStatuses);
    if (nextPinStatuses.desktop) {
      useVaultStore.setState({ pin: nextPinStatuses.desktop });
    }
    if (nextPinStatuses.agent) {
      setAgentStatus((current) => (current ? { ...current, pin: nextPinStatuses.agent! } : current));
    }
  };

  const reload = async (): Promise<void> => {
    const [nextHealth, nextTrash, nextCardTrash, nextSshTrash, nextIdentityTrash, nextSecuritySettings, nextPinStatuses, nextAgentStatus] = await Promise.all([
      window.vaultMesh.items.passwordHealth(),
      window.vaultMesh.items.trash(),
      window.vaultMesh.cards.trash(),
      window.vaultMesh.ssh.trash(),
      window.vaultMesh.identities.trash(),
      window.vaultMesh.security.settings(),
      fetchAllDomainPinStatuses(),
      window.vaultMesh.agent.status(),
    ]);
    setHealth(nextHealth);
    setTrash(nextTrash);
    setCardTrash(nextCardTrash);
    setSshTrash(nextSshTrash);
    setIdentityTrash(nextIdentityTrash);
    setSecuritySettings(nextSecuritySettings);
    setSecurityDraft(nextSecuritySettings);
    setPinStatuses(nextPinStatuses);
    setAgentStatus(nextAgentStatus);
    if (nextPinStatuses.desktop) {
      useVaultStore.setState({ pin: nextPinStatuses.desktop });
    }
    if (historyItemId) setHistory(await window.vaultMesh.items.history(historyItemId));
    if (cardHistoryItemId) setCardHistory(await window.vaultMesh.cards.history(cardHistoryItemId));
    if (sshHistoryItemId) setSshHistory(await window.vaultMesh.ssh.history(sshHistoryItemId));
    if (identityHistoryItemId) setIdentityHistory(await window.vaultMesh.identities.history(identityHistoryItemId));
  };

  useEffect(() => {
    void reload().catch(() => toast.error('无法加载安全状态。'));
    return window.vaultMesh.agent.onPairingRequested(() => {
      void window.vaultMesh.agent.status().then(setAgentStatus).catch(() => {
        toast.error('无法加载 Agent 配对请求。');
      });
    });
  }, []);

  const run = async (operation: () => Promise<void>, success: string): Promise<void> => {
    setBusy(true);
    try {
      await operation();
      toast.success(success);
    } catch (reason) {
      toast.error(reason instanceof Error ? reason.message : '操作失败。');
    } finally {
      setBusy(false);
    }
  };

  const changePassword = async (event: FormEvent): Promise<void> => {
    event.preventDefault();
    if (newPassword !== confirmation) {
      toast.error('两次输入的新主密码不一致。');
      return;
    }
    await run(async () => {
      await window.vaultMesh.vault.changeMasterPassword({ currentPassword, newPassword });
      await refreshPinStatuses();
      setCurrentPassword('');
      setNewPassword('');
      setConfirmation('');
    }, '主密码已更新；快速解锁已关闭。');
  };

  const saveSecuritySettings = async (): Promise<void> => {
    if (!securityDraft) return;
    await run(async () => {
      const updated = await window.vaultMesh.security.updateSettings(securityDraft);
      setSecuritySettings(updated);
      setSecurityDraft(updated);
    }, '安全策略已保存并立即生效。');
  };

  const updateSecurityDraft = (patch: Partial<SecuritySettings>): void => {
    setSecurityDraft((current) => current ? { ...current, ...patch } : current);
  };

  const loadHistory = async (itemId: string): Promise<void> => {
    setHistoryItemId(itemId);
    setHistory(itemId ? await window.vaultMesh.items.history(itemId) : []);
  };

  const loadCardHistory = async (itemId: string): Promise<void> => {
    setCardHistoryItemId(itemId);
    setCardHistory(itemId ? await window.vaultMesh.cards.history(itemId) : []);
  };

  const loadSshHistory = async (itemId: string): Promise<void> => {
    setSshHistoryItemId(itemId);
    setSshHistory(itemId ? await window.vaultMesh.ssh.history(itemId) : []);
  };
  const loadIdentityHistory = async (itemId: string): Promise<void> => { setIdentityHistoryItemId(itemId); setIdentityHistory(itemId ? await window.vaultMesh.identities.history(itemId) : []); };

  const mergeDuplicateGroup = async (key: string, group: LoginItemSummary[]): Promise<void> => {
    const primaryId = mergePrimaryIds[key] ?? group[0]?.id;
    const primary = group.find((item) => item.id === primaryId);
    if (!primary) return;
    const secondary = group.filter((item) => item.id !== primary.id);

    setBusy(true);
    try {
      const primaryDetail = await getItemDetail(primary.id);
      if (!primaryDetail) return;
      const details = await Promise.all(secondary.map((item) => getItemDetail(item.id)));
      if (details.some((detail) => !detail)) return;
      const validDetails = details.filter((detail): detail is NonNullable<typeof detail> => detail !== null);
      const urls = [...new Set([primaryDetail.url, ...primaryDetail.additionalUrls, ...validDetails.flatMap((detail) => [detail.url, ...detail.additionalUrls])].filter((url): url is string => Boolean(url)))];
      const fields = [...primaryDetail.customFields];
      for (const detail of validDetails) for (const field of detail.customFields) {
        if (!fields.some((current) => current.label === field.label && current.value === field.value)) fields.push(field);
      }
      const notes = [primaryDetail.notes, ...validDetails.map((detail) => detail.notes)].filter((value): value is string => Boolean(value)).filter((value, index, values) => values.indexOf(value) === index).join('\n\n') || null;
      const [url, ...additionalUrls] = urls;
      const merged = await updateItem({
        ...primaryDetail,
        url: url ?? null,
        additionalUrls,
        notes,
        folder: primaryDetail.folder ?? validDetails.find((detail) => detail.folder)?.folder ?? null,
        favorite: primaryDetail.favorite || validDetails.some((detail) => detail.favorite),
        password: null,
        totpSecret: null,
        clearTotpSecret: false,
        recoveryCodes: null,
        clearRecoveryCodes: false,
        customFields: fields,
      });
      if (!merged) return;
      for (const item of secondary) {
        if (!await deleteItems([item.id])) return;
      }
      setMergePrimaryIds((current) => {
        const { [key]: _, ...remaining } = current;
        return remaining;
      });
      toast.success(`已合并 ${secondary.length + 1} 条重复登录信息；副本已移入回收站。`);
    } finally {
      setBusy(false);
    }
  };
  return {
    items,
    cards,
    sshCredentials,
    identities,
    refreshVault,
    health,
    trash,
    cardTrash,
    sshTrash,
    identityTrash,
    historyItemId,
    history,
    cardHistoryItemId,
    cardHistory,
    sshHistoryItemId,
    sshHistory,
    identityHistoryItemId,
    identityHistory,
    securitySettings,
    securityDraft,
    pinStatuses,
    agentStatus,
    currentPassword,
    newPassword,
    confirmation,
    restorePassword,
    mergePrimaryIds,
    busy,
    issueMap,
    duplicateGroups,
    setAgentStatus,
    setSecurityDraft,
    setCurrentPassword,
    setNewPassword,
    setConfirmation,
    setRestorePassword,
    setPinStatusForDomain,
    refreshPinStatuses,
    setMergePrimaryIds,
    setHistory,
    setCardHistory,
    setSshHistory,
    setIdentityHistory,
    reload,
    run,
    changePassword,
    saveSecuritySettings,
    updateSecurityDraft,
    loadHistory,
    loadCardHistory,
    loadSshHistory,
    loadIdentityHistory,
    mergeDuplicateGroup,
  };
}

export type SecurityCenterModel = ReturnType<typeof useSecurityCenterModel>;
