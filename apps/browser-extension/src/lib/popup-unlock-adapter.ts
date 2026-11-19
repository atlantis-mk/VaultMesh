export type PopupUnlockEntryMode = "auto-open" | "manual-locked" | "vault-missing";

export type PopupUnlockResolveContext = {
  hasVault: boolean;
  suppressAutoUnlock: boolean;
};

export interface PopupUnlockAdapter {
  readonly mode: PopupUnlockEntryMode;
  readonly shouldAutoRequestDesktopUnlock: boolean;
  readonly canTriggerDesktopUnlock: boolean;
  readonly title: string;
  readonly description: string;
  readonly actionLabel: string;
}

export class AutoOpenPopupUnlockAdapter implements PopupUnlockAdapter {
  readonly mode: PopupUnlockEntryMode = "auto-open";
  readonly shouldAutoRequestDesktopUnlock = true;
  readonly canTriggerDesktopUnlock = true;
  readonly title = "解锁 VaultMesh 浏览器插件";
  readonly description = "正在请求 VaultMesh 桌面端打开解锁窗口，请在桌面端完成 Touch ID、PIN 或主密码验证。";
  readonly actionLabel = "解锁 VaultMesh 浏览器插件";
}

export class ManualLockedPopupUnlockAdapter implements PopupUnlockAdapter {
  readonly mode: PopupUnlockEntryMode = "manual-locked";
  readonly shouldAutoRequestDesktopUnlock = false;
  readonly canTriggerDesktopUnlock = true;
  readonly title = "插件已锁定";
  readonly description = "已手动锁定浏览器插件，本次不会自动弹出桌面解锁窗口。需要继续使用时请点击下方按钮。";
  readonly actionLabel = "解锁 VaultMesh 浏览器插件";
}

export class VaultMissingPopupUnlockAdapter implements PopupUnlockAdapter {
  readonly mode: PopupUnlockEntryMode = "vault-missing";
  readonly shouldAutoRequestDesktopUnlock = false;
  readonly canTriggerDesktopUnlock = false;
  readonly title = "创建 VaultMesh 保险库";
  readonly description = "尚未创建保险库，请先在 VaultMesh 桌面端创建后再解锁浏览器插件。";
  readonly actionLabel = "";
}

const AUTO_OPEN_ADAPTER = new AutoOpenPopupUnlockAdapter();
const MANUAL_LOCKED_ADAPTER = new ManualLockedPopupUnlockAdapter();
const VAULT_MISSING_ADAPTER = new VaultMissingPopupUnlockAdapter();

const ADAPTERS: Record<PopupUnlockEntryMode, PopupUnlockAdapter> = {
  "auto-open": AUTO_OPEN_ADAPTER,
  "manual-locked": MANUAL_LOCKED_ADAPTER,
  "vault-missing": VAULT_MISSING_ADAPTER,
};

export const PopupUnlockFactory = {
  all(): readonly PopupUnlockAdapter[] {
    return [AUTO_OPEN_ADAPTER, MANUAL_LOCKED_ADAPTER, VAULT_MISSING_ADAPTER];
  },

  createFor(mode: PopupUnlockEntryMode): PopupUnlockAdapter {
    return ADAPTERS[mode];
  },

  resolve({ hasVault, suppressAutoUnlock }: PopupUnlockResolveContext): PopupUnlockAdapter {
    if (!hasVault) return VAULT_MISSING_ADAPTER;
    return suppressAutoUnlock ? MANUAL_LOCKED_ADAPTER : AUTO_OPEN_ADAPTER;
  },
};
