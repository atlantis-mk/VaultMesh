import { useEffect, useRef, useState, type ReactNode } from "react";
import { LockKeyholeIcon, RefreshCwIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { getDesktopStatus } from "@/lib/desktop-rpc";
import type { PopupUnlockAdapter } from "@/lib/popup-unlock-adapter";

const STATUS_POLL_INTERVAL_MS = 1_000;

type UnlockRequestResponse = {
  status?: unknown;
  errorMessage?: unknown;
};

export function PopupUnlockPage({
  adapter,
  onUnlocked,
  onManualUnlockRequest,
  onVaultDetected,
  notice,
}: {
  adapter: PopupUnlockAdapter;
  onUnlocked: () => Promise<boolean>;
  onManualUnlockRequest?: () => void;
  onVaultDetected?: (hasVault: boolean) => void;
  notice?: (busy: boolean) => ReactNode;
}) {
  const [busy, setBusy] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const mountedRef = useRef(false);
  const autoRequestedRef = useRef(false);
  const requestInFlightRef = useRef(false);
  const completedRef = useRef(false);
  const transitioningRef = useRef(false);
  const onUnlockedRef = useRef(onUnlocked);
  onUnlockedRef.current = onUnlocked;
  const onVaultDetectedRef = useRef(onVaultDetected);
  onVaultDetectedRef.current = onVaultDetected;

  async function completeUnlock() {
    if (!mountedRef.current || completedRef.current || transitioningRef.current) return;
    transitioningRef.current = true;
    try {
      const ok = await onUnlockedRef.current();
      if (!mountedRef.current) return;
      if (ok) {
        completedRef.current = true;
      } else {
        setBusy(false);
        setStatusMessage("验证已完成，但保险库状态发生变化，请重试。");
      }
    } finally {
      transitioningRef.current = false;
    }
  }

  async function requestDesktopUnlock(automatic = false) {
    if (!adapter.canTriggerDesktopUnlock || requestInFlightRef.current || completedRef.current) return;
    requestInFlightRef.current = true;
    setBusy(true);
    setStatusMessage(null);
    try {
      const response = (await browser.runtime.sendMessage({
        kind: "vaultmesh.browser-unlock.request",
        ...(automatic ? { automatic: true } : {}),
      })) as UnlockRequestResponse | null | undefined;
      if (!mountedRef.current) return;
      if (response?.status === "passkey-prompt") {
        setBusy(false);
        return;
      }
      if (response?.status === "unlocked") {
        await completeUnlock();
        return;
      }
      if (response?.status === "cancelled") {
        setBusy(false);
        setStatusMessage(
          typeof response.errorMessage === "string" && response.errorMessage.trim().length > 0
            ? response.errorMessage
            : "已取消桌面端解锁，可点击下方按钮重试。",
        );
        return;
      }
      setBusy(false);
      setStatusMessage(
        typeof response?.errorMessage === "string" && response.errorMessage.trim().length > 0
          ? response.errorMessage
          : "无法连接 VaultMesh 桌面端，请确认桌面端正在运行。",
      );
    } catch (error) {
      if (!mountedRef.current) return;
      setBusy(false);
      setStatusMessage(
        error instanceof Error && error.message.trim().length > 0
          ? error.message
          : "无法连接 VaultMesh 桌面端，请确认桌面端正在运行。",
      );
    } finally {
      requestInFlightRef.current = false;
    }
  }

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    setStatusMessage(null);
    if (adapter.shouldAutoRequestDesktopUnlock && !autoRequestedRef.current) {
      autoRequestedRef.current = true;
      void requestDesktopUnlock(true);
    }
  }, [adapter]);

  useEffect(() => {
    let active = true;
    let polling = false;
    const pollStatus = async () => {
      if (!active || polling || completedRef.current) return;
      polling = true;
      try {
        const status = await getDesktopStatus();
        if (!active || !mountedRef.current || completedRef.current) return;
        onVaultDetectedRef.current?.(status.hasVault);
        if (status.unlocked) {
          await completeUnlock();
        }
      } catch {
        // Keep polling while popup remains open if desktop status is transiently unavailable.
      } finally {
        polling = false;
      }
    };
    const timer = setInterval(() => void pollStatus(), STATUS_POLL_INTERVAL_MS);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);

  function handleManualUnlock() {
    autoRequestedRef.current = true;
    onManualUnlockRequest?.();
    void requestDesktopUnlock();
  }

  return (
    <main className="flex h-full w-full items-center p-3">
      <Card className="w-full">
        <CardContent className="flex flex-col gap-3">
          <span className="grid size-12 place-items-center rounded-xl bg-muted">
            <LockKeyholeIcon aria-hidden="true" />
          </span>
          {notice?.(busy)}
          <div className="space-y-1">
            <h1 className="text-lg font-semibold">{adapter.title}</h1>
            <p className="text-sm text-muted-foreground">{statusMessage ?? adapter.description}</p>
          </div>
          {busy ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground" role="status" aria-live="polite">
              <RefreshCwIcon className="animate-spin" size={16} aria-hidden="true" />
              <span>正在等待桌面端完成解锁…</span>
            </div>
          ) : null}
          {adapter.canTriggerDesktopUnlock ? (
            <Button type="button" disabled={busy} onClick={handleManualUnlock}>
              {busy ? "正在打开桌面解锁窗口…" : adapter.actionLabel}
            </Button>
          ) : null}
        </CardContent>
      </Card>
    </main>
  );
}
