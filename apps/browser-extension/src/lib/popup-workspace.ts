import { z } from "zod";

import {
  getDesktopStatus,
  getFillHistory,
  getWorkspaceSnapshot,
  workspaceSchema,
  type DesktopState,
  type FillEvent,
  type WorkspaceSnapshot,
} from "@/lib/desktop-rpc";

type PopupWorkspaceDependencies = {
  getStatus: typeof getDesktopStatus;
  getSnapshot: typeof getWorkspaceSnapshot;
  getHistory: typeof getFillHistory;
  getActiveUrl: () => Promise<string | undefined>;
};

type PopupWorkspaceResult =
  | { state: "locked"; hasVault: boolean }
  | {
      state: "ready";
      hasVault: boolean;
      snapshot: WorkspaceSnapshot;
      history: FillEvent[];
      activeUrl?: string;
    };

const popupWorkspaceCacheResponseSchema = z.discriminatedUnion("status", [
  z.object({ status: z.literal("empty") }),
  z.object({
    status: z.literal("ready"),
    snapshot: workspaceSchema,
    cachedAt: z.number().int().nonnegative(),
  }),
]);

const popupSuggestionsResponseSchema = z.object({
  status: z.enum(["ready", "locked", "unavailable", "unsupported-page"]),
  candidateIds: z.array(z.string().uuid()).max(600),
});

const defaultDependencies: PopupWorkspaceDependencies = {
  getStatus: getDesktopStatus,
  getSnapshot: getWorkspaceSnapshot,
  getHistory: getFillHistory,
  getActiveUrl: async () => {
    const tabs = await browser.tabs.query({ active: true, lastFocusedWindow: true });
    return tabs[0]?.url;
  },
};

/**
 * Loads the renderer-safe popup data after authorization. A successful unlock
 * is already an authenticated status result, so that path deliberately skips
 * a redundant vault.status round trip.
 */
export async function loadPopupWorkspace(
  options: { assumeUnlocked?: boolean } = {},
  dependencies: PopupWorkspaceDependencies = defaultDependencies,
): Promise<PopupWorkspaceResult> {
  const activeUrl = dependencies.getActiveUrl().catch(() => undefined);
  if (!options.assumeUnlocked) {
    const status = await dependencies.getStatus();
    if (!status.unlocked) return { state: "locked", hasVault: status.hasVault };
  }

  const [snapshot, history, currentUrl] = await Promise.all([
    dependencies.getSnapshot(),
    dependencies.getHistory().catch(() => []),
    activeUrl,
  ]);
  return {
    state: "ready",
    hasVault: snapshot.status.hasVault,
    snapshot,
    history: history.slice(0, 10),
    activeUrl: currentUrl,
  };
}

export async function loadCachedPopupWorkspace(
  dependencies: {
    getCache?: () => Promise<unknown>;
    getActiveUrl?: () => Promise<string | undefined>;
  } = {},
): Promise<Extract<PopupWorkspaceResult, { state: "ready" }> | null> {
  const getCache = dependencies.getCache ?? (() => browser.runtime.sendMessage({ kind: "vaultmesh.popup-workspace-cache.get" }));
  const getActiveUrl = dependencies.getActiveUrl ?? defaultDependencies.getActiveUrl;
  const [cached, activeUrl] = await Promise.all([
    getCache().then((value) => popupWorkspaceCacheResponseSchema.safeParse(value)).catch(() => null),
    getActiveUrl().catch(() => undefined),
  ]);
  if (!cached?.success || cached.data.status !== "ready") return null;
  return {
    state: "ready",
    hasVault: cached.data.snapshot.status.hasVault,
    snapshot: cached.data.snapshot,
    history: [],
    activeUrl,
  };
}

export async function loadPopupSuggestionIds(
  getSuggestions: () => Promise<unknown> = () => browser.runtime.sendMessage({ kind: "vaultmesh.popup-suggestions.get" }),
): Promise<Set<string> | null> {
  const parsed = popupSuggestionsResponseSchema.safeParse(await getSuggestions().catch(() => null));
  return parsed.success && parsed.data.status === "ready" ? new Set(parsed.data.candidateIds) : null;
}

export function shouldShowDesktopConnection(state: DesktopState, loading: boolean): boolean {
  return !loading && state !== "ready" && state !== "locked";
}

export function popupSessionInvalidation(
  status: { unlocked: boolean },
  events: Array<{ type: "vault-locked" | "pairing-revoked" | "operation-expired" | "desktop-shutdown" }>,
): Extract<DesktopState, "locked" | "unavailable"> | null {
  if (!status.unlocked || events.some((event) => event.type === "vault-locked")) return "locked";
  if (events.some((event) => event.type === "pairing-revoked" || event.type === "desktop-shutdown")) return "unavailable";
  return null;
}
