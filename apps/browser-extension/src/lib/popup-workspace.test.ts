import { describe, expect, it, vi } from "vitest";

import type { WorkspaceSnapshot } from "./desktop-rpc";
import { loadCachedPopupWorkspace, loadPopupSuggestionIds, loadPopupWorkspace, popupSessionInvalidation, shouldShowDesktopConnection } from "./popup-workspace";

const emptyWorkspace: WorkspaceSnapshot = {
  status: { unlocked: true, hasVault: true, itemCount: 0 },
  items: [],
  cards: [],
  identities: [],
  sshCredentials: [],
  secrets: [],
};

describe("popup workspace loading", () => {
  it("renders a validated background-memory snapshot before the fresh request finishes", async () => {
    const cached = await loadCachedPopupWorkspace({
      getCache: vi.fn().mockResolvedValue({ status: "ready", snapshot: emptyWorkspace, cachedAt: 1_000 }),
      getActiveUrl: vi.fn().mockResolvedValue("https://example.test/login"),
    });

    expect(cached).toMatchObject({ state: "ready", activeUrl: "https://example.test/login", snapshot: emptyWorkspace });
  });

  it("does not present a warm popup refresh as a desktop reconnection", () => {
    expect(shouldShowDesktopConnection("unavailable", true)).toBe(false);
    expect(shouldShowDesktopConnection("unavailable", false)).toBe(true);
    expect(shouldShowDesktopConnection("error", false)).toBe(true);
    expect(shouldShowDesktopConnection("ready", false)).toBe(false);
  });

  it("uses the successful unlock result without another status round trip", async () => {
    const getStatus = vi.fn().mockRejectedValue(new Error("status must not be requested"));
    const result = await loadPopupWorkspace(
      { assumeUnlocked: true },
      {
        getStatus,
        getSnapshot: vi.fn().mockResolvedValue(emptyWorkspace),
        getHistory: vi.fn().mockResolvedValue([]),
        getActiveUrl: vi.fn().mockResolvedValue("https://example.test/login"),
      },
    );

    expect(getStatus).not.toHaveBeenCalled();
    expect(result).toMatchObject({ state: "ready", activeUrl: "https://example.test/login" });
  });

  it("does not request unlocked data while the extension session is locked", async () => {
    const getSnapshot = vi.fn().mockResolvedValue(emptyWorkspace);
    const getHistory = vi.fn().mockResolvedValue([]);
    const result = await loadPopupWorkspace(
      {},
      {
        getStatus: vi.fn().mockResolvedValue({ unlocked: false, hasVault: true, itemCount: 0 }),
        getSnapshot,
        getHistory,
        getActiveUrl: vi.fn().mockResolvedValue(undefined),
      },
    );

    expect(result).toEqual({ state: "locked", hasVault: true });
    expect(getSnapshot).not.toHaveBeenCalled();
    expect(getHistory).not.toHaveBeenCalled();
  });

  it("accepts only a complete authoritative popup suggestion response", async () => {
    const first = crypto.randomUUID();
    const second = crypto.randomUUID();
    await expect(loadPopupSuggestionIds(vi.fn().mockResolvedValue({
      status: "ready",
      candidateIds: [first, second, first],
    }))).resolves.toEqual(new Set([first, second]));
    await expect(loadPopupSuggestionIds(vi.fn().mockResolvedValue({
      status: "unavailable",
      candidateIds: [first],
    }))).resolves.toBeNull();
    await expect(loadPopupSuggestionIds(vi.fn().mockResolvedValue({
      status: "ready",
      candidateIds: ["not-an-id"],
    }))).resolves.toBeNull();
  });

  it("invalidates the popup when desktop authority is locked, revoked, or stopped", () => {
    expect(popupSessionInvalidation({ unlocked: false }, [])).toBe("locked");
    expect(popupSessionInvalidation({ unlocked: true }, [{ type: "vault-locked" }])).toBe("locked");
    expect(popupSessionInvalidation({ unlocked: true }, [{ type: "pairing-revoked" }])).toBe("unavailable");
    expect(popupSessionInvalidation({ unlocked: true }, [{ type: "desktop-shutdown" }])).toBe("unavailable");
    expect(popupSessionInvalidation({ unlocked: true }, [{ type: "operation-expired" }])).toBeNull();
  });
});
