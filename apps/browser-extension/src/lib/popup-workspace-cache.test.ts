import { describe, expect, it } from "vitest";

import { PopupWorkspaceMemoryCache } from "./popup-workspace-cache";

function rpcResult(result: unknown) {
  return {
    kind: "vaultmesh.rpc-result",
    version: 2,
    requestId: crypto.randomUUID(),
    ok: true,
    result,
  };
}

const workspace = {
  status: { unlocked: true, hasVault: true, itemCount: 1 },
  items: [{
    id: "4f3621b7-8dc4-43c9-9a29-b111bf48e35a",
    title: "Example",
    username: "ada@example.test",
    url: "https://example.test",
    notes: null,
    hasPassword: true,
    hasTotpSecret: false,
    autofillOnPageLoad: true,
    masterPasswordReprompt: false,
    password: "must-be-stripped",
  }],
  cards: [],
  identities: [],
  sshCredentials: [],
  secrets: [],
};

describe("popup workspace memory cache", () => {
  it("keeps only a validated renderer-safe workspace in volatile memory", () => {
    const cache = new PopupWorkspaceMemoryCache();
    cache.observeRpcResponse("vault.workspace", rpcResult(workspace), 1_000);

    const cached = cache.read();
    expect(cached?.snapshot.items[0]?.title).toBe("Example");
    expect(JSON.stringify(cached)).not.toContain("must-be-stripped");
  });

  it("survives for the authorization lifetime and clears on a locked status", () => {
    const cache = new PopupWorkspaceMemoryCache();
    cache.observeRpcResponse("vault.workspace", rpcResult(workspace), 1_000);
    expect(cache.read()?.cachedAt).toBe(1_000);

    cache.observeRpcResponse("vault.workspace", rpcResult(workspace), 2_000);
    cache.observeRpcResponse("vault.status", rpcResult({ unlocked: false }), 2_001);
    expect(cache.read()).toBeNull();
  });

  it("drops a stale snapshot when the broker reports a Vault change", () => {
    const cache = new PopupWorkspaceMemoryCache();
    cache.observeRpcResponse("vault.workspace", rpcResult(workspace), 1_000);
    cache.observeRpcResponse("events.poll", rpcResult({
      sequence: 1,
      events: [{ sequence: 1, type: "vault-changed", occurredAt: "2026-09-18T00:00:00.000Z" }],
    }), 2_000);
    expect(cache.read()).toBeNull();

    cache.observeRpcResponse("vault.workspace", rpcResult(workspace), 3_000);
    expect(cache.read()?.cachedAt).toBe(3_000);
  });

  it("ignores malformed or failed workspace responses", () => {
    const cache = new PopupWorkspaceMemoryCache();
    cache.observeRpcResponse("vault.workspace", { ...rpcResult(workspace), ok: false }, 1_000);
    expect(cache.read()).toBeNull();
  });
});
