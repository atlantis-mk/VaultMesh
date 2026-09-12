import { afterEach, describe, expect, it, vi } from "vitest";

import { DesktopRpcError, getRecoveryHistory, getRecoveryTrash } from "./desktop-rpc";

const itemId = "10000000-0000-4000-8000-000000000001";
const trashId = "10000000-0000-4000-8000-000000000002";
const revisionId = "10000000-0000-4000-8000-000000000003";

afterEach(() => vi.restoreAllMocks());

function respond(resultFor: (operation: string) => unknown) {
  return vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message: unknown) => {
    const request = (message as { request: { requestId: string; operation: string } }).request;
    return { kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result: resultFor(request.operation) };
  });
}

describe("CT-RECOVERY-001 browser recovery RPC", () => {
  it.each([
    ["login", "items.trash.list", "username", "user@example.test"],
    ["card", "cards.trash.list", "maskedNumber", "•••• 4242"],
    ["identity", "identities.trash.list", "displayName", "Test User"],
    ["ssh", "ssh.trash.list", "host", "host.example.test"],
  ] as const)("maps the closed %s trash route without reading secrets", async (kind, operation, detailKey, detail) => {
    const send = respond((received) => {
      expect(received).toBe(operation);
      return [{ trashId, itemId, title: "Test", deletedAt: 1_700_000_000, [detailKey]: detail }];
    });
    expect(await getRecoveryTrash(kind)).toEqual([{ trashId, itemId, title: "Test", deletedAt: 1_700_000_000, detail }]);
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("rejects history rows belonging to another item", async () => {
    respond(() => [{ revisionId, itemId: "20000000-0000-4000-8000-000000000001", title: "Other", username: "other", savedAt: 1_700_000_000 }]);
    await expect(getRecoveryHistory("login", itemId)).rejects.toEqual(expect.objectContaining<Partial<DesktopRpcError>>({ code: "invalid-broker-response" }));
  });
});
