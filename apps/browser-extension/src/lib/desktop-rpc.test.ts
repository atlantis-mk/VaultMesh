import { describe, expect, it, vi } from "vitest";

import { copyRecoveryCode, DesktopRpcError, getEmailOtpCandidates, getLoginDetail, getPasskeysForLogin, getRecoveryCodes, getUnlockHistory, getWorkspaceSnapshot, importRecoveryCodesFile, pollDesktopEvents } from "./desktop-rpc";

describe("desktop RPC client", () => {
  it("accepts lock and vault-change events retained across an idle lock and PIN unlock", async () => {
    const events = [
      { sequence: 6, type: "vault-locked", occurredAt: "2026-09-18T00:00:00.000Z" },
      { sequence: 7, type: "vault-changed", occurredAt: "2026-09-18T00:05:00.000Z" },
    ];
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => ({
      kind: "vaultmesh.rpc-result", version: 2,
      requestId: (message as unknown as { request: { requestId: string } }).request.requestId,
      ok: true, result: { sequence: 7, events },
    }) as never);

    await expect(pollDesktopEvents(0)).resolves.toEqual({ sequence: 7, events });
    sendMessage.mockImplementation(async (message) => ({
      kind: "vaultmesh.rpc-result", version: 2,
      requestId: (message as unknown as { request: { requestId: string } }).request.requestId,
      ok: true, result: { sequence: 8, events: [{ sequence: 8, type: "unexpected-event", occurredAt: "2026-09-18T00:06:00.000Z" }] },
    }) as never);
    await expect(pollDesktopEvents(7)).rejects.toThrow();
    sendMessage.mockRestore();
  });

  it("rejects malformed or uncorrelated native responses", async () => {
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockResolvedValue({ kind: "vaultmesh.rpc-result", version: 2, requestId: crypto.randomUUID(), ok: true, result: {} } as never);
    await expect(getWorkspaceSnapshot()).rejects.toBeInstanceOf(DesktopRpcError);
    sendMessage.mockRestore();
  });

  it("never persists RPC responses in browser storage", async () => {
    const storageSet = vi.spyOn(browser.storage.local, "set");
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockRejectedValue(new Error("offline"));
    await expect(getWorkspaceSnapshot()).rejects.toThrow();
    expect(storageSet).not.toHaveBeenCalled();
    sendMessage.mockRestore(); storageSet.mockRestore();
  });

  it("requires safe password-presence metadata without accepting a password value", async () => {
    const item = {
      id: crypto.randomUUID(), title: "Example", username: "ada@example.test", url: null, notes: null,
      hasPassword: true, hasTotpSecret: false, hasRecoveryCodes: false, autofillOnPageLoad: true, masterPasswordReprompt: false,
    };
    const result = { status: { unlocked: true, hasVault: true, itemCount: 1 }, items: [item], cards: [], identities: [], sshCredentials: [], secrets: [] };
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => ({
      kind: "vaultmesh.rpc-result", version: 2, requestId: (message as unknown as { request: { requestId: string } }).request.requestId, ok: true, result,
    }) as never);

    await expect(getWorkspaceSnapshot()).resolves.toEqual(result);
    expect(JSON.stringify(await getWorkspaceSnapshot())).not.toContain('"password"');
    sendMessage.mockImplementation(async (message) => ({
      kind: "vaultmesh.rpc-result", version: 2, requestId: (message as unknown as { request: { requestId: string } }).request.requestId, ok: true,
      result: { ...result, items: [{ ...item, hasPassword: undefined }] },
    }) as never);
    await expect(getWorkspaceSnapshot()).rejects.toThrow();
    sendMessage.mockRestore();
  });

  it("parses password-free Login details without requiring summary-only hasPassword", async () => {
    const detail = {
      id: crypto.randomUUID(), title: "Example", username: "ada@example.test", url: "https://example.test", notes: null,
      folder: null, favorite: false, hasTotpSecret: false, hasRecoveryCodes: false, additionalUrls: [],
      autofillOnPageLoad: true, masterPasswordReprompt: false, customFields: [],
    };
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => ({
      kind: "vaultmesh.rpc-result", version: 2, requestId: (message as unknown as { request: { requestId: string } }).request.requestId, ok: true, result: detail,
    }) as never);

    await expect(getLoginDetail(detail.id)).resolves.toEqual(expect.not.objectContaining({ hasPassword: expect.anything() }));
    sendMessage.mockRestore();
  });

  it("reads only redacted unlock activity without extension storage", async () => {
    const storageSet = vi.spyOn(browser.storage.local, "set");
    const event = { eventId: crypto.randomUUID(), occurredAt: 1_725_000_000, source: "desktop" };
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => ({ kind: "vaultmesh.rpc-result", version: 2, requestId: (message as unknown as { request: { requestId: string } }).request.requestId, ok: true, result: [event] }) as never);
    await expect(getUnlockHistory()).resolves.toEqual([event]);
    expect(storageSet).not.toHaveBeenCalled();
    sendMessage.mockRestore(); storageSet.mockRestore();
  });

  it("keeps global email OTP candidates transient and rejects message metadata", async () => {
    const storageSet = vi.spyOn(browser.storage.local, "set");
    const candidate = { id: crypto.randomUUID(), code: "A9b2C3", sourceDomain: "example.test", receivedAt: 1_725_000_000, expiresAt: 1_725_000_090 };
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => {
      const request = (message as unknown as { request: { requestId: string; operation: string; input: Record<string, unknown> } }).request;
      expect(request.operation).toBe("email.otp.candidates");
      expect(request.input).toEqual({ topOrigin: "https://example.test" });
      return { kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result: { candidates: [candidate], boostExpiresAt: candidate.expiresAt } } as never;
    });
    await expect(getEmailOtpCandidates("https://example.test")).resolves.toEqual({ candidates: [candidate], boostExpiresAt: candidate.expiresAt });
    expect(storageSet).not.toHaveBeenCalled();

    sendMessage.mockImplementation(async (message) => {
      const request = (message as unknown as { request: { requestId: string } }).request;
      return { kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true, result: { candidates: [{ ...candidate, subject: "must not cross" }], boostExpiresAt: 0 } } as never;
    });
    await expect(getEmailOtpCandidates("https://example.test")).resolves.toEqual({ candidates: [candidate], boostExpiresAt: 0 });
    sendMessage.mockRestore(); storageSet.mockRestore();
  });

  it("returns only Passkeys linked to the requested login", async () => {
    const loginId = crypto.randomUUID();
    const otherLoginId = crypto.randomUUID();
    const passkey = {
      id: crypto.randomUUID(), title: "GitHub Passkey", kind: "authenticator-key", provider: "VaultMesh Passkey", account: "octocat",
      environment: "Passkey", expiresAt: null, website: "https://github.com", notes: null, favorite: false, masterPasswordReprompt: false, isPasskey: true, loginId,
    };
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => ({
      kind: "vaultmesh.rpc-result", version: 2, requestId: (message as unknown as { request: { requestId: string } }).request.requestId, ok: true,
      result: [passkey, { ...passkey, id: crypto.randomUUID(), loginId: otherLoginId }, { ...passkey, id: crypto.randomUUID(), isPasskey: false, loginId }],
    }) as never);

    await expect(getPasskeysForLogin(loginId)).resolves.toEqual([passkey]);
    sendMessage.mockRestore();
  });

  it("imports recovery-code files through confirmation without exposing a local path", async () => {
    const confirmationToken = crypto.randomUUID();
    const storageSet = vi.spyOn(browser.storage.local, "set");
    const requests: Array<{ operation: string; input: Record<string, unknown> }> = [];
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => {
      const request = (message as unknown as { request: { requestId: string; operation: string; input: Record<string, unknown> } }).request;
      requests.push({ operation: request.operation, input: request.input });
      return {
        kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true,
        result: request.operation === "confirmation.request"
          ? { confirmationToken }
          : { codes: [" alpha ", "beta"], fileName: "codes.txt", sourceFileStatus: "kept", localPath: "/must/not/cross" },
      } as never;
    });

    await expect(importRecoveryCodesFile()).resolves.toEqual({
      codes: [" alpha ", "beta"], fileName: "codes.txt", sourceFileStatus: "kept",
    });
    expect(requests.map((request) => request.operation)).toEqual([
      "confirmation.request", "items.recovery-codes.import-file",
    ]);
    expect(requests[1]?.input.confirmationToken).toBe(confirmationToken);
    expect(requests[1]?.input.userGestureId).toBe(requests[0]?.input.userGestureId);
    expect(storageSet).not.toHaveBeenCalled();
    sendMessage.mockRestore(); storageSet.mockRestore();
  });

  it("reveals and copies recovery codes only through separately reauthenticated requests", async () => {
    const id = crypto.randomUUID();
    const storageSet = vi.spyOn(browser.storage.local, "set");
    const requests: Array<{ operation: string; input: Record<string, unknown> }> = [];
    const sendMessage = vi.spyOn(browser.runtime, "sendMessage").mockImplementation(async (message) => {
      const request = (message as unknown as { request: { requestId: string; operation: string; input: Record<string, unknown> } }).request;
      requests.push({ operation: request.operation, input: request.input });
      return {
        kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true,
        result: request.operation === "items.recovery-codes"
          ? { codes: ["alpha", "beta"], localPath: "/must/not/cross" }
          : { clearsAt: 42_000, code: "must-not-return" },
      } as never;
    });

    await expect(getRecoveryCodes(id, "master password one")).resolves.toEqual(["alpha", "beta"]);
    await expect(copyRecoveryCode(id, 1, "master password two")).resolves.toBe(42_000);
    expect(requests.map((request) => request.operation)).toEqual(["items.recovery-codes", "items.copy-recovery-code"]);
    expect(requests[0]?.input).toMatchObject({ id, masterPassword: "master password one", userGestureId: expect.any(String) });
    expect(requests[1]?.input).toMatchObject({ id, index: 1, masterPassword: "master password two", userGestureId: expect.any(String) });
    expect(requests[0]?.input.userGestureId).not.toBe(requests[1]?.input.userGestureId);
    expect(storageSet).not.toHaveBeenCalled();
    sendMessage.mockRestore(); storageSet.mockRestore();
  });
});
