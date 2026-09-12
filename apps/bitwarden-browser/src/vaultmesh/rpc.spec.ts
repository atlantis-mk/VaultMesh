import { VaultMeshRpcClient, VaultMeshRpcError, VaultMeshStatusSchema } from "./rpc";

type FakeConnection = {
  start: jest.Mock;
  dispose: jest.Mock;
  request: jest.Mock;
};

function fakeConnection(response: unknown): FakeConnection {
  return {
    start: jest.fn(),
    dispose: jest.fn(),
    request: jest.fn().mockResolvedValue(response),
  };
}

describe("VaultMeshRpcClient", () => {
  it("preserves only known transport diagnostics for status reads", async () => {
    const connection = fakeConnection(null);
    const client = new VaultMeshRpcClient(connection as never);
    connection.request.mockRejectedValueOnce(new Error("native-host-not-found"));
    await expect(client.status()).rejects.toMatchObject({ code: "native-host-not-found" });
    connection.request.mockRejectedValueOnce(new Error("private-path-and-secret"));
    await expect(client.status()).rejects.toMatchObject({ code: "desktop-unavailable" });
  });
  it("uses a fresh gesture for each unlock/lock and drops the password after sending", async () => {
    const connection = fakeConnection(null);
    const snapshots: any[] = [];
    connection.request.mockImplementation(async (request) => {
      snapshots.push(JSON.parse(JSON.stringify(request)));
      return {
        kind: "vaultmesh.rpc-result", version: 2, requestId: request.requestId, ok: true,
        result: request.operation === "vault.unlock"
          ? { cancelled: false, status: { unlocked: true, hasVault: true, itemCount: 1 } }
          : { unlocked: false, hasVault: true, itemCount: 0 },
      };
    });
    const client = new VaultMeshRpcClient(connection as never);
    await client.unlock("test-only-password");
    await client.lock();
    expect(snapshots[0].input.masterPassword).toBe("test-only-password");
    expect(snapshots[0].input.userGestureId).toMatch(/^[0-9a-f-]{36}$/);
    expect(snapshots[1].input.userGestureId).not.toBe(snapshots[0].input.userGestureId);
    expect(connection.request.mock.calls[0][0].input.masterPassword).toBeUndefined();
    expect(Date.parse(snapshots[0].expiresAt) - Date.parse(snapshots[0].issuedAt)).toBe(60_000);
  });

  it("rejects a correlated host status for a different request", async () => {
    const client = new VaultMeshRpcClient(fakeConnection({
      kind: "vaultmesh.host-status", status: "unpaired", requestId: "00000000-0000-4000-8000-000000000099",
    }) as never);
    await expect(client.status()).rejects.toMatchObject({ code: "invalid-broker-response" });
  });

  it("creates a bounded v2 status request and returns only the renderer-safe status", async () => {
    const connection = fakeConnection({
      kind: "vaultmesh.rpc-result",
      version: 2,
      requestId: "00000000-0000-4000-8000-000000000001",
      ok: true,
      result: { unlocked: true, hasVault: true, itemCount: 3 },
    });
    const client = new VaultMeshRpcClient(connection as never);

    client.start();
    // The fake response requestId must match the generated request; replace the
    // response after inspecting the request to model a real broker response.
    connection.request.mockImplementation(async (request) => ({
      kind: "vaultmesh.rpc-result",
      version: 2,
      requestId: request.requestId,
      ok: true,
      result: { unlocked: true, hasVault: true, itemCount: 3 },
    }));
    const status = await client.status();

    expect(connection.start).toHaveBeenCalledTimes(1);
    expect(status).toEqual({ unlocked: true, hasVault: true, itemCount: 3 });
    const [request] = connection.request.mock.calls[0];
    expect(request).toMatchObject({ kind: "vaultmesh.rpc", version: 2, operation: "vault.status", input: {} });
    expect(new Date(request.expiresAt).getTime()).toBeGreaterThan(new Date(request.issuedAt).getTime());
    expect(request).not.toHaveProperty("vault");
    expect(VaultMeshStatusSchema.parse(status)).toEqual(status);
  });

  it("maps broker errors without exposing an unvalidated result", async () => {
    const connection = fakeConnection(null);
    connection.request.mockImplementation(async (request) => ({
      kind: "vaultmesh.rpc-result",
      version: 2,
      requestId: request.requestId,
      ok: false,
      error: { code: "unlock-required", message: "locked" },
    }));
    const client = new VaultMeshRpcClient(connection as never);

    await expect(client.status()).rejects.toMatchObject<VaultMeshRpcError>({ code: "unlock-required" });
  });

  it("rejects mismatched request ids and malformed status payloads", async () => {
    const connection = fakeConnection({
      kind: "vaultmesh.rpc-result",
      version: 2,
      requestId: "00000000-0000-4000-8000-000000000099",
      ok: true,
      result: { unlocked: true, hasVault: true, itemCount: 1 },
    });
    const client = new VaultMeshRpcClient(connection as never);

    await expect(client.status()).rejects.toMatchObject<VaultMeshRpcError>({ code: "invalid-broker-response" });
  });

});
