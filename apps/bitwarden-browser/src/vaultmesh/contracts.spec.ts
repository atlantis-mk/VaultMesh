import { LoginSummariesSchema, SessionMessageSchema, SESSION_MESSAGE, StatusResponseSchema, VAULTMESH_STATUS_MESSAGE } from "./contracts";
import { loginSummaryView } from "./login-view";

const summary = {
  id: "00000000-0000-4000-8000-000000000005", title: "Example", username: "alice",
  url: "https://example.test/login", hasPassword: true, hasTotpSecret: true,
  hasRecoveryCodes: false, autofillOnPageLoad: true, masterPasswordReprompt: true,
};
describe("CT-BROWSER-002 VaultMesh metadata boundary", () => {
  it("accepts actual login summaries without invented kind/subtitle and strips protected extras", () => {
    const [parsed] = LoginSummariesSchema.parse([{ ...summary, password: "not-real", totpSecret: "not-real", notes: "unused" }]);
    expect(parsed).toEqual(summary);
    const view = loginSummaryView(parsed);
    expect(view.id).toBe(summary.id);
    expect(view.login.username).toBe("alice");
    expect(view.login.uri).toBe(summary.url);
    expect(view.login.password).toBeUndefined();
    expect(view.login.totp).toBeUndefined();
    expect(view.viewPassword).toBe(false);
  });
  it("accepts locked broker errors without fabricating a ready vault", () => {
    expect(StatusResponseSchema.parse({ kind: VAULTMESH_STATUS_MESSAGE, status: "locked" })).toEqual({ kind: VAULTMESH_STATUS_MESSAGE, status: "locked" });
    expect(StatusResponseSchema.safeParse({ kind: VAULTMESH_STATUS_MESSAGE, status: "ready", vault: { unlocked: false, hasVault: true, itemCount: 0 } }).success).toBe(false);
    expect(StatusResponseSchema.safeParse({ kind: VAULTMESH_STATUS_MESSAGE, status: "anything" }).success).toBe(false);
  });
  it("does not expose a generic operation or allow caller-controlled gesture ids", () => {
    expect(SessionMessageSchema.safeParse({ kind: SESSION_MESSAGE, action: "items.delete" }).success).toBe(false);
    expect(SessionMessageSchema.safeParse({ kind: SESSION_MESSAGE, action: "unlock", masterPassword: "test-only-password", userGestureId: "injected" }).success).toBe(false);
  });
});
