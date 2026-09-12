import { describe, expect, it } from "vitest";

import { ContentMessageSchema, DiscoveryFrameResponseSchema, DiscoveryFrameSchema, FillRequestSchema, PageInformationDetectionResponseSchema, PopupMessageSchema, SaveCapturePendingResponseSchema, SaveCaptureReadyMessageSchema, TotpQrScanResponseSchema } from "./protocol";

describe("browser form discovery protocol", () => {
  it("accepts a content-script response before the background attaches frameId", () => {
    const response = {
      documentId: "953370ec-4dc7-4c77-a6e0-f2a4f6e37f03",
      frameOrigin: "https://www.bilibili.com",
      fields: [{
        handle: "a5370ec1-4dc7-4c77-a6e0-f2a4f6e37f03",
        control: "input",
        inputType: "text",
        isEmpty: true,
        autocomplete: ["username"],
        label: "账号",
        name: "username",
        id: "login-username",
        placeholder: "请输入账号",
      }],
    };

    const parsed = DiscoveryFrameResponseSchema.parse(response);
    expect(DiscoveryFrameSchema.safeParse(response).success).toBe(false);
    expect(DiscoveryFrameSchema.parse({ ...parsed, frameId: 0 })).toMatchObject({ frameId: 0, fields: [{ autocomplete: ["username"] }] });
  });

  it("binds a fill request's exact target page URL to its target frame origin", () => {
    const frame = {
      frameId: 2,
      documentId: crypto.randomUUID(),
      frameOrigin: "https://auth.example.test",
      fields: [{
        handle: crypto.randomUUID(), control: "input", inputType: "password", isEmpty: true,
        autocomplete: ["current-password"], label: "Password", name: "password", id: "password", placeholder: "", context: "login",
      }],
    };
    const request = {
      version: 1, requestId: crypto.randomUUID(), issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60_000).toISOString(),
      tabId: 1, topOrigin: "https://shop.example.test", targetOrigin: "https://auth.example.test", targetPageUrl: "https://auth.example.test/login", frames: [frame],
    };
    expect(FillRequestSchema.safeParse(request).success).toBe(true);
    expect(FillRequestSchema.safeParse({ ...request, targetPageUrl: "https://evil.example.test/login" }).success).toBe(false);
    expect(FillRequestSchema.safeParse({ ...request, targetOrigin: "https://auth.example.test/path" }).success).toBe(false);
  });

  it("accepts one-time plugin payment-card and identity confirmation messages", () => {
    const fillConfirmationToken = crypto.randomUUID();
    const card = { kind: "card", id: crypto.randomUUID(), title: "Work card" };
    const identity = { kind: "identity", id: crypto.randomUUID(), title: "Ada" };
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.popup-workspace-cache.get" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.popup-suggestions.get" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.fill-confirmation.get" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-popup.get" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-popup.decision", captureId: crypto.randomUUID(), decision: "save" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-window.get" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-window.decision", decision: "ignore" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.security-policy.updated" }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.fill-confirmation.cancel", fillConfirmationToken }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.start-fill", selectedItem: card, masterPassword: "master-password", fillConfirmationToken }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.start-fill", selectedItem: identity, fillConfirmationToken }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.start-fill", selectedItem: card, masterPassword: "short", fillConfirmationToken }).success).toBe(false);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.email-otp-fill", candidateId: crypto.randomUUID() }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.email-otp-fill", candidateId: "not-a-uuid", code: "123456" }).success).toBe(false);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.email-otp-select", candidateId: crypto.randomUUID() }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.email-otp-select", candidateId: "not-a-uuid", code: "123456" }).success).toBe(false);
  });

  it("accepts only a boolean value-free account-replacement intent for inline login selection", () => {
    const selectedItem = { kind: "login", id: crypto.randomUUID(), title: "Apple" };
    expect(PopupMessageSchema.safeParse({
      kind: "vaultmesh.autofill-select",
      selectedItem,
      replaceExistingAccount: true,
    }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({
      kind: "vaultmesh.autofill-select",
      selectedItem,
      replaceExistingAccount: "account@example.test",
    }).success).toBe(false);
  });

  it("validates active page recognition and confirmed-save messages", () => {
    const captureId = crypto.randomUUID();
    const data = {
      identity: {
        title: "Ada", firstName: "Ada", middleName: null, lastName: "Lovelace", birthDate: null,
        emails: [], phones: [], addresses: [], organization: null, department: null, jobTitle: null, website: null,
      },
    };
    expect(ContentMessageSchema.safeParse({ kind: "vaultmesh.detect-page-information" }).success).toBe(true);
    expect(ContentMessageSchema.safeParse({ kind: "vaultmesh.scan-totp-qr" }).success).toBe(true);
    expect(ContentMessageSchema.safeParse({ kind: "vaultmesh.save-page-information", captureId, pageUrl: "https://example.test/profile", data }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-confirmed", captureId, pageUrl: "https://example.test/profile", data }).success).toBe(true);
    expect(PageInformationDetectionResponseSchema.safeParse({
      status: "detected", captureId, pageUrl: "https://example.test/profile", pageTitle: "Profile", data, ignoredSensitiveFields: [],
    }).success).toBe(true);
    expect(ContentMessageSchema.safeParse({ kind: "vaultmesh.save-page-information", captureId, pageUrl: "chrome://settings", data }).success).toBe(false);
  });

  it("limits navigation-resume messages to non-secret save prompt metadata", () => {
    const captureId = crypto.randomUUID();
    const prompt = { status: "queued", captureId, hostname: "example.test", labels: ["登录信息"], update: false, expiresAt: Date.now() + 10_000, actions: { login: "new" } };
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-pending" }).success).toBe(true);
    expect(SaveCapturePendingResponseSchema.safeParse(prompt).success).toBe(true);
    expect(SaveCapturePendingResponseSchema.parse({ ...prompt, password: "must-not-cross" })).not.toHaveProperty("password");
    expect(SaveCapturePendingResponseSchema.safeParse({ status: "preparing", captureId: prompt.captureId }).success).toBe(true);
    expect(SaveCapturePendingResponseSchema.safeParse({ status: "none" }).success).toBe(true);
    const pushed = SaveCaptureReadyMessageSchema.parse({ kind: "vaultmesh.save-capture-ready", prompt: { ...prompt, password: "must-not-cross" } });
    expect(pushed.prompt).not.toHaveProperty("password");
    expect(pushed.prompt.expiresAt).toBe(prompt.expiresAt);
  });

  it("validates TOTP QR scan results without accepting arbitrary secrets", () => {
    expect(TotpQrScanResponseSchema.safeParse({
      status: "found",
      values: [{ uri: "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example", issuer: "Example", account: "ada" }],
    }).success).toBe(true);
    expect(TotpQrScanResponseSchema.safeParse({
      status: "found",
      values: [{ uri: "https://evil.example/secret", issuer: null, account: null }],
    }).success).toBe(false);
    expect(TotpQrScanResponseSchema.safeParse({
      status: "found",
      values: [{ uri: "otpauth://hotp/Example:ada?secret=JBSWY3DPEHPK3PXP", issuer: "Example", account: "ada" }],
    }).success).toBe(false);
    expect(TotpQrScanResponseSchema.safeParse({
      status: "found",
      values: [{ uri: "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&digits=8", issuer: "Example", account: "ada" }],
    }).success).toBe(false);
  });

  it("accepts captured API secrets and SSH key material", () => {
    const captureId = crypto.randomUUID();
    const data = {
      secrets: [{
        title: "GitHub 访问令牌", kind: "access-token", secret: "github_pat_A1b2C3d4E5f6G7h8I9j0K1l2",
        provider: "GitHub", account: null, environment: null, scopes: [], expiresAt: null, website: "https://github.com/settings/tokens",
      }],
      sshCredentials: [{
        title: "GitHub SSH 密钥", host: null, port: 22, username: "", password: null,
        publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest", privateKey: null, keyPassphrase: null,
      }],
    };
    expect(ContentMessageSchema.safeParse({ kind: "vaultmesh.save-page-information", captureId, pageUrl: "https://github.com/settings/tokens", data }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({ kind: "vaultmesh.save-capture-confirmed", captureId, pageUrl: "https://github.com/settings/tokens", data }).success).toBe(true);
    expect(PopupMessageSchema.safeParse({
      kind: "vaultmesh.save-capture-confirmed", captureId, pageUrl: "https://github.com/settings/tokens",
      data: { sshCredentials: [{ ...data.sshCredentials[0], publicKey: null }] },
    }).success).toBe(false);
  });
});
