import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("Email OTP popup contract", () => {
  it("shows transient candidates and hands only the candidate ID to background fill", () => {
    const source = readFileSync(resolve(process.cwd(), "src/entrypoints/popup/popup-app.tsx"), "utf8");
    expect(source).toContain("getEmailOtpCandidates(origin)");
    expect(source).toContain("邮箱验证码");
    expect(source).toContain("{candidate.code}");
    expect(source).toContain("正在等待新的邮箱验证码…");
    expect(source).not.toContain("正在等待与当前网站匹配的新验证码");
    expect(source).toContain('kind: "vaultmesh.email-otp-fill", candidateId: candidate.id');
    expect(source).not.toContain("browser.storage");
  });

  it("connects trusted get/resend gestures to Rust polling without carrying page values", () => {
    const source = readFileSync(resolve(process.cwd(), "src/entrypoints/background.ts"), "utf8");
    expect(source).toContain('backgroundDesktopRpc("email.otp.watch", { topOrigin: page.topOrigin, active: true })');
    expect(source).toContain('backgroundDesktopRpc("email.otp.poll")');
    expect(source).not.toContain("verification_code.value");
  });

  it("routes inline candidate lookup and selection through the originating trusted page", () => {
    const background = readFileSync(resolve(process.cwd(), "src/entrypoints/background.ts"), "utf8");
    const content = readFileSync(resolve(process.cwd(), "src/lib/autofill-page.ts"), "utf8");
    expect(background).toContain('emailOtpCandidates: emailOtp.status === "ready" ? emailOtp.candidates : []');
    expect(background).toContain('page.fillOrigin !== page.topOrigin');
    expect(background).toContain('fillEmailOtpForTab(page.tabId, page.topOrigin, page.framePageUrl, parsed.data.candidateId, parsed.data.target, sender.frameId ?? 0)');
    expect(content).toContain('kind: "vaultmesh.email-otp-select", candidateId: candidate.id');
    expect(content).not.toContain('kind: "vaultmesh.email-otp-select", candidateId: candidate.id, code: candidate.code');
  });
});
