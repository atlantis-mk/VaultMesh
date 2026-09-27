import { act, createElement } from "react";
import { createRoot } from "react-dom/client";
import { describe, expect, it, vi } from "vitest";

import { candidateGroups, InlineAutofillView } from "./inline-autofill-view";

const exact = { id: "153370ec-4dc7-4c77-a6e0-f2a4f6e37f03", kind: "login" as const, title: "Port login", subtitle: "port-user", matchScope: "origin" as const };
const domain = { id: "253370ec-4dc7-4c77-a6e0-f2a4f6e37f03", kind: "login" as const, title: "Domain login", subtitle: "domain-user", matchScope: "domain" as const };
const path = { id: "353370ec-4dc7-4c77-a6e0-f2a4f6e37f03", kind: "login" as const, title: "Path login", subtitle: "path-user", matchScope: "path" as const };

describe("candidateGroups", () => {
  it("shows exact domain-and-port matches before same-domain matches", () => {
    const groups = candidateGroups([domain, exact, path], "example.test:8443", "example.test");

    expect(groups.map((group) => group.label)).toEqual(["当前站点 · example.test:8443", "同域名 · example.test"]);
    expect(groups.map((group) => group.candidates.map((candidate) => candidate.id))).toEqual([[path.id, exact.id], [domain.id]]);
  });

  it("CT-DEVICE-ASSIST-002 keeps paired-phone sources out of the same-domain vault group", () => {
    const phone = { kind: "device-assist" as const, id: "device-assist", assistKind: "sms" as const, title: "从手机获取验证码", subtitle: "已配对设备 · 在电脑点选填充" };
    const groups = candidateGroups([exact, phone], "example.test:8443", "example.test");

    expect(groups.map((group) => group.label)).toEqual(["当前站点 · example.test:8443", "已配对手机"]);
    expect(groups.at(-1)!.candidates).toEqual([phone]);
    expect(candidateGroups([phone], "example.test:8443", "example.test")).toEqual([{ key: "device-assist", label: null, candidates: [phone] }]);
  });

  it("shows current-origin email codes before saved authenticator logins", () => {
    const emailOtp = {
      id: "453370ec-4dc7-4c77-a6e0-f2a4f6e37f03",
      kind: "email-otp" as const,
      title: "A12B34",
      subtitle: "来自 example.test",
      code: "A12B34",
      sourceDomain: "example.test",
      receivedAt: 1,
      expiresAt: 2,
    };

    const groups = candidateGroups([domain, emailOtp, exact], "example.test", "example.test");

    expect(groups.map((group) => group.label)).toEqual(["邮箱验证码", "当前站点 · example.test", "同域名 · example.test"]);
    expect(groups[0]?.candidates).toEqual([emailOtp]);
  });

  it("renders bounded fill feedback without inventing an empty candidate message", async () => {
    const container = document.createElement("div");
    const root = createRoot(container);
    await act(async () => root.render(createElement(InlineAutofillView, {
      candidates: [],
      currentHost: "example.test",
      currentHostname: "example.test",
      generatedLoginKey: 1,
      generatedMode: "none",
      statusMessage: "页面已经变化，请重新选择要填充的项目。",
      onGeneratedPasswordSelect: vi.fn(),
      onGeneratedSelect: vi.fn(),
      onSelect: vi.fn(),
    })));

    expect(container.querySelector('[role="status"]')?.textContent).toContain("页面已经变化");
    expect(container.querySelector(".empty")).toBeNull();
    await act(async () => root.unmount());
  });

  it("keeps modal focus traps from destroying a pointer-selected candidate before click", async () => {
    const container = document.createElement("div");
    const root = createRoot(container);
    const onSelect = vi.fn();
    await act(async () => root.render(createElement(InlineAutofillView, {
      candidates: [exact],
      currentHost: "example.test",
      currentHostname: "example.test",
      generatedLoginKey: 1,
      generatedMode: "none",
      onGeneratedPasswordSelect: vi.fn(),
      onGeneratedSelect: vi.fn(),
      onSelect,
    })));
    const option = container.querySelector<HTMLButtonElement>('[role="option"]')!;
    const pointerDown = new Event("pointerdown", { bubbles: true, cancelable: true, composed: true });

    await act(async () => option.dispatchEvent(pointerDown));
    expect(pointerDown.defaultPrevented).toBe(true);
    expect(onSelect).not.toHaveBeenCalled();

    await act(async () => option.click());
    expect(onSelect).toHaveBeenCalledWith(exact);
    await act(async () => root.unmount());
  });

  it("shows and refreshes a selectable generated login when no candidates exist", async () => {
    const container = document.createElement("div");
    const root = createRoot(container);
    const onGeneratedSelect = vi.fn();
    await act(async () => root.render(createElement(InlineAutofillView, {
      candidates: [],
      currentHost: "example.test",
      currentHostname: "example.test",
      generatedLoginKey: 1,
      generatedMode: "login",
      passwordGeneratorOptions: { length: 18, uppercase: false, lowercase: true, numbers: false, symbols: false, minimumNumbers: 0, minimumSymbols: 0, avoidAmbiguous: true },
      usernameGeneratorOptions: { length: 12, prefix: "", style: "random", includeNumber: false },
      onGeneratedPasswordSelect: vi.fn(),
      onGeneratedSelect,
      onSelect: vi.fn(),
    })));
    const username = () => container.querySelector<HTMLElement>(".generated-username")!.textContent;
    const password = () => container.querySelector<HTMLElement>(".generated-password")!.textContent;
    const before = `${username()}:${password()}`;

    expect(username()).toMatch(/^[a-z2-9]{12}$/);
    expect(username()).not.toContain("@");
    expect(password()).toMatch(/^[a-z]{18}$/);
    await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="刷新随机账号和密码"]')!.click());
    expect(`${username()}:${password()}`).not.toBe(before);
    await act(async () => container.querySelector<HTMLButtonElement>('[role="option"]')!.click());
    expect(onGeneratedSelect).toHaveBeenCalledWith({ username: username(), password: password() });
    await act(async () => root.unmount());
  });

  it("previews, refreshes, and only fills a generated password after selection", async () => {
    const container = document.createElement("div");
    const root = createRoot(container);
    const onGeneratedPasswordSelect = vi.fn();
    await act(async () => root.render(createElement(InlineAutofillView, {
      candidates: [],
      currentHost: "example.test",
      currentHostname: "example.test",
      generatedLoginKey: 1,
      generatedMode: "password",
      passwordGeneratorOptions: { length: 28, uppercase: false, lowercase: true, numbers: false, symbols: false, minimumNumbers: 0, minimumSymbols: 0, avoidAmbiguous: true },
      onGeneratedPasswordSelect,
      onGeneratedSelect: vi.fn(),
      onSelect: vi.fn(),
    })));
    const password = () => container.querySelector<HTMLElement>(".generated-password")!.textContent!;
    const before = password();

    expect(before).toHaveLength(28);
    expect(before).toMatch(/^[a-z]+$/);
    expect(onGeneratedPasswordSelect).not.toHaveBeenCalled();
    await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="刷新随机密码"]')!.click());
    expect(password()).not.toBe(before);
    expect(onGeneratedPasswordSelect).not.toHaveBeenCalled();
    const refreshed = password();
    await act(async () => container.querySelector<HTMLButtonElement>('[role="option"]')!.click());
    expect(onGeneratedPasswordSelect).toHaveBeenCalledWith(refreshed);
    await act(async () => root.unmount());
  });
});
