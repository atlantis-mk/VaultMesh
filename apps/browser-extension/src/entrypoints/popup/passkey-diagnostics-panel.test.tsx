import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PasskeyDiagnosticsPanel } from "./passkey-diagnostics-panel";

vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
let container: HTMLDivElement;
let root: Root;
const sendMessage = vi.fn();

const button = (text: string) => Array.from(container.querySelectorAll("button")).find((element) => element.textContent?.includes(text))!;
const click = async (text: string) => { await act(async () => { button(text).click(); }); };

beforeEach(() => {
  sendMessage.mockReset();
  vi.spyOn(browser.runtime, "sendMessage").mockImplementation(sendMessage as never);
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(() => { act(() => root.unmount()); container.remove(); vi.restoreAllMocks(); });

describe("CT-PASSKEY-002 passkey diagnostics panel", () => {
  it("is collapsed until asked, then lists the newest request first with a plain explanation", async () => {
    sendMessage.mockResolvedValue({ entries: [
      { at: 1_000, message: "[VaultMesh Passkey] get https://github.com -> browser (no-matching-passkey)" },
      { at: 2_000, message: "[VaultMesh Passkey] create https://github.com -> cancelled (unlock-timed-out)" },
    ] });
    await act(async () => { root.render(createElement(PasskeyDiagnosticsPanel)); });
    expect(container.textContent).not.toContain("github.com");
    await click("查看最近的通行密钥请求");
    expect(sendMessage).toHaveBeenCalledWith({ kind: "vaultmesh.passkey-diagnostics.get" });
    const items = Array.from(container.querySelectorAll("li"));
    expect(items).toHaveLength(2);
    expect(items[0].textContent).toContain("create https://github.com -> cancelled (unlock-timed-out)");
    expect(items[0].textContent).toContain("5 分钟内没有解锁");
    expect(items[1].textContent).toContain("VaultMesh 里没有该网站的通行密钥");
    expect(container.textContent).not.toContain("[VaultMesh Passkey]");
  });

  it("shows an empty state, clears entries and collapses", async () => {
    sendMessage.mockResolvedValueOnce({ entries: [{ at: 1, message: "[VaultMesh Passkey] get https://a.test -> browser (takeover-disabled)" }] });
    await act(async () => { root.render(createElement(PasskeyDiagnosticsPanel)); });
    await click("查看最近的通行密钥请求");
    sendMessage.mockResolvedValueOnce({ status: "cleared" });
    await click("清除");
    expect(sendMessage).toHaveBeenLastCalledWith({ kind: "vaultmesh.passkey-diagnostics.clear" });
    expect(container.textContent).toContain("暂无记录");
    expect(button("清除").disabled).toBe(true);
    await click("收起");
    expect(container.textContent).toContain("查看最近的通行密钥请求");
  });

  it("treats a failed or malformed response as no records instead of crashing", async () => {
    sendMessage.mockRejectedValueOnce(new Error("worker asleep"));
    await act(async () => { root.render(createElement(PasskeyDiagnosticsPanel)); });
    await click("查看最近的通行密钥请求");
    expect(container.textContent).toContain("暂无记录");
    sendMessage.mockResolvedValueOnce({ entries: "nope" });
    await click("刷新");
    expect(container.textContent).toContain("暂无记录");
  });
});
