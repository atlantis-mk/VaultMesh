import { describe, expect, it } from "vitest";

import { copyOptions, requiresFillPassword } from "./popup-app";

describe("popup fill confirmation", () => {
  it("collects a current master password for cards and protected non-card items", () => {
    expect(requiresFillPassword({ type: "支付卡", masterPasswordReprompt: false })).toBe(true);
    expect(requiresFillPassword({ type: "登录", masterPasswordReprompt: true })).toBe(true);
    expect(requiresFillPassword({ type: "机密", masterPasswordReprompt: true })).toBe(true);
    expect(requiresFillPassword({ type: "SSH", masterPasswordReprompt: true })).toBe(true);
    expect(requiresFillPassword({ type: "登录", masterPasswordReprompt: false })).toBe(false);
    expect(requiresFillPassword({ type: "身份" })).toBe(false);
  });

  it("only offers copy actions backed by a present protected value", () => {
    expect(copyOptions({ id: crypto.randomUUID(), title: "Card", detail: "", type: "支付卡", hasSecurityCode: false, hasPin: true })).toEqual(["卡号", "PIN"]);
    expect(copyOptions({ id: crypto.randomUUID(), title: "SSH", detail: "", type: "SSH", hasSshPassword: true, hasPublicKey: false, hasPrivateKey: true, hasKeyPassphrase: true })).toEqual(["密码", "私钥", "口令"]);
  });
});
