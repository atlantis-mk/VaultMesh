import { afterEach, describe, expect, it } from "vitest";

import { captureSubmittedData } from "./save-capture";

afterEach(() => { document.body.innerHTML = ""; });

describe("captureSubmittedData", () => {
  it.each([
    '<input type="hidden" autocomplete="username" value="ada@example.test">',
    '<div hidden><input type="email" autocomplete="username" value="ada@example.test"></div>',
    '<input type="email" autocomplete="username" value="ada@example.test" style="display:none" readonly>',
  ])("captures the selected account retained by a password step: %s", (account) => {
    document.body.innerHTML = `<form>${account}<input type="password" autocomplete="current-password" value="synthetic password"></form>`;
    expect(captureSubmittedData(document.querySelector("form")!, "https://accounts.example.test/login").login)
      .toEqual({ username: "ada@example.test", password: "synthetic password" });
  });

  it("does not guess between conflicting hidden accounts or use arbitrary hidden values", () => {
    for (const accounts of [
      '<input type="hidden" autocomplete="username" value="ada"><input type="hidden" autocomplete="username" value="grace">',
      '<input type="hidden" name="email" value="never-capture"><input type="hidden" name="token" value="never-capture">',
    ]) {
      document.body.innerHTML = `<form>${accounts}<input type="password" autocomplete="current-password" value="synthetic password"></form>`;
      expect(captureSubmittedData(document.querySelector("form")!, "https://example.test/login").login)
        .toEqual({ username: "", password: "synthetic password" });
    }
  });

  it("prefers the current visible account over a hidden account from an earlier step", () => {
    document.body.innerHTML = `<form>
      <input type="hidden" autocomplete="username" value="old@example.test">
      <input autocomplete="username" value="new@example.test">
      <input type="password" autocomplete="current-password" value="synthetic password">
    </form>`;
    expect(captureSubmittedData(document.querySelector("form")!, "https://example.test/login").login)
      .toEqual({ username: "new@example.test", password: "synthetic password" });
  });

  it("does not read a hidden account owned by a different form", () => {
    document.body.innerHTML = `<form id="other"><input type="hidden" autocomplete="username" value="other@example.test"></form>
      <form id="login"><input type="hidden" form="other" autocomplete="username" value="other@example.test"><input type="password" autocomplete="current-password" value="synthetic password"></form>`;
    expect(captureSubmittedData(document.querySelector("#login")!, "https://example.test/login").login)
      .toEqual({ username: "", password: "synthetic password" });
  });

  it("ignores a CSS-hidden password retained from another step", () => {
    document.body.innerHTML = `<form><input autocomplete="username" value="ada">
      <input type="password" style="display:none" value="never-capture">
      <input type="password" autocomplete="current-password" value="synthetic password">
    </form>`;
    expect(captureSubmittedData(document.querySelector("form")!, "https://example.test/login").login)
      .toEqual({ username: "ada", password: "synthetic password" });
  });

  it("does not offer a mismatched or empty new-password confirmation for saving", () => {
    for (const confirmation of ["different password", ""]) {
      document.body.innerHTML = `<form><input type="password" autocomplete="current-password" value="old password"><input type="password" autocomplete="new-password" value="new password"><input type="password" autocomplete="new-password"></form>`;
      document.querySelectorAll<HTMLInputElement>("input")[2]!.value = confirmation;
      expect(captureSubmittedData(document.querySelector("form")!, "https://example.test/settings", { context: "password-change" }).login).toBeUndefined();
    }
  });
  it("captures a newly submitted login without exposing unrelated fields", () => {
    document.body.innerHTML = `<form>
      <input autocomplete="username" value="ada@example.test">
      <input type="password" autocomplete="current-password" value="correct horse battery staple">
      <input name="search" value="private search">
    </form>`;

    const result = captureSubmittedData(document.querySelector("form")!, "https://accounts.example.test/login", { context: "login" });

    expect(result).toEqual({ login: { username: "ada@example.test", password: "correct horse battery staple" } });
    expect(JSON.stringify(result)).not.toContain("private search");
  });

  it("takes the filled account of the password's own form when a page has several sign-in forms", () => {
    document.body.innerHTML = `<form><input autocomplete="username"><input name="code" autocomplete="one-time-code"></form>
      <form><input autocomplete="username" value="qa-otp@vaultmesh.test"><input type="password" autocomplete="current-password" value="synthetic password"></form>`;

    expect(captureSubmittedData(document.body, "https://accounts.example.test/login", { context: "login" }).login)
      .toEqual({ username: "qa-otp@vaultmesh.test", password: "synthetic password" });
  });

  it("captures the new password rather than the current password on password-change forms", () => {
    document.body.innerHTML = `<form>
      <input autocomplete="username" value="ada">
      <input type="password" autocomplete="current-password" value="old password">
      <input type="password" autocomplete="new-password" value="new password">
      <input type="password" autocomplete="new-password" value="new password">
    </form>`;

    expect(captureSubmittedData(document.querySelector("form")!, "https://example.test/settings", { context: "password-change" }).login)
      .toEqual({ username: "ada", password: "new password" });
  });

  it("captures login and reusable identity data together during signup", () => {
    document.body.innerHTML = `<form>
      <input autocomplete="given-name" value="Ada">
      <input autocomplete="family-name" value="Lovelace">
      <input autocomplete="email" value="ada@example.test">
      <input autocomplete="tel" value="+86 138 0000 0000">
      <input autocomplete="new-password" type="password" value="generated password">
    </form>`;

    const result = captureSubmittedData(document.querySelector("form")!, "https://example.test/signup", { context: "signup" });

    expect(result.login).toEqual({ username: "ada@example.test", password: "generated password" });
    expect(result.identity).toMatchObject({
      title: "Ada Lovelace", firstName: "Ada", lastName: "Lovelace",
      emails: [{ value: "ada@example.test", preferred: true }],
      phones: [{ value: "+86 138 0000 0000", preferred: true }],
    });
  });

  it("captures a shipping address for future identity autofill", () => {
    document.body.innerHTML = `<form>
      <input autocomplete="shipping address-line1" value="文一西路 969 号">
      <input autocomplete="shipping address-level2" value="杭州">
      <input autocomplete="shipping address-level1" value="浙江">
      <input autocomplete="shipping postal-code" value="311121">
      <select autocomplete="shipping country"><option value="CN" selected>中国</option></select>
    </form>`;

    const result = captureSubmittedData(document.querySelector("form")!, "https://shop.example.test/checkout", { context: "checkout" });

    expect(result.identity?.addresses).toEqual([expect.objectContaining({
      label: "收货", addressLine1: "文一西路 969 号", city: "杭州", region: "浙江", postalCode: "311121", countryCode: "CN",
    })]);
  });

  it("captures a valid payment card and rejects invalid card-like values", () => {
    const nextYear = new Date().getFullYear() + 1;
    document.body.innerHTML = `<form>
      <input autocomplete="cc-name" value="Ada Lovelace">
      <input autocomplete="cc-number" value="4242 4242 4242 4242">
      <input autocomplete="cc-exp-month" value="12">
      <input autocomplete="cc-exp-year" value="${nextYear}">
      <input autocomplete="cc-csc" value="123">
    </form>`;
    const form = document.querySelector("form")!;

    expect(captureSubmittedData(form, "https://shop.example.test/pay", { context: "checkout" }).card).toMatchObject({
      cardholderName: "Ada Lovelace", cardNumber: "4242424242424242", expirationMonth: 12, expirationYear: nextYear, securityCode: "123",
    });
    form.querySelector<HTMLInputElement>('[autocomplete="cc-number"]')!.value = "1234567890123456";
    expect(captureSubmittedData(form, "https://shop.example.test/pay", { context: "checkout" }).card).toBeUndefined();
  });

  it("does not turn an ordinary email-only form into a saved identity", () => {
    document.body.innerHTML = `<form><input type="email" autocomplete="email" value="newsletter@example.test"></form>`;
    expect(captureSubmittedData(document.querySelector("form")!, "https://example.test/newsletter", { context: "unknown" })).toEqual({});
  });
});
