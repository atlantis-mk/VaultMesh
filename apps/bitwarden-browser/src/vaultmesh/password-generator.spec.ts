import { generateMaintenancePassword, WebCryptoRandomizer } from "./password-generator";

describe("CT-AUTOFILL-001 native password composition", () => {
  it("uses Bitwarden composition with every enabled class", async () => {
    const password = await generateMaintenancePassword();
    expect(password).toHaveLength(20);
    expect(password).toMatch(/[a-z]/); expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/); expect(password).toMatch(/[^a-zA-Z0-9]/);
  });
  it("rejects modulo-biased samples and erases the entropy buffer", async () => {
    let buffer: Uint32Array | undefined;
    const getRandom = jest.spyOn(crypto, "getRandomValues").mockImplementation((array) => {
      buffer = array as Uint32Array;
      buffer[0] = getRandom.mock.calls.length === 1 ? 0xffffffff : 7;
      return array;
    });
    try {
      expect(await new WebCryptoRandomizer().uniform(0, 9)).toBe(7);
      expect(getRandom).toHaveBeenCalledTimes(2); expect(buffer?.[0]).toBe(0);
    } finally { getRandom.mockRestore(); }
  });
});
