import { PasswordRandomizer } from "../../libs/tools/generator/core/src/engine/password-randomizer";
import type { Randomizer } from "../../libs/tools/generator/core/src/engine/abstractions";
import { DEFAULT_GENERATOR_PREFERENCES, nativePasswordRequest, type GeneratorPreferences } from "./generator-preferences";

/** Web Crypto entropy adapter; password composition stays in Bitwarden. */
export class WebCryptoRandomizer implements Randomizer {
  async uniform(min: number, max: number): Promise<number> {
    const range = max - min + 1;
    if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || range < 1 || range > 0x100000000) throw new Error("Invalid random range.");
    const limit = 0x100000000 - (0x100000000 % range);
    const bytes = new Uint32Array(1);
    try {
      do { crypto.getRandomValues(bytes); } while (bytes[0] >= limit);
      return min + bytes[0] % range;
    } finally { bytes.fill(0); }
  }
  async pick<T>(items: T[]): Promise<T> {
    if (!items.length) throw new Error("Empty random source.");
    return items[await this.uniform(0, items.length - 1)];
  }
  async shuffle<T>(items: T[]): Promise<T[]> {
    const shuffled = [...items];
    for (let i = shuffled.length - 1; i > 0; i--) {
      const j = await this.uniform(0, i);
      [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
    }
    return shuffled;
  }
  async pickWord(items: string[], options?: { titleCase?: boolean; number?: boolean }): Promise<string> {
    let word = await this.pick(items);
    if (options?.titleCase) word = word.charAt(0).toUpperCase() + word.slice(1);
    if (options?.number) word += await this.uniform(0, 9);
    return word;
  }
  async chars(length: number): Promise<string> {
    if (!Number.isInteger(length) || length < 0 || length > 1024) throw new Error("Invalid random length.");
    const alphabet = [..."abcdefghijklmnopqrstuvwxyz1234567890"];
    return (await Promise.all(Array.from({ length }, () => this.pick(alphabet)))).join("");
  }
}

export function generateMaintenancePassword(options: GeneratorPreferences["password"] = DEFAULT_GENERATOR_PREFERENCES.password): Promise<string> {
  return new PasswordRandomizer(new WebCryptoRandomizer(), Date.now).randomAscii(nativePasswordRequest(options));
}
