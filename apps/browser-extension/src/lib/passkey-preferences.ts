import { z } from "zod";

import type { PasskeyOperation } from "@/lib/passkey-shim";

/** Non-secret, per-origin choice of who serves a WebAuthn operation. */
export type PasskeyProviderChoice = "vaultmesh" | "native";

const KEY_PREFIX = "vaultmesh.passkey.choice.v1:";
const choiceSchema = z.enum(["vaultmesh", "native"]);

function preferenceKey(operation: PasskeyOperation, origin: string): string | null {
  try {
    const url = new URL(origin);
    if ((url.protocol !== "http:" && url.protocol !== "https:") || url.origin !== origin) return null;
    return `${KEY_PREFIX}${operation}:${url.origin}`;
  } catch {
    return null;
  }
}

export async function rememberPasskeyChoice(operation: PasskeyOperation, origin: string, choice: PasskeyProviderChoice): Promise<void> {
  const key = preferenceKey(operation, origin);
  if (!key) return;
  await browser.storage.local.set({ [key]: choice });
}

export async function rememberedPasskeyChoice(operation: PasskeyOperation, origin: string): Promise<PasskeyProviderChoice | null> {
  const key = preferenceKey(operation, origin);
  if (!key) return null;
  try {
    const stored = await browser.storage.local.get(key);
    const parsed = choiceSchema.safeParse(stored[key]);
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export async function clearPasskeyChoices(): Promise<void> {
  const all = await browser.storage.local.get(null);
  const keys = Object.keys(all).filter((key) => key.startsWith(KEY_PREFIX));
  if (keys.length > 0) await browser.storage.local.remove(keys);
}
