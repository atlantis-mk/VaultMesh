import { z } from "zod";

import type { PasskeyOperation } from "@/lib/passkey-shim";
import type { PasskeyDefaultMode } from "@/lib/plugin-security-policy";

/** Non-secret, per-origin choice of who serves a WebAuthn operation. */
export type PasskeyProviderChoice = "vaultmesh" | "native";
export type SitePasskeyMode = "default" | "ask" | "vaultmesh" | "native";
export type PasskeySiteScope = {
  origin: string;
  topOrigin?: string;
  sameOriginWithAncestors?: boolean;
};

const KEY_PREFIX = "vaultmesh.passkey.choice.v1:";
const SITE_MODE_PREFIX = "vaultmesh.passkey.site-mode.v1:";
const choiceSchema = z.enum(["vaultmesh", "native"]);
const siteModeSchema = z.enum(["default", "ask", "vaultmesh", "native"]);

function canonicalOrigin(origin: string): string | null {
  try {
    const url = new URL(origin);
    return (url.protocol === "http:" || url.protocol === "https:") && url.origin === origin ? url.origin : null;
  } catch {
    return null;
  }
}

function resolveScope(originOrScope: string | PasskeySiteScope): {
  scopeKey: string;
  isCrossOrigin: boolean;
  origin: string;
  topOrigin: string;
} | null {
  const input = typeof originOrScope === "string" ? { origin: originOrScope } : originOrScope;
  const origin = canonicalOrigin(input.origin);
  if (!origin) return null;
  const topCandidate = input.topOrigin === undefined ? origin : canonicalOrigin(input.topOrigin);
  if (!topCandidate) return null;
  const isCrossOrigin = input.sameOriginWithAncestors === false || topCandidate !== origin;
  return {
    scopeKey: isCrossOrigin ? `${topCandidate}|${origin}` : origin,
    isCrossOrigin,
    origin,
    topOrigin: topCandidate,
  };
}

function preferenceKey(operation: PasskeyOperation, originOrScope: string | PasskeySiteScope): { key: string; isCrossOrigin: boolean } | null {
  const scope = resolveScope(originOrScope);
  if (!scope) return null;
  return { key: `${KEY_PREFIX}${operation}:${scope.scopeKey}`, isCrossOrigin: scope.isCrossOrigin };
}

function siteModeKey(originOrScope: string | PasskeySiteScope): string | null {
  const scope = resolveScope(originOrScope);
  return scope ? `${SITE_MODE_PREFIX}${scope.scopeKey}` : null;
}

export async function rememberPasskeyChoice(
  operation: PasskeyOperation,
  originOrScope: string | PasskeySiteScope,
  choice: PasskeyProviderChoice,
): Promise<void> {
  const resolved = preferenceKey(operation, originOrScope);
  if (!resolved) return;
  if (resolved.isCrossOrigin && operation === "create") return;
  await browser.storage.local.set({ [resolved.key]: choice });
}

export async function rememberedPasskeyChoice(
  operation: PasskeyOperation,
  originOrScope: string | PasskeySiteScope,
): Promise<PasskeyProviderChoice | null> {
  const resolved = preferenceKey(operation, originOrScope);
  if (!resolved) return null;
  if (resolved.isCrossOrigin && operation === "create") return null;
  try {
    const stored = await browser.storage.local.get(resolved.key);
    const parsed = choiceSchema.safeParse(stored[resolved.key]);
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export async function getSitePasskeyMode(originOrScope: string | PasskeySiteScope): Promise<SitePasskeyMode> {
  const key = siteModeKey(originOrScope);
  if (!key) return "default";
  try {
    const stored = await browser.storage.local.get(key);
    const parsed = siteModeSchema.safeParse(stored[key]);
    return parsed.success ? parsed.data : "default";
  } catch {
    return "default";
  }
}

export async function setSitePasskeyMode(
  originOrScope: string | PasskeySiteScope,
  mode: SitePasskeyMode,
): Promise<void> {
  const parsed = siteModeSchema.safeParse(mode);
  const scope = resolveScope(originOrScope);
  if (!parsed.success || !scope) return;
  const modeKey = `${SITE_MODE_PREFIX}${scope.scopeKey}`;
  const opKeys = [`${KEY_PREFIX}create:${scope.scopeKey}`, `${KEY_PREFIX}get:${scope.scopeKey}`];
  await browser.storage.local.remove(opKeys);
  if (parsed.data === "default") {
    await browser.storage.local.remove(modeKey);
    return;
  }
  await browser.storage.local.set({ [modeKey]: parsed.data });
}

export async function resolveEffectivePasskeyPreference(
  operation: PasskeyOperation,
  originOrScope: string | PasskeySiteScope,
  globalDefault: PasskeyDefaultMode = operation === "create" ? "ask" : "vaultmesh",
): Promise<{ choice: PasskeyProviderChoice | "ask" | null; reason: string | null }> {
  const scope = resolveScope(originOrScope);
  if (!scope) return { choice: null, reason: null };

  const mode = await getSitePasskeyMode(scope);
  if (mode === "native") return { choice: "native", reason: "site-mode-native" };
  if (mode === "ask") return { choice: "ask", reason: "site-mode-ask" };
  if (mode === "vaultmesh" && !(scope.isCrossOrigin && operation === "create")) {
    return { choice: "vaultmesh", reason: "site-mode-vaultmesh" };
  }

  if (scope.isCrossOrigin) {
    const topMode = await getSitePasskeyMode(scope.topOrigin);
    if (topMode === "native") return { choice: "native", reason: "site-mode-native" };
    if (topMode === "ask") return { choice: "ask", reason: "site-mode-ask" };
  }

  const remembered = await rememberedPasskeyChoice(operation, scope);
  if (remembered === "native") return { choice: "native", reason: "remembered-browser-choice" };
  if (remembered === "vaultmesh") return { choice: "vaultmesh", reason: "remembered-vaultmesh-choice" };
  if (globalDefault === "vaultmesh" && !(scope.isCrossOrigin && operation === "create")) {
    return { choice: "vaultmesh", reason: "default-vaultmesh" };
  }
  return { choice: null, reason: null };
}

export async function clearPasskeyChoices(): Promise<void> {
  const all = await browser.storage.local.get(null);
  const keys = Object.keys(all).filter((key) => key.startsWith(KEY_PREFIX) || key.startsWith(SITE_MODE_PREFIX));
  if (keys.length > 0) await browser.storage.local.remove(keys);
}
