import { z } from "zod";
import type { NativeCandidate } from "./native-fill-contracts";

const KEY = "vaultmesh.bitwarden-dev.autofill.v1";
const origin = z.string().max(2048).refine((value) => {
  try { const url = new URL(value); return /^https?:$/.test(url.protocol) && url.origin === value; } catch { return false; }
});
const preferences = z.array(z.object({ origin, id: z.string().uuid() }).strict()).max(200);

/** Background-owned nonsecret preferences. No summaries, values, drafts or authorizations. */
export class AutofillPreferences {
  private writes: Promise<void> = Promise.resolve();
  private async read(): Promise<z.infer<typeof preferences>> {
    return new Promise((resolve) => chrome.storage.local.get(KEY, (stored) => {
      const parsed = preferences.safeParse(stored?.[KEY]);
      resolve(!chrome.runtime.lastError && parsed.success ? parsed.data : []);
    }));
  }
  async remembered(targetOrigin: string): Promise<string | undefined> {
    if (!origin.safeParse(targetOrigin).success) return undefined;
    await this.writes;
    return (await this.read()).find((entry) => entry.origin === targetOrigin)?.id;
  }
  async remember(targetOrigin: string, id: string): Promise<void> {
    if (!origin.safeParse(targetOrigin).success || !z.string().uuid().safeParse(id).success) return;
    const write = this.writes.then(async () => {
      const next = (await this.read()).filter((entry) => entry.origin !== targetOrigin).slice(-199);
      next.push({ origin: targetOrigin, id });
      await new Promise<void>((resolve) => chrome.storage.local.set({ [KEY]: next }, () => { void chrome.runtime.lastError; resolve(); }));
    });
    this.writes = write.catch((): undefined => undefined);
    await write;
  }
}

export function automaticCandidate(candidates: NativeCandidate[], remembered?: string): NativeCandidate | undefined {
  const rank = { path: 0, origin: 1, domain: 2 };
  const eligible = candidates.filter((candidate) => candidate.kind === "login" && candidate.autofillOnPageLoad && !candidate.masterPasswordReprompt && candidate.matchScope in rank);
  const prior = eligible.find((candidate) => candidate.id === remembered);
  if (prior) return prior;
  eligible.sort((a, b) => rank[a.matchScope as keyof typeof rank] - rank[b.matchScope as keyof typeof rank]);
  if (eligible.length > 1 && eligible[0].matchScope === eligible[1].matchScope) return undefined;
  return eligible[0];
}
