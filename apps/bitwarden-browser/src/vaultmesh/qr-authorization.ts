import { z } from "zod";
import { createVaultMeshUuid } from "./uuid";
import { QR_CHECK, type QrGrant } from "./qr-contracts";
export class QrAuthorization {
  private grant?: { metadata: QrGrant; started: Set<number>; finished: Set<number>; current: () => Promise<boolean> };
  start(): void {
    chrome.runtime.onMessage.addListener((message, sender, respond) => {
      if (message?.kind !== QR_CHECK) return false;
      void this.check(message, sender).then(respond, () => respond(false)); return true;
    });
  }
  cancel(): void { this.grant = undefined; }
  async authorize(current: () => Promise<boolean>): Promise<QrGrant> {
    this.cancel();
    const tab = await new Promise<chrome.tabs.Tab>((resolve, reject) => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (chrome.runtime.lastError || tabs.length !== 1 || tabs[0].id == null || !/^https?:\/\//.test(tabs[0].url ?? "")) reject(new Error("page-unavailable")); else resolve(tabs[0]);
    }));
    const frames = await new Promise<chrome.webNavigation.GetAllFrameResultDetails[]>((resolve, reject) => chrome.webNavigation.getAllFrames({ tabId: tab.id! }, (frames) => {
      if (chrome.runtime.lastError || !frames) reject(new Error("page-unavailable")); else resolve(frames);
    }));
    if (!await current()) throw new Error("operation-expired");
    const metadata: QrGrant = { requestId: createVaultMeshUuid(), tabId: tab.id!, topUrl: tab.url!, expiresAt: Date.now() + 30000,
      frames: frames.filter((frame) => /^https?:\/\//.test(frame.url)).slice(0, 16).map(({ frameId, url }) => ({ frameId, url })) };
    this.grant = { metadata, started: new Set(), finished: new Set(), current }; return metadata;
  }
  private async check(message: unknown, sender: chrome.runtime.MessageSender): Promise<boolean> {
    const parsed = z.object({ kind: z.literal(QR_CHECK), requestId: z.uuid(), phase: z.enum(["start", "finish"]) }).strict().safeParse(message);
    const grant = this.grant;
    if (!parsed.success || !grant || sender.id !== chrome.runtime.id || sender.tab?.id !== grant.metadata.tabId || sender.frameId == null
      || parsed.data.requestId !== grant.metadata.requestId || Date.now() >= grant.metadata.expiresAt || !grant.metadata.frames.some((frame) => frame.frameId === sender.frameId && frame.url === sender.url)) return false;
    const set = parsed.data.phase === "start" ? grant.started : grant.finished;
    if (set.has(sender.frameId) || parsed.data.phase === "finish" && !grant.started.has(sender.frameId)) return false;
    set.add(sender.frameId); // Consume before await so duplicate checks cannot race.
    const tab = await new Promise<chrome.tabs.Tab | undefined>((resolve) => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(chrome.runtime.lastError ? undefined : tabs[0])));
    const frame = await new Promise<chrome.webNavigation.GetFrameResultDetails | null>((resolve) => chrome.webNavigation.getFrame({ tabId: grant.metadata.tabId, frameId: sender.frameId! }, (value) => resolve(chrome.runtime.lastError ? null : value)));
    return this.grant === grant && tab?.id === grant.metadata.tabId && tab.url === grant.metadata.topUrl && frame?.url === sender.url
      && await grant.current() && this.grant === grant && Date.now() < grant.metadata.expiresAt;
  }
}
