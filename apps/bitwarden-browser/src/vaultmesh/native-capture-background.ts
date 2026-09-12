import { VaultMeshRpcClient } from "./rpc";
import { LoginDraft } from "./login-draft";
import { ManagedDraft } from "./managed-draft";
import { applyCapturedItem } from "./native-item-capture";
import { CAPTURE_ITEM_SAVE } from "./native-capture-contracts";
import { clearLoginSecrets } from "./login-contracts";
import { createVaultMeshUuid } from "./uuid";
import { CAPTURE_OPTIONS, CAPTURE_SAVE, CAPTURE_STATUS, CaptureRequestSchema, clearCapture } from "./native-capture-contracts";

/** Offers contain metadata only. Protected capture data arrives only on explicit Save. */
export class VaultMeshNativeCaptureBackground {
  private generation = 0;
  private saving = false;
  private activeSave?: { tabId: number; frameId: number };
  private readonly offers = new Map<string, { nonce: string; expires: number; tabId: number; frameId: number; url: string; ids: Set<string>; itemKind?: "card" | "identity" }>();
  constructor(private readonly client: VaultMeshRpcClient, private readonly current: () => Promise<boolean>) {}

  cancel(): void { this.generation++; this.offers.clear(); }

  start(): void {
    chrome.runtime.onMessage.addListener((message, sender, respond) => {
      if (![CAPTURE_OPTIONS, CAPTURE_SAVE, CAPTURE_ITEM_SAVE, CAPTURE_STATUS].includes(message?.kind)) return false;
      void this.handle(message, sender).then(respond, () => respond(null)).finally(() => clearCapture(message));
      return true;
    });
    const navigation = (event: { tabId: number; frameId: number }) => {
      if (this.activeSave?.tabId === event.tabId && (event.frameId === 0 || event.frameId === this.activeSave.frameId)) this.generation++;
      for (const [id, offer] of this.offers) if (offer.tabId === event.tabId && (event.frameId === 0 || event.frameId === offer.frameId)) this.offers.delete(id);
    };
    chrome.webNavigation.onCommitted.addListener(navigation);
    chrome.webNavigation.onHistoryStateUpdated.addListener(navigation);
    chrome.webNavigation.onReferenceFragmentUpdated.addListener(navigation);
    chrome.tabs.onRemoved.addListener((tabId) => navigation({ tabId, frameId: 0 }));
  }

  async handle(message: unknown, sender: chrome.runtime.MessageSender): Promise<unknown> {
    const parsed = CaptureRequestSchema.safeParse(message);
    if (!parsed.success || sender.id !== chrome.runtime.id || sender.tab?.id == null || sender.frameId == null || !sender.url || !/^https?:\/\//.test(sender.url)) {
      clearCapture(message); return null;
    }
    const request = parsed.data;
    const generation = this.generation;
    let draft: LoginDraft | undefined;
    let managed: ManagedDraft | undefined;
    let ownsSave = false;
    try {
      if (!await this.current() || generation !== this.generation) return null;
      const frame = await new Promise<chrome.webNavigation.GetFrameResultDetails | null>((resolve) => {
        chrome.webNavigation.getFrame({ tabId: sender.tab!.id!, frameId: sender.frameId! }, (value) => resolve(chrome.runtime.lastError ? null : value));
      });
      if (frame?.url !== sender.url) return null;
      if (request.kind === CAPTURE_STATUS) return true;
      for (const [id, offer] of this.offers) if (offer.expires <= Date.now()) this.offers.delete(id);
      if (request.kind === CAPTURE_OPTIONS) {
        if (this.offers.has(request.captureId) || this.offers.size >= 32) return null;
        const rows = request.itemKind ? await this.client.managedItem({ verb: "list", kind: request.itemKind }, () => generation === this.generation) : null;
        const result = request.itemKind ? { candidates: (Array.isArray(rows) ? rows : []).slice(0, 200).map((row) => ({ id: row.id!, title: row.title, subtitle: "" })) } : await this.client.candidates(sender.url, "login");
        if (!await this.current() || generation !== this.generation || !await this.frameCurrent(sender)) return null;
        const nonce = createVaultMeshUuid(); const expires = Date.now() + 30_000;
        this.offers.set(request.captureId, { nonce, expires, tabId: sender.tab.id, frameId: sender.frameId, url: sender.url, ids: new Set(result.candidates.map((entry) => entry.id)), itemKind: request.itemKind });
        return { nonce, expiresAt: new Date(expires).toISOString(), candidates: result.candidates.map(({ id, title, subtitle }) => ({ id, title, subtitle })) };
      }
      const offer = this.offers.get(request.captureId);
      this.offers.delete(request.captureId); // consume before privilege reads or writes; no replay after failure
      if (!offer || offer.nonce !== request.nonce || offer.expires <= Date.now() || offer.tabId !== sender.tab.id
        || offer.frameId !== sender.frameId || offer.url !== sender.url || (request.itemId && !offer.ids.has(request.itemId)) || this.saving) return null;
      this.saving = ownsSave = true;
      this.activeSave = { tabId: sender.tab.id, frameId: sender.frameId };
      if (request.kind === CAPTURE_ITEM_SAVE) {
        if (request.itemKind !== offer.itemKind) return null;
        const detail = request.itemId ? await this.client.managedItem({ verb: "detail", kind: request.itemKind, id: request.itemId }, () => generation === this.generation) : undefined;
        managed = new ManagedDraft(request.itemKind, detail as Record<string, unknown> | undefined);
        if (!request.itemId) managed.data.title = new URL(sender.url).hostname;
        applyCapturedItem(managed, request.values);
        if (!await this.current() || !await this.frameCurrent(sender) || generation !== this.generation || offer.expires <= Date.now()) return null;
        const input = managed.toInput();
        try { await this.client.managedItem({ verb: "save", kind: request.itemKind, input }, () => generation === this.generation && offer.expires > Date.now()); }
        finally { clearLoginSecrets(input); }
        return { saved: true };
      }
      if (offer.itemKind) return null;
      if (request.itemId) {
        const detail = await this.client.loginDetail(request.itemId);
        try { draft = new LoginDraft(detail); } finally { clearLoginSecrets(detail); }
      } else {
        draft = new LoginDraft();
        draft.cipher.name = new URL(sender.url).hostname;
        draft.cipher.login.uris[0].uri = sender.url;
      }
      if (request.username) draft.cipher.login.username = request.username;
      draft.cipher.login.password = request.password;
      if (!await this.current() || !await this.frameCurrent(sender) || generation !== this.generation || offer.expires <= Date.now()) return null;
      const input = draft.toInput();
      try { await this.client.saveLogin(input); }
      finally { clearLoginSecrets(input); }
      return { saved: true };
    } finally {
      managed?.clear(); draft?.clear(); clearCapture(request); clearCapture(message);
      if (ownsSave) { this.saving = false; this.activeSave = undefined; }
    }
  }

  private async frameCurrent(sender: chrome.runtime.MessageSender): Promise<boolean> {
    return new Promise((resolve) => {
      chrome.webNavigation.getFrame({ tabId: sender.tab!.id!, frameId: sender.frameId! }, (frame) => resolve(!chrome.runtime.lastError && frame?.url === sender.url));
    });
  }
}
