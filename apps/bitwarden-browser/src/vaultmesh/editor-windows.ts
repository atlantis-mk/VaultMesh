import { createVaultMeshUuid } from "./uuid";

type Editor = { windowId: number; tabId: number; url: string; loaded?: boolean };

/** Browser-created identities only. No drafts, secrets or grants are stored here. */
export class EditorWindows {
  private editor?: Editor;
  private opening = false;
  constructor(private readonly invalidated: () => void) {}

  start(): void {
    chrome.webNavigation.onCommitted.addListener((detail) => {
      if (detail.tabId !== this.editor?.tabId || detail.frameId !== 0) return;
      if (!this.editor.loaded && detail.url === "about:blank") return;
      if (!this.editor.loaded && detail.url === this.editor.url) this.editor.loaded = true;
      else this.revoke();
    });
    chrome.tabs.onRemoved.addListener((id) => { if (id === this.editor?.tabId) this.revoke(); });
    chrome.tabs.onUpdated.addListener((id, change) => {
      if (id === this.editor?.tabId && change.url && change.url !== this.editor.url) this.revoke();
    });
  }

  allows(sender: chrome.runtime.MessageSender): boolean {
    return !!this.editor && sender.id === chrome.runtime.id && sender.tab?.id === this.editor.tabId
      && sender.tab?.windowId === this.editor.windowId && sender.url === this.editor.url
      && (sender.frameId === undefined || sender.frameId === 0);
  }

  private revoke(): void { this.editor = undefined; this.invalidated(); }

  async focus(sender: chrome.runtime.MessageSender): Promise<void> {
    if (!this.allows(sender)) throw new Error("editor-unavailable");
    await new Promise<void>((resolve, reject) => chrome.windows.update(this.editor!.windowId, { focused: true }, () => {
      if (chrome.runtime.lastError || !this.allows(sender)) reject(new Error("editor-unavailable")); else resolve();
    }));
  }

  async open(): Promise<void> {
    if (this.opening) throw new Error("operation-busy");
    if (this.editor) {
      await new Promise<void>((resolve, reject) => chrome.windows.update(this.editor!.windowId, { focused: true }, () => {
        if (chrome.runtime.lastError) { this.revoke(); reject(new Error("editor-unavailable")); } else resolve();
      }));
      return;
    }
    this.opening = true;
    let created: chrome.windows.Window | undefined;
    try {
      // Register before loading privileged code; creation never transfers a popup draft.
      created = await new Promise<chrome.windows.Window>((resolve, reject) => chrome.windows.create({
        url: "about:blank", type: "popup", width: 560, height: 760, focused: true,
      }, (result) => chrome.runtime.lastError || !result ? reject(new Error("editor-unavailable")) : resolve(result)));
      const tab = created.tabs?.[0];
      if (created.id === undefined || tab?.id === undefined || created.tabs?.length !== 1) throw new Error("editor-unavailable");
      const url = chrome.runtime.getURL(`popup/index.html?editor=${createVaultMeshUuid()}`);
      this.editor = { windowId: created.id, tabId: tab.id, url };
      await new Promise<void>((resolve, reject) => chrome.tabs.update(tab.id!, { url }, () => {
        if (chrome.runtime.lastError) reject(new Error("editor-unavailable")); else resolve();
      }));
    } catch (error) {
      this.revoke();
      if (created?.id !== undefined) chrome.windows.remove(created.id, () => { void chrome.runtime.lastError; });
      throw error;
    } finally { this.opening = false; }
  }
}
