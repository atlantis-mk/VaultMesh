import { EMAIL_WATCH } from "./email-otp";
import type { VaultMeshRpcClient } from "./rpc";
import { sendSessionMessage } from "./runtime";

/** No codes, credentials or field values are retained by this bounded watch. */
export class EmailWatch {
  private active?: { tabId: number; url: string; origin: string; frameId: number; frameUrl: string; deadline: number };
  private timer?: ReturnType<typeof setTimeout>;
  private generation = 0;
  private navigationEpoch = 0;
  private transitions: Promise<unknown> = Promise.resolve();
  private setWatch(origin: string, active: boolean, current: () => boolean = () => true): Promise<unknown> {
    const next = this.transitions.catch((): undefined => undefined).then(() => current() ? this.client.emailWatch(origin, active) : undefined);
    this.transitions = next; return next;
  }
  constructor(private readonly client: VaultMeshRpcClient, private readonly authorized: () => Promise<boolean>) {}
  start(): void {
    chrome.runtime.onMessage.addListener((message, sender, respond) => {
      if (message?.kind !== EMAIL_WATCH || Object.keys(message).length !== 1) return false;
      void this.watch(sender).then(respond, () => respond(false)); return true;
    });
    const navigation = (details: { tabId: number; frameId: number }) => {
      this.navigationEpoch++;
      if (details.tabId === this.active?.tabId && (details.frameId === 0 || details.frameId === this.active.frameId)) this.cancel();
    };
    chrome.webNavigation.onCommitted.addListener(navigation); chrome.webNavigation.onHistoryStateUpdated.addListener(navigation); chrome.webNavigation.onReferenceFragmentUpdated.addListener(navigation);
    chrome.tabs.onRemoved.addListener((tabId) => { if (tabId === this.active?.tabId) this.cancel(); });
  }
  cancel(): void {
    const active = this.active; this.active = undefined; this.generation++;
    if (this.timer) clearTimeout(this.timer); this.timer = undefined;
    if (active) void this.setWatch(active.origin, false).catch((): undefined => undefined);
  }
  private async watch(sender: chrome.runtime.MessageSender): Promise<boolean> {
    if (sender.id !== chrome.runtime.id || sender.tab?.id == null || sender.frameId == null || !sender.url) return false;
    const navigationEpoch = this.navigationEpoch;
    const tab = await new Promise<chrome.tabs.Tab | undefined>((resolve) => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => resolve(chrome.runtime.lastError ? undefined : tabs[0])));
    if (!tab?.url || tab.id !== sender.tab.id || !/^https?:\/\//.test(tab.url) || new URL(tab.url).origin !== new URL(sender.url).origin) return false;
    const frame = await new Promise<chrome.webNavigation.GetFrameResultDetails | null>((resolve) => chrome.webNavigation.getFrame({ tabId: tab.id!, frameId: sender.frameId! }, (value) => resolve(chrome.runtime.lastError ? null : value)));
    if (frame?.url !== sender.url || !await this.authorized() || navigationEpoch !== this.navigationEpoch) return false;
    this.cancel(); const generation = this.generation;
    const active = { tabId: tab.id!, url: tab.url, origin: new URL(tab.url).origin, frameId: sender.frameId, frameUrl: sender.url, deadline: Date.now() + 90000 };
    this.active = active;
    await this.setWatch(active.origin, true, () => this.active === active && generation === this.generation);
    if (generation !== this.generation || this.active !== active) return false;
    this.timer = setTimeout(() => void this.poll(active), 3000); return true;
  }
  private async poll(active: NonNullable<typeof this.active>): Promise<void> {
    if (this.active !== active) return;
    try {
      const tab = await new Promise<chrome.tabs.Tab | undefined>((resolve) => chrome.tabs.get(active.tabId, (value) => resolve(chrome.runtime.lastError ? undefined : value)));
      if (Date.now() >= active.deadline || tab?.url !== active.url || !await this.authorized()) { this.cancel(); return; }
      if (this.active !== active) return;
      await this.client.emailPoll();
      if (this.active === active) this.timer = setTimeout(() => void this.poll(active), 3000);
    } catch { if (this.active === active) this.cancel(); }
  }
}

export function startEmailWatchContent(): void {
  let last = 0;
  document.addEventListener("click", (event) => {
    if (!event.isTrusted || document.hidden || Date.now() - last < 500) return;
    const button = event.composedPath().find((node) => node instanceof Element && node.matches('button,input[type="button"],input[type="submit"],[role="button"]')) as HTMLElement | undefined;
    if (!button || button.closest('[hidden],[inert],[aria-hidden="true"]') || button.getAttribute("aria-disabled") === "true"
      || (button instanceof HTMLButtonElement || button instanceof HTMLInputElement) && button.disabled || !button.getClientRects().length) return;
    const label = [button.textContent, button.getAttribute("aria-label"), button instanceof HTMLInputElement ? button.value : ""].join(" ").slice(0, 256);
    if (!/(?:发送|获取|重发|重新发送).{0,8}(?:验证码|校验码)|(?:send|resend|get|request).{0,24}(?:code|otp|verification)/i.test(label)) return;
    last = Date.now(); void sendSessionMessage({ kind: EMAIL_WATCH }).catch((): undefined => undefined);
  }, true);
}
