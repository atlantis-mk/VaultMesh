import { z } from "zod";
import { AutofillPreferences } from "./autofill-preferences";
import type { VaultMeshRpcClient } from "./rpc";

type ProxyApi = typeof chrome.webAuthenticationProxy;
type Finish = (details: { requestId: number; responseJson?: string; error?: { name: string; message: string } }) => Promise<void>;

/** Chromium events are the only caller. No popup/content message can submit raw WebAuthn requests. */
export class VaultMeshPasskeyProxy {
  private attached = false;
  private generation = 0;
  private transition?: Promise<void>;
  private request?: { id: number; cancelled: boolean };
  private timer?: ReturnType<typeof setTimeout>;
  private readonly preferences = new AutofillPreferences();
  constructor(private readonly client: Pick<VaultMeshRpcClient, "passkey">, private readonly current: () => Promise<boolean>,
    private readonly proxy: ProxyApi | undefined = chrome.webAuthenticationProxy) {}

  start(): void {
    const proxy = this.proxy;
    if (!proxy) return;
    proxy.onRequestCanceled.addListener((id) => { if (this.request?.id === id) this.request.cancelled = true; });
    proxy.onIsUvpaaRequest.addListener((request) => {
      void this.current().then((ready) => proxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: this.attached && ready }),
        () => proxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: false })).catch((): undefined => undefined);
    });
    proxy.onCreateRequest.addListener((request) => void this.complete("create", request.requestId, request.requestDetailsJson, proxy.completeCreateRequest.bind(proxy)));
    proxy.onGetRequest.addListener((request) => void this.complete("get", request.requestId, request.requestDetailsJson, proxy.completeGetRequest.bind(proxy)));
  }
  async sync(ready: boolean): Promise<void> {
    if (!this.proxy) return;
    if (!ready) { await this.detach(); return; }
    if (this.attached) return;
    if (this.transition) { await this.transition; return; }
    const generation = this.generation;
    this.transition = (async () => {
      try {
        const error = await this.proxy!.attach();
        if (error) return; // Another extension may own the proxy. Never displace it.
        if (generation !== this.generation) { await this.proxy!.detach(); return; }
        this.attached = true; this.schedule();
      } catch { this.attached = false; }
    })();
    try { await this.transition; } finally { this.transition = undefined; }
  }
  async detach(): Promise<void> {
    this.generation++;
    if (this.request) this.request.cancelled = true;
    if (this.timer) clearTimeout(this.timer); this.timer = undefined;
    const wasAttached = this.attached; this.attached = false;
    if (wasAttached) try { await this.proxy?.detach(); } catch { /* Browser unload also detaches. */ }
  }
  private schedule(): void {
    if (this.timer) clearTimeout(this.timer);
    this.timer = setTimeout(async () => {
      this.timer = undefined;
      try { if (!await this.current()) { await this.detach(); return; } }
      catch { await this.detach(); return; }
      if (this.attached) this.schedule();
    }, 3000);
  }
  private async complete(kind: "create" | "get", id: number, json: string, finish: Finish): Promise<void> {
    const reject = () => finish({ requestId: id, error: { name: "NotAllowedError", message: "VaultMesh 未完成请求，请检查插件授权及桌面确认。" } }).catch((): undefined => undefined);
    if (!this.attached || this.request || !z.string().min(2).max(128 * 1024).safeParse(json).success) { await reject(); return; }
    const generation = this.generation;
    const request = this.request = { id, cancelled: false };
    const deadline = Date.now() + 60000;
    let responseJson = "";
    try {
      if (!await this.current() || generation !== this.generation || request.cancelled) return await reject();
      const loginId = kind === "create" ? await defaultPasskeyLogin(json, this.preferences) : undefined;
      if (request.cancelled || generation !== this.generation) return;
      const response = await this.client.passkey(kind, json, loginId);
      responseJson = response.responseJson; response.responseJson = "";
      if (request.cancelled || generation !== this.generation) return;
      if (Date.now() >= deadline) { await reject(); return; }
      if (!await this.current()) { await reject(); await this.detach(); return; }
      if (request.cancelled || generation !== this.generation) return;
      if (Date.now() >= deadline) { await reject(); return; }
      await finish({ requestId: id, responseJson });
    } catch { if (!request.cancelled && generation === this.generation) await reject(); }
    finally { responseJson = json = ""; if (this.request === request) this.request = undefined; }
  }
}

export async function defaultPasskeyLogin(json: string, preferences: Pick<AutofillPreferences, "remembered">): Promise<string | undefined> {
  try {
    const value = JSON.parse(json)?.extensions?.remoteDesktopClientOverride?.origin;
    if (typeof value !== "string") return undefined;
    const url = new URL(value);
    if (!/^https?:$/.test(url.protocol) || url.origin !== value) return undefined;
    return await preferences.remembered(value);
  } catch { return undefined; }
}
