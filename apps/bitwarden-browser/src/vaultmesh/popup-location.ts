import { LocationStrategy, type LocationChangeListener } from "@angular/common";
import { Injectable } from "@angular/core";

/** Popup route history is memory-only. In particular, routing must not change
 * the exact URL used by the background to authorize an independent editor. */
@Injectable()
export class PopupLocationStrategy extends LocationStrategy {
  private entries = ["/"];
  private index = 0;
  private readonly listeners: LocationChangeListener[] = [];
  override path(): string { return this.entries[this.index]; }
  override getBaseHref(): string { return ""; }
  override getState(): unknown { return null; }
  override prepareExternalUrl(internal: string): string { return internal; }
  override onPopState(listener: LocationChangeListener): void { this.listeners.push(listener); }
  override pushState(_state: unknown, _title: string, url: string, query: string): void {
    this.entries = this.entries.slice(0, this.index + 1);
    this.entries.push(url + (query ? `?${query}` : "")); this.index++;
  }
  override replaceState(_state: unknown, _title: string, url: string, query: string): void {
    this.entries[this.index] = url + (query ? `?${query}` : "");
  }
  override back(): void { this.historyGo(-1); }
  override forward(): void { this.historyGo(1); }
  override historyGo(offset = 0): void {
    const index = this.index + offset;
    if (index < 0 || index >= this.entries.length || index === this.index) return;
    this.index = index;
    for (const listener of this.listeners) listener({ type: "popstate", state: null });
  }
}
