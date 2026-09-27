import { z } from 'zod';
import { ApprovedFillSchema, type AutofillTarget, type FillRequest } from './protocol';
import { backgroundDesktopRpc, DesktopRpcError } from './desktop-rpc';
import { discoverFrame, applyApprovedFill, getHttpOrigin } from './background-fill';
import { isDeviceAssistField, type AssistKind } from './device-assist-fields';
import { DeviceAssistStateSchema } from './device-assist-schema';

type Owner = { tabId: number; frameId: number; origin: string; pageUrl: string; target?: AutofillTarget; popup: boolean };
type Pending = { owner: Owner; discovery: FillRequest; expires: number; selected: boolean; finishing: boolean; topUrl: string; windowId?: number; kind: AssistKind };
const pending = new Map<string, Pending>();
// Invalidation is scoped: activity in another tab or in an unrelated iframe must
// not discard a request that is still bound to its original document.
let sequence = 0;
let invalidatedAll = 0;
const invalidated = new Map<string, number>();
const tabKey = (tabId: number) => `${tabId}`;
const frameKey = (tabId: number, frameId: number) => `${tabId}:${frameId}`;
// A locked plugin authorization is not a device failure; tell the user to unlock instead.
const failure = (error: unknown) => ({ status: error instanceof DesktopRpcError && error.code === 'unlock-required' ? 'locked' : 'unavailable' });
const isStale = (ticket: number, owner: Owner) => invalidatedAll > ticket
  || (invalidated.get(tabKey(owner.tabId)) ?? 0) > ticket
  || (invalidated.get(frameKey(owner.tabId, owner.frameId)) ?? 0) > ticket;
/** Without a frame (or for the top frame) every request of the tab is cancelled. */
export async function cancelDeviceAssists(tabId?: number, frameId?: number) {
  const mark = ++sequence;
  if (tabId == null) invalidatedAll = mark;
  else invalidated.set(frameId ? frameKey(tabId, frameId) : tabKey(tabId), mark);
  await cancelMatching(tabId, frameId);
}
/**
 * Activating a tab only hides the other tabs of the same window. Requests in
 * other windows remain bound to a still-visible document; polls re-check that
 * the owning tab is active before any value is selected or filled.
 */
export async function deviceAssistTabActivated(tabId: number, windowId: number) {
  const ids = [...pending].filter(([, p]) => p.owner.tabId !== tabId && p.windowId === windowId).map(([id]) => id);
  await Promise.all(ids.map(cancel));
}
async function cancelMatching(tabId?: number, frameId?: number) {
  const ids = [...pending].filter(([,p]) => tabId == null || p.owner.tabId === tabId
    && (!frameId || p.owner.frameId === frameId || p.discovery.frames.some(f => f.frameId === frameId))).map(([id]) => id);
  await Promise.all(ids.map(cancel));
}
async function cancel(id: string) { pending.delete(id); await backgroundDesktopRpc('device.assist.cancel', { id }).catch(() => undefined); }
export async function startDeviceAssist(owner: Owner, kind: AssistKind) {
  const ticket = ++sequence;
  // A newer request supersedes every older request of the same tab.
  invalidated.set(tabKey(owner.tabId), ticket);
  await cancelMatching(owner.tabId);
  if (isStale(ticket, owner)) return { status: 'document-changed' };
  if (getHttpOrigin(owner.origin) !== owner.origin || getHttpOrigin(owner.pageUrl) !== owner.origin) return { status: 'unsupported-page' };
  try {
    const support = await backgroundDesktopRpc('device.assist.capabilities');
    if (!support || (support as {version?: number}).version !== 1) return { status: 'update-required' };
    const top = await browser.tabs.get(owner.tabId);
    if (!top.active || !top.url || new URL(top.url).origin !== owner.origin) return { status: 'document-changed' };
    const requestId = crypto.randomUUID();
    const frameIds = owner.popup
      ? ((await browser.webNavigation.getAllFrames({tabId: owner.tabId})) ?? []).filter(f => { try { return new URL(f.url).origin === owner.origin; } catch { return false; } }).map(f => f.frameId)
      : [owner.frameId];
    const found = await Promise.all(frameIds.map(id => discoverFrame(owner.tabId, id, requestId, false, owner.target)));
    const frames = found.flatMap(frame => frame ? [{ ...frame, fields: frame.fields.filter(f => isDeviceAssistField(f, kind)) }] : []).filter(f => f.fields.length);
    if (frames.length !== 1 || (kind === 'phone' && frames[0].fields.length !== 1) || (frames[0].fields.length > 1 && !frames[0].fields.every(f => f.maxLength === 1))) return { status: 'no-supported-fields' };
    const expires = Date.now() + 60_000;
    const discovery: FillRequest = { version: 1, requestId, issuedAt: new Date().toISOString(), expiresAt: new Date(expires).toISOString(), tabId: owner.tabId, topOrigin: owner.origin, targetOrigin: owner.origin, targetPageUrl: owner.pageUrl, frames };
    const result = z.object({ id: z.string().regex(/^[a-f0-9]{32}$/) }).parse(await backgroundDesktopRpc('device.assist.start', { kind, discovery }));
    if (isStale(ticket, owner)) { await cancel(result.id); return { status: 'document-changed' }; }
    pending.set(result.id, { owner, discovery, expires, selected: false, finishing: false, topUrl: top.url, windowId: top.windowId, kind });
    setTimeout(() => { if (pending.has(result.id)) void cancel(result.id); }, 60_000);
    return { status: 'ready', id: result.id };
  } catch (error) { return failure(error); }
}
export async function deviceAssistAction(id: string, action: 'poll' | 'select' | 'cancel', candidateId: string | undefined, owner: { tabId?: number; frameId?: number; popup: boolean }) {
  const p = pending.get(id);
  if (!p || p.owner.popup !== owner.popup || (!owner.popup && (p.owner.tabId !== owner.tabId || p.owner.frameId !== owner.frameId))) return { status: 'request-expired' };
  if (action === 'cancel') { await cancel(id); return { status: 'cancelled' }; }
  try {
    const tab = await browser.tabs.get(p.owner.tabId);
    if (p.expires <= Date.now() || !tab.active || tab.url !== p.topUrl) { await cancel(id); return { status: 'document-changed' }; }
    if (p.finishing) return { status: 'ready', busy: true, ready: false, failed: false, candidates: [] };
    if (action === 'select') {
      if (p.selected || !candidateId) return { status: 'request-expired' };
      p.selected = true;
      await backgroundDesktopRpc('device.assist.select', { id, candidateId });
    }
    const state = DeviceAssistStateSchema.parse(await backgroundDesktopRpc('device.assist.poll', { id }));
    if (!pending.has(id)) return { status: 'request-expired' };
    if (state.failed) { await cancel(id); return { status: 'unavailable' }; }
    if (state.ready && p.selected) {
      if (p.finishing) return { status: 'ready', ...state };
      p.finishing = true;
      const approval = ApprovedFillSchema.parse(await backgroundDesktopRpc('device.assist.finish', { id }));
      if (!pending.has(id)) return { status: 'request-expired' };
      pending.delete(id);
      const current = await browser.tabs.get(p.owner.tabId);
      if (!current.active || current.url !== p.topUrl) return { status: 'document-changed' };
      return applyApprovedFill(approval, p.owner.tabId, p.owner.origin, undefined, false, p.kind);
    }
    return { status: 'ready', ...state };
  } catch (error) { await cancel(id); return failure(error); }
}
