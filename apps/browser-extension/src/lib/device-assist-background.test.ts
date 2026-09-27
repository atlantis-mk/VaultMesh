import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { startDeviceAssist, deviceAssistAction, cancelDeviceAssists, deviceAssistTabActivated } from './device-assist-background';
import { backgroundDesktopRpc, DesktopRpcError } from './desktop-rpc';
import { discoverFrame, applyApprovedFill } from './background-fill';
vi.mock('./desktop-rpc', async importOriginal => ({ ...await importOriginal<typeof import('./desktop-rpc')>(), backgroundDesktopRpc: vi.fn() }));
vi.mock('./background-fill', async importOriginal => ({ ...await importOriginal<typeof import('./background-fill')>(), discoverFrame: vi.fn(), applyApprovedFill: vi.fn() }));
const id = 'a'.repeat(32);
const owner = {tabId: 7, frameId: 0, origin: 'https://example.test', pageUrl: 'https://example.test/login', popup: false};
const caller = {tabId: 7, frameId: 0, popup: false};
const state = {busy: false, ready: false, failed: false, candidates: []};
let frame: Awaited<ReturnType<typeof discoverFrame>>;
beforeEach(() => {
  vi.useFakeTimers();
  vi.spyOn(browser.tabs, 'get').mockImplementation(async () => ({id: 7, active: true, url: owner.pageUrl} as Browser.tabs.Tab));
  frame = {frameId: 0, documentId: crypto.randomUUID(), frameOrigin: owner.origin, fields: [{handle: crypto.randomUUID(), control: 'input', inputType: 'tel', isEmpty: true, autocomplete: ['tel'], label: '', name: '', id: '', placeholder: '', context: 'unknown'}]};
  vi.mocked(discoverFrame).mockResolvedValue(frame);
  vi.mocked(backgroundDesktopRpc).mockImplementation(async op => op === 'device.assist.capabilities' ? {version: 1} : op === 'device.assist.start' ? {id} : state);
});
afterEach(async () => {await cancelDeviceAssists();vi.clearAllTimers();vi.useRealTimers();vi.restoreAllMocks();vi.mocked(backgroundDesktopRpc).mockReset();vi.mocked(discoverFrame).mockReset();vi.mocked(applyApprovedFill).mockReset();});
it.each(['http://localhost:4173', 'http://example.test', 'https://example.test'])('CT-DEVICE-ASSIST-002 permits explicit phone and SMS requests on %s', async origin => {
  const pageUrl = `${origin}/login`;
  vi.mocked(browser.tabs.get).mockImplementation(async () => ({id: 7, active: true, url: pageUrl} as Browser.tabs.Tab));
  frame!.frameOrigin = origin;
  for (const kind of ['phone', 'sms'] as const) {
    frame!.fields[0].autocomplete = [kind === 'phone' ? 'tel' : 'one-time-code'];
    expect(await startDeviceAssist({...owner, origin, pageUrl}, kind)).toEqual({status: 'ready', id});
    expect(backgroundDesktopRpc).toHaveBeenCalledWith('device.assist.start', expect.objectContaining({kind, discovery: expect.objectContaining({topOrigin: origin, targetOrigin: origin, targetPageUrl: pageUrl})}));
    // Merely requesting candidates must never consume or fill a value.
    expect(backgroundDesktopRpc).not.toHaveBeenCalledWith('device.assist.select', expect.anything());
    expect(applyApprovedFill).not.toHaveBeenCalled();
  }
});
it.each(['file:///tmp/form.html', 'data:text/html,form', 'ftp://example.test', 'https://', 'not-a-url'])('CT-DEVICE-ASSIST-002 rejects non-web/malformed targets %s', async origin => {
  expect(await startDeviceAssist({...owner, origin, pageUrl: origin}, 'phone')).toEqual({status: 'unsupported-page'});
  expect(discoverFrame).not.toHaveBeenCalled();
});
it('CT-DEVICE-ASSIST-002 drops start responses after navigation cancellation', async () => {
  let resolve!: (value: unknown) => void;
  vi.mocked(backgroundDesktopRpc).mockImplementation(async op => {
    if(op === 'device.assist.capabilities') return {version: 1};
    if(op === 'device.assist.start') return new Promise(r => {resolve = r;});
    return state;
  });
  const start = startDeviceAssist(owner, 'phone');
  await vi.waitFor(() => expect(resolve).toBeDefined());
  await cancelDeviceAssists(7);resolve({id});
  expect(await start).toEqual({status: 'document-changed'});
  expect(await deviceAssistAction(id, 'poll', undefined, caller)).toEqual({status: 'request-expired'});
  expect(applyApprovedFill).not.toHaveBeenCalled();
});
it('CT-DEVICE-ASSIST-002 rejects replacement page and foreign frame before selection', async () => {
  expect(await startDeviceAssist(owner, 'phone')).toEqual({status: 'ready', id});
  expect(await deviceAssistAction(id, 'select', 'phone', {...caller, frameId: 4})).toEqual({status: 'request-expired'});
  vi.mocked(browser.tabs.get).mockImplementation(async () => ({id: 7, active: true, url: 'https://example.test/replaced'} as Browser.tabs.Tab));
  expect(await deviceAssistAction(id, 'select', 'phone', caller)).toEqual({status: 'document-changed'});
  expect(backgroundDesktopRpc).not.toHaveBeenCalledWith('device.assist.select', expect.anything());
});
it('CT-DEVICE-ASSIST-002 applies concurrent ready polls only once and keeps original binding', async () => {
  await startDeviceAssist(owner, 'phone');
  await deviceAssistAction(id, 'select', 'phone', caller);
  let finish!: (v: unknown) => void;
  vi.mocked(backgroundDesktopRpc).mockImplementation(async op => op === 'device.assist.finish' ? new Promise(r => {finish = r;}) : {...state, ready: true});
  const a = deviceAssistAction(id, 'poll', undefined, caller);
  await vi.waitFor(() => expect(finish).toBeDefined());
  await deviceAssistAction(id, 'poll', undefined, caller);
  finish({kind: 'vaultmesh.approved-fill', requestId: crypto.randomUUID(), tabId: 7, topOrigin: owner.origin, expiresAt: new Date(Date.now()+30000).toISOString(), frames: [{frameId: 0, documentId: frame!.documentId, frameOrigin: owner.origin, assignments: [{handle: frame!.fields[0].handle, value: '+12025550123', overwrite: false}]}]});
  await a;
  expect(applyApprovedFill).toHaveBeenCalledTimes(1);
  expect(vi.mocked(backgroundDesktopRpc).mock.calls.filter(c => c[0] === 'device.assist.finish')).toHaveLength(1);
});
it('CT-DEVICE-ASSIST-002 keeps the newest rapid click when an older cancellation responds late', async () => {
  await startDeviceAssist(owner, 'phone');
  let release!: (value: unknown) => void;
  let delayed = false;
  vi.mocked(backgroundDesktopRpc).mockImplementation(async op => {
    if(op==='device.assist.cancel' && !delayed){delayed=true;return new Promise(resolve=>{release=resolve;});}
    if(op==='device.assist.capabilities')return {version:1};
    if(op==='device.assist.start')return {id};
    return state;
  });
  const older=startDeviceAssist(owner,'phone');
  await vi.waitFor(()=>expect(release).toBeDefined());
  expect(await startDeviceAssist(owner,'phone')).toEqual({status:'ready',id});
  release({status:'cancelled'});
  expect(await older).toEqual({status:'document-changed'});
  expect(await deviceAssistAction(id,'poll',undefined,caller)).toEqual({status:'ready',...state});
});
it('CT-DEVICE-ASSIST-002 ignores navigation in other tabs and unrelated iframes', async () => {
  let resolve!: (value: unknown) => void;
  vi.mocked(backgroundDesktopRpc).mockImplementation(async op => {
    if(op === 'device.assist.capabilities') return {version: 1};
    if(op === 'device.assist.start') return new Promise(r => {resolve = r;});
    return state;
  });
  const start = startDeviceAssist(owner, 'phone');
  await vi.waitFor(() => expect(resolve).toBeDefined());
  await cancelDeviceAssists(8);
  await cancelDeviceAssists(7, 3);
  resolve({id});
  expect(await start).toEqual({status: 'ready', id});
  await cancelDeviceAssists(8, 0);
  await cancelDeviceAssists(7, 3);
  expect(await deviceAssistAction(id, 'poll', undefined, caller)).toEqual({status: 'ready', ...state});
  await cancelDeviceAssists(7, 0);
  expect(await deviceAssistAction(id, 'poll', undefined, caller)).toEqual({status: 'request-expired'});
});
it('CT-DEVICE-ASSIST-002 cancels on navigation of the owning or discovered iframe', async () => {
  const framed = {...owner, frameId: 3};
  frame!.frameId = 3;
  expect(await startDeviceAssist(framed, 'phone')).toEqual({status: 'ready', id});
  await cancelDeviceAssists(7, 3);
  expect(await deviceAssistAction(id, 'poll', undefined, {...caller, frameId: 3})).toEqual({status: 'request-expired'});
  let resolve!: (value: unknown) => void;
  vi.mocked(backgroundDesktopRpc).mockImplementation(async op => {
    if(op === 'device.assist.capabilities') return {version: 1};
    if(op === 'device.assist.start') return new Promise(r => {resolve = r;});
    return state;
  });
  const start = startDeviceAssist(framed, 'phone');
  await vi.waitFor(() => expect(resolve).toBeDefined());
  await cancelDeviceAssists(7, 3);
  resolve({id});
  expect(await start).toEqual({status: 'document-changed'});
});
it('CT-DEVICE-ASSIST-002 keeps requests when a tab in another window is activated', async () => {
  vi.mocked(browser.tabs.get).mockImplementation(async () => ({id: 7, windowId: 1, active: true, url: owner.pageUrl} as Browser.tabs.Tab));
  expect(await startDeviceAssist(owner, 'phone')).toEqual({status: 'ready', id});
  await deviceAssistTabActivated(9, 2);
  await deviceAssistTabActivated(7, 1);
  expect(await deviceAssistAction(id, 'poll', undefined, caller)).toEqual({status: 'ready', ...state});
  await deviceAssistTabActivated(8, 1);
  expect(await deviceAssistAction(id, 'poll', undefined, caller)).toEqual({status: 'request-expired'});
});
it('CT-DEVICE-ASSIST-002 reports a locked plugin session instead of a device failure', async () => {
  expect(await startDeviceAssist(owner, 'phone')).toEqual({status: 'ready', id});
  vi.mocked(backgroundDesktopRpc).mockRejectedValue(new DesktopRpcError('unlock-required', 'locked'));
  expect(await deviceAssistAction(id, 'poll', undefined, caller)).toEqual({status: 'locked'});
  expect(await startDeviceAssist(owner, 'phone')).toEqual({status: 'locked'});
});
