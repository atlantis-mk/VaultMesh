import { act, createElement } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { DeviceAssistView } from './device-assist-view';
let container: HTMLDivElement;
let root: Root;
const id = 'a'.repeat(32);
const empty = {status: 'ready', busy: false, failed: false, ready: false, candidates: []};
beforeEach(() => { vi.useFakeTimers(); container = document.createElement('div'); root = createRoot(container); });
afterEach(async () => { await act(async () => root.unmount()); vi.clearAllTimers(); vi.useRealTimers(); });
async function mount(send: (message: unknown) => Promise<unknown>) {
  await act(async () => root.render(createElement(DeviceAssistView, {kind:'phone', send, onClose:vi.fn()})));
}
it('CT-DEVICE-ASSIST-002 bounds an unanswered start and cancels a late request', async () => {
  let finish!: (v: unknown) => void;
  const send = vi.fn(async (message: unknown) => (message as {kind:string}).kind.endsWith('start') ? new Promise(r => {finish = r;}) : empty);
  await mount(send);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(container.textContent).toContain('连接超时');
  await act(async () => {finish({status:'ready', id});});
  expect(send).toHaveBeenCalledWith({kind:'vaultmesh.device-assist-action', action:'cancel', id});
  expect(send).not.toHaveBeenCalledWith(expect.objectContaining({action:'poll'}));
});
it.each([undefined, null, {status:'ready', unexpected:true}])('CT-DEVICE-ASSIST-002 reports invalid responses instead of leaving the initial spinner (%s)', async value => {
  await mount(async () => value);
  expect(container.textContent).not.toContain('正在连接');
  expect(container.textContent).toContain('响应无效');
});
it('CT-DEVICE-ASSIST-002 bounds an unanswered poll and ignores late candidates', async () => {
  let finish!: (v: unknown) => void;
  const send = vi.fn(async (message: unknown) => {
    const m = message as {kind:string;action?:string};
    if(m.kind.endsWith('start')) return {status:'ready',id};
    if(m.action==='poll') return new Promise(r => {finish=r;});
    return {status:'cancelled'};
  });
  await mount(send);
  await act(async () => { await vi.advanceTimersByTimeAsync(10_000); });
  expect(container.textContent).toContain('连接超时');
  await act(async () => finish({...empty, candidates:[{id:'c',peer:'p',device:'合成手机',kind:'phone',source:'0123',remainingMs:1000}]}));
  expect(container.textContent).not.toContain('合成手机');
  expect(send).toHaveBeenCalledWith({kind:'vaultmesh.device-assist-action',action:'cancel',id});
});
it('CT-DEVICE-ASSIST-002 shows empty phone status without promising an SMS fallback', async () => {
  await mount(async m => (m as {kind:string}).kind.endsWith('start') ? {status:'ready',id} : empty);
  expect(container.textContent).toContain('暂无可用手机号');
  expect(container.textContent).not.toContain('手动交付验证码');
});
it('CT-DEVICE-ASSIST-002 expires a responsive but empty request after sixty seconds', async () => {
  const send = vi.fn(async m => (m as {kind:string}).kind.endsWith('start') ? {status:'ready',id} : empty);
  await mount(send);
  await act(async () => {await vi.advanceTimersByTimeAsync(60_000);});
  expect(container.textContent).toContain('请求已过期');
  expect(send).toHaveBeenCalledWith({kind:'vaultmesh.device-assist-action',action:'cancel',id});
});
it('CT-DEVICE-ASSIST-002 shows candidates promptly but selects only on click', async () => {
  const send = vi.fn(async (message: unknown) => {
    const m=message as {kind:string;action?:string};
    if(m.kind.endsWith('start'))return {status:'ready',id};
    if(m.action==='select')return {status:'filled'};
    return {...empty, candidates:[{id:'c',peer:'p',device:'合成手机',kind:'phone',source:'0123',remainingMs:1000}]};
  });
  await mount(send);
  expect(container.querySelector('[role="option"]')?.textContent).toContain('尾号 0123');
  expect(container.querySelector('[role="option"]')?.textContent).toContain('合成手机');
  expect(send).not.toHaveBeenCalledWith(expect.objectContaining({action:'select'}));
  await act(async () => container.querySelector<HTMLButtonElement>('button[role="option"]')!.click());
  expect(send).toHaveBeenCalledWith({kind:'vaultmesh.device-assist-action',action:'select',id,candidateId:'c'});
  expect(container.textContent).toContain('已填入当前字段');
});
it('CT-DEVICE-ASSIST-002 cancels a start that arrives after closing the view', async () => {
  let finish!: (v: unknown) => void;
  const send = vi.fn(async (m:unknown) => (m as {kind:string}).kind.endsWith('start') ? new Promise(r=>{finish=r;}) : empty);
  await mount(send);
  await act(async () => container.querySelector<HTMLButtonElement>('button[aria-label="关闭"]')!.click());
  await act(async () => finish({status:'ready',id}));
  expect(send).toHaveBeenCalledWith({kind:'vaultmesh.device-assist-action',action:'cancel',id});
  expect(send).not.toHaveBeenCalledWith(expect.objectContaining({action:'poll'}));
});
