import { useEffect, useRef, useState } from 'react';
import { DeviceAssistStateSchema, type DeviceAssistCandidate } from './device-assist-schema';
import type { AssistKind } from './device-assist-fields';

type Send = (message: unknown) => Promise<unknown>;
const RESPONSE_TIMEOUT_MS = 10_000;
const REQUEST_TIMEOUT_MS = 60_000;
const invalidResponse = '设备互通响应无效，请更新并重新加载扩展';
const errors: Record<string, string> = {
  'no-supported-fields': '请在网页里点选一个空的手机号或验证码框，再使用框内的 V 菜单',
  'update-required': '请更新桌面客户端以使用设备互通',
  'unsupported-page': '请在 HTTP 或 HTTPS 网页的手机号或验证码框中使用',
  'document-changed': '网页或目标字段已变化，请重新点选原字段',
  'request-expired': '请求已过期，请重新打开候选',
  unavailable: '设备互通不可用，请检查客户端连接及手机授权',
  locked: 'VaultMesh 插件已锁定，请先解锁插件后重新打开候选',
};
export function DeviceAssistView({kind, send, onClose}: {kind:AssistKind;send:Send;onClose:()=>void}) {
  const [attempt,setAttempt]=useState(0);
  const [candidates,setCandidates]=useState<DeviceAssistCandidate[]>([]);
  const [message,setMessage]=useState('正在检查当前网页…');
  const [selecting,setSelecting]=useState(false);
  const actions=useRef({select: (_id:string)=>{}, close:()=>{}});
  useEffect(()=>{
    let ended=false, request:string|undefined, polling=false, selected=false;
    let pollTimer:ReturnType<typeof setTimeout>|undefined;
    const responseTimers=new Set<ReturnType<typeof setTimeout>>();
    let lifetime:ReturnType<typeof setTimeout>|undefined;
    const cancel=(id:string)=>{void send({kind:'vaultmesh.device-assist-action',action:'cancel',id}).catch(()=>undefined);};
    const stop=(text?:string)=>{
      if(ended)return;
      ended=true;
      clearTimeout(pollTimer);for(const timer of responseTimers)clearTimeout(timer);responseTimers.clear();clearTimeout(lifetime);
      if(request)cancel(request);
      if(text){setMessage(text);setCandidates([]);setSelecting(true);}
    };
    const receive=async(message:unknown)=>{
      const timer=setTimeout(()=>stop('设备互通连接超时，请检查客户端连接后重新打开候选'),RESPONSE_TIMEOUT_MS);
      responseTimers.add(timer);
      try{return await send(message);}finally{clearTimeout(timer);responseTimers.delete(timer);}
    };
    const accept=(value:unknown)=>{
      if(ended)return;
      if(!value||typeof value!=='object'){stop(invalidResponse);return;}
      const {status,...data}=value as Record<string,unknown>;
      if(status==='filled'){stop('已填入当前字段');return;}
      if(status!=='ready'){stop(typeof status==='string' ? errors[status]??'请求已结束，请重新打开候选' : invalidResponse);return;}
      const parsed=DeviceAssistStateSchema.safeParse(data);
      if(!parsed.success){stop(invalidResponse);return;}
      if(parsed.data.failed){stop(errors.unavailable);return;}
      setCandidates(selected ? [] : parsed.data.candidates);
      setMessage(!selected && parsed.data.candidates.length
        ? (kind==='phone'?'选择要填入的手机号':'来源信息仅供辨认，请选择本次验证码')
        : selected?'正在接收并填入当前字段…'
        : kind==='phone'?'暂无可用手机号。请检查手机互通开关、对此电脑的号码授权，以及 SIM 或备用号码。正在继续查找…'
        :'暂无短信验证码。正在等待新短信，也可在手机当前请求中手动输入并发送。');
    };
    const poll=async()=>{
      if(ended||polling||!request)return;
      polling=true;
      try{accept(await receive({kind:'vaultmesh.device-assist-action',action:'poll',id:request}));}
      catch{stop('设备互通连接已断开，请重新打开候选');}
      finally{polling=false;if(!ended)pollTimer=setTimeout(()=>void poll(),1000);}
    };
    actions.current={close:()=>stop(), select:(candidateId)=>{
      if(ended||selected||!request)return;
      selected=true;setSelecting(true);setCandidates([]);setMessage('正在接收并填入当前字段…');
      // Pause polls while selection is in flight; polling never automatically selects a value.
      clearTimeout(pollTimer);
      void (async()=>{
        try{accept(await receive({kind:'vaultmesh.device-assist-action',action:'select',id:request,candidateId}));}
        catch{stop('填充失败，请重新打开候选');}
        if(!ended&&!polling){clearTimeout(pollTimer);pollTimer=setTimeout(()=>void poll(),1000);}
      })();
    }};
    setCandidates([]);setSelecting(false);setMessage('正在检查当前网页…');
    lifetime=setTimeout(()=>stop('请求已过期，请重新打开候选'),REQUEST_TIMEOUT_MS);
    void (async()=>{
      try{
        const value=await receive({kind:'vaultmesh.device-assist-start',assistKind:kind});
        const result=value as {status?:string;id?:string}|null|undefined;
        const id=typeof result?.id==='string'&&/^[a-f0-9]{32}$/.test(result.id)?result.id:undefined;
        if(ended){if(id)cancel(id);return;}
        if(result?.status!=='ready'){accept(value);return;}
        if(!id){stop(invalidResponse);return;}
        request=id;setMessage('正在连接已授权手机…');await poll();
      }catch{stop('设备互通不可用，请检查客户端连接');}
    })();
    return()=>stop();
  },[kind,send,attempt]);
  const title=kind==='phone'?'从手机填入号码':'从手机填入短信验证码';
  // Same visual language as the inline autofill menu: bordered panel, V mark,
  // name/subtitle option rows and quiet text actions.
  return <section className="vm-assist" aria-label="来自手机">
    <style>{DEVICE_ASSIST_CSS}</style>
    <div className="vm-assist-head">
      <span className="vm-assist-mark" aria-hidden="true">V</span>
      <span className="vm-assist-text">
        <span className="vm-assist-name">{title}</span>
        <span className="vm-assist-subtitle" role="status">{message}</span>
      </span>
    </div>
    {candidates.length ? <div className="vm-assist-list" role="listbox" aria-label={title}>
      {candidates.map(c=><button type="button" role="option" className="vm-assist-option" key={c.id} disabled={selecting} onPointerDown={event=>event.preventDefault()} onClick={()=>actions.current.select(c.id)}>
        <span className="vm-assist-mark vm-assist-mark-source" aria-hidden="true">{kind==='phone'?'号':'码'}</span>
        <span className="vm-assist-text">
          <span className="vm-assist-name">{kind==='phone'?`尾号 ${c.source}`:c.source}</span>
          <span className="vm-assist-subtitle">{c.device}{kind==='sms'?`${c.receivedAt ? ` · ${new Date(c.receivedAt).toLocaleTimeString()} 收到` : ''} · ${Math.ceil(c.remainingMs/1000)} 秒内有效`:''}</span>
        </span>
      </button>)}
    </div> : null}
    <div className="vm-assist-actions">
      <button type="button" className="vm-assist-action" onPointerDown={event=>event.preventDefault()} onClick={()=>setAttempt(value=>value+1)}>刷新候选</button>
      <button type="button" className="vm-assist-action" aria-label="关闭" onPointerDown={event=>event.preventDefault()} onClick={()=>{actions.current.close();onClose();}}>关闭</button>
    </div>
  </section>;
}

const DEVICE_ASSIST_CSS = `
  .vm-assist { box-sizing:border-box;width:100%;max-height:var(--vaultmesh-menu-max-height,none);overflow:auto;border:1px solid rgba(127,127,127,.35);border-radius:10px;background:Canvas;color:CanvasText;box-shadow:0 12px 32px rgba(0,0,0,.22);font:13px/1.35 system-ui,sans-serif; }
  .vm-assist * { box-sizing:border-box; }
  .vm-assist-head { display:flex;align-items:center;gap:10px;padding:10px 12px; }
  .vm-assist-mark { flex:none;display:grid;place-items:center;width:22px;height:22px;border-radius:6px;background:#6d5dfc;color:#fff;font-weight:800;font-size:12px; }
  .vm-assist-mark-source { background:color-mix(in srgb, #6d5dfc 14%, transparent);color:#6d5dfc; }
  .vm-assist-text { min-width:0;display:flex;flex-direction:column; }
  .vm-assist-name { font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
  .vm-assist-subtitle { color:GrayText;font-size:12px; }
  .vm-assist-list { padding:4px;border-top:1px solid rgba(127,127,127,.25); }
  .vm-assist-option { width:100%;display:flex;align-items:center;gap:10px;border:0;border-radius:7px;padding:8px;background:transparent;color:inherit;text-align:left;font:inherit;cursor:pointer; }
  .vm-assist-option .vm-assist-subtitle { overflow:hidden;text-overflow:ellipsis;white-space:nowrap; }
  .vm-assist-option:hover,.vm-assist-option:focus-visible { background:color-mix(in srgb, Highlight 14%, transparent);outline:2px solid transparent; }
  .vm-assist-option:disabled { cursor:default;opacity:.55; }
  .vm-assist-actions { display:flex;justify-content:flex-end;gap:4px;padding:4px 6px;border-top:1px solid rgba(127,127,127,.25); }
  .vm-assist-action { border:0;border-radius:6px;padding:5px 9px;background:transparent;color:GrayText;font:inherit;font-size:12px;font-weight:600;cursor:pointer; }
  .vm-assist-action:hover,.vm-assist-action:focus-visible { background:color-mix(in srgb, Highlight 14%, transparent);color:CanvasText;outline:2px solid transparent; }
`;
