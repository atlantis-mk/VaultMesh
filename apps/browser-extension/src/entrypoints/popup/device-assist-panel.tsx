import { useEffect, useState } from 'react';
import { DeviceAssistView } from '@/lib/device-assist-view';
import type { AssistKind } from '@/lib/device-assist-fields';
const send = (message: unknown): Promise<unknown> => browser.runtime.sendMessage(message);
export function DeviceAssistPanel() {
  const [supported,setSupported]=useState<boolean|null>(null);
  useEffect(()=>{let active=true;void send({kind:'vaultmesh.device-assist-capabilities'}).then(v=>{if(active)setSupported((v as {supported?:boolean})?.supported===true);}).catch(()=>{if(active)setSupported(false);});return()=>{active=false;};},[]);
  const [kind,setKind]=useState<AssistKind|null>(null);
  if(supported!==true)return supported===false?<small>设备互通不可用，请检查连接或更新桌面客户端。</small>:null;
  if(kind)return <DeviceAssistView kind={kind} send={send} onClose={()=>setKind(null)}/>;
  return <section aria-label="手机填充" className="flex flex-col gap-2 rounded-lg border p-3">
    <strong>来自已配对手机</strong>
    <div className="flex gap-2">
      <button type="button" className="rounded border px-3 py-2" onClick={()=>setKind('phone')}>填入手机号</button>
      <button type="button" className="rounded border px-3 py-2" onClick={()=>setKind('sms')}>短信验证码</button>
    </div>
  </section>;
}
