import { createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { DeviceAssistView } from './device-assist-view';
import type { AutofillTarget } from './protocol';
import type { AssistKind } from './device-assist-fields';
import { inlineMenuLayout } from './inline-menu-layout';
export function openDeviceAssist(document: Document, target: HTMLElement, bind: () => AutofillTarget | undefined, kind: AssistKind, send: (m:unknown)=>Promise<unknown>, anchor: HTMLElement = target) {
  const host=document.createElement('div');host.dataset.vaultmeshAutofill='';
  host.style.cssText='all:initial;position:fixed;z-index:2147483647;display:block';
  // Same in-frame placement as the inline menu: directly below (or above) the field that was clicked.
  const position=()=>{
    const view=document.defaultView, visual=view?.visualViewport;
    const layout=inlineMenuLayout((anchor.isConnected?anchor:target).getBoundingClientRect(),{width:visual?.width??view?.innerWidth??640,height:visual?.height??view?.innerHeight??640,left:visual?.offsetLeft,top:visual?.offsetTop});
    if(!layout)return;
    host.style.left=`${layout.left}px`;host.style.width=`${layout.width}px`;host.style.setProperty('--vaultmesh-menu-max-height',`${Math.max(layout.maxHeight,160)}px`);
    host.style.top=layout.top===undefined?'auto':`${layout.top}px`;
    host.style.bottom=layout.bottom===undefined?'auto':`${(view?.innerHeight??640)-layout.bottom}px`;
  };
  position();
  const shadow=host.attachShadow({mode:'closed'});const mount=document.createElement('div');shadow.append(mount);document.documentElement.append(host);
  const root=createRoot(mount);let closed=false;
  const close=()=>{if(closed)return;closed=true;root.unmount();host.remove();document.removeEventListener('visibilitychange',visibility);document.removeEventListener('pointerdown',outside,true);document.removeEventListener('keydown',escape,true);target.removeEventListener('input',close);document.defaultView?.removeEventListener('pagehide',close);document.defaultView?.removeEventListener('scroll',position,true);document.defaultView?.removeEventListener('resize',position);observer.disconnect();};
  const visibility=()=>{if(document.hidden)close();};
  const escape=(event:KeyboardEvent)=>{if(event.key!=='Escape'||event.isComposing)return;event.preventDefault();close();target.focus();};
  const outside=(event:Event)=>{if(event.target!==host&&event.target!==target)close();};
  const observer=new MutationObserver(()=>{if(!target.isConnected || !target.getClientRects().length || (target instanceof HTMLInputElement && (target.disabled || target.readOnly || target.type === "password" || target.value)))close();});observer.observe(document,{childList:true,subtree:true,attributes:true,attributeFilter:["style","class","hidden","disabled","readonly","type"]});
  // Every start (including "刷新候选") re-binds the original field; a binding captured
  // when the panel opened expires after a minute.
  const boundSend=(m:unknown)=>{const message=m as Record<string,unknown>;if(message.kind!=='vaultmesh.device-assist-start')return send(message);const binding=bind();return binding?send({...message,target:binding}):Promise.resolve({status:'document-changed'});};
  document.addEventListener('visibilitychange',visibility);document.addEventListener('pointerdown',outside,true);document.addEventListener('keydown',escape,true);target.addEventListener('input',close);document.defaultView?.addEventListener('pagehide',close);document.defaultView?.addEventListener('scroll',position,true);document.defaultView?.addEventListener('resize',position);
  root.render(createElement(DeviceAssistView,{kind,send:boundSend,onClose:close}));
  return close;
}
