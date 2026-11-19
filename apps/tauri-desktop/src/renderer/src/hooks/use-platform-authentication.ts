import { useCallback, useEffect, useRef, useState } from 'react';

import type { DesktopAuthenticationEvent } from '../../../shared/api';
import type { PlatformAuthBridgeAdapter } from '../lib/platform-auth-bridge';

export interface UsePlatformAuthenticationOptions {
  bridge: PlatformAuthBridgeAdapter;
  enabled: boolean;
  attemptKey?: string;
  onUnlocked: () => Promise<void>;
}

export function usePlatformAuthentication({
  bridge,
  enabled,
  attemptKey = 'default',
  onUnlocked,
}: UsePlatformAuthenticationOptions) {
  const anchor = useRef<HTMLDivElement>(null);
  const session = useRef<string | null>(null);
  const [version, setVersion] = useState(0);
  const [capability, setCapability] = useState<{ supported: boolean; label: string } | null>(null);
  const [status, setStatus] = useState<DesktopAuthenticationEvent['status']>('paused');
  const [error, setError] = useState<string | null>(null);
  const unlocked = useRef(onUnlocked);
  unlocked.current = onUnlocked;

  const cancel = useCallback(async () => {
    const id = session.current;
    session.current = null;
    if (id) await bridge.cancelAuthentication(id);
    setStatus('paused');
  }, [bridge]);

  useEffect(() => {
    let active = true;
    void bridge.authenticationStatus().then((value) => {
      if (active) setCapability(value);
    }).catch(() => {
      if (active) setError('系统认证暂时不可用，请使用主密码或 PIN。');
    });
    return () => { active = false; };
  }, [bridge]);

  useEffect(() => {
    if (!enabled || !capability?.supported) {
      session.current = null;
      setStatus('paused');
      setError(null);
      return;
    }

    const id = crypto.randomUUID();
    session.current = id;
    let active = true;
    let unlisten: (() => void) | undefined;
    let observer: ResizeObserver | undefined;

    const bounds = () => {
      const rect = anchor.current?.getBoundingClientRect();
      return rect ? { x: rect.x, y: rect.y, width: rect.width, height: rect.height } : null;
    };

    const resume = () => {
      const rect = bounds();
      if (active && session.current === id && rect) {
        void bridge.beginAuthentication(id, rect).catch(() => {
          if (active && session.current === id) {
            setStatus('failed');
            setError('Touch ID 当前不可用，请重试或使用密码。');
          }
        });
      }
    };

    const layout = () => {
      const rect = bounds();
      if (active && session.current === id && rect) {
        void bridge.layoutAuthentication(id, rect).catch(() => {
          if (active && session.current === id) {
            setError('无法更新 Touch ID 位置，请使用主密码或 PIN。');
          }
        });
      }
    };

    setError(null);
    setStatus('paused');
    void (async () => {
      unlisten = await bridge.onAuthentication((event) => {
        if (!active || session.current !== id || event.sessionId !== id) return;
        setStatus(event.status);
        setError(event.status === 'failed' ? event.message ?? 'Touch ID 验证未完成，请重试或使用密码。' : null);
        if (event.status === 'unlocked') {
          setStatus('opening');
          session.current = null;
          void unlocked.current().catch(() => {
            if (active && session.current === null) {
              setStatus('failed');
              setError('保险库摘要加载失败，请重试或使用密码。');
            }
          });
        }
      });
      if (!active || session.current !== id) {
        unlisten();
        return;
      }
      const rect = bounds();
      if (!rect) return;
      await bridge.beginAuthentication(id, rect);
      if (!active || session.current !== id) {
        await bridge.cancelAuthentication(id);
        return;
      }
      observer = new ResizeObserver(layout);
      if (anchor.current) observer.observe(anchor.current);
      observer.observe(document.documentElement);
      window.addEventListener('focus', resume);
      window.addEventListener('resize', layout);
      window.addEventListener('scroll', layout, true);
    })().catch(() => {
      if (active && session.current === id) {
        setStatus('failed');
        setError('Touch ID 当前不可用，请使用主密码或 PIN。');
      }
    });

    return () => {
      active = false;
      observer?.disconnect();
      window.removeEventListener('focus', resume);
      window.removeEventListener('resize', layout);
      window.removeEventListener('scroll', layout, true);
      unlisten?.();
      if (session.current === id) session.current = null;
      void bridge.cancelAuthentication(id).catch(() => {});
    };
  }, [bridge, enabled, capability?.supported, attemptKey, version]);

  return {
    anchor,
    capability,
    status,
    error,
    cancel,
    retry: () => setVersion((value) => value + 1),
  };
}
