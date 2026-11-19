import { useMemo } from 'react';

import { usePlatformAuthentication } from '../hooks/use-platform-authentication';
import { PlatformAuthBridgeFactory } from '../lib/platform-auth-bridge';

export function useDesktopAuthentication(enabled: boolean, onUnlocked: () => Promise<void>) {
  const bridge = useMemo(() => PlatformAuthBridgeFactory.createFor('main-window'), []);
  return usePlatformAuthentication({
    bridge,
    enabled,
    attemptKey: 'desktop',
    onUnlocked,
  });
}
