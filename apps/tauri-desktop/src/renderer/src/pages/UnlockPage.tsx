import { useMemo } from 'react';
import { useNavigate } from '@tanstack/react-router';

import { UnlockCard } from '../components/UnlockCard';
import { PlatformAuthBridgeFactory } from '../lib/platform-auth-bridge';
import { UnlockSurfaceUiFactory } from '../lib/unlock-surface-adapter';
import { useVaultStore } from '@/stores/vault-store';

export function UnlockPage() {
  const busy = useVaultStore((state) => state.busy);
  const error = useVaultStore((state) => state.error);
  const status = useVaultStore((state) => state.status);
  const biometric = useVaultStore((state) => state.biometric);
  const pin = useVaultStore((state) => state.pin);
  const unlockVault = useVaultStore((state) => state.unlockVault);
  const refresh = useVaultStore((state) => state.refresh);
  const unlockWithPin = useVaultStore((state) => state.unlockWithPin);
  const clearError = useVaultStore((state) => state.clearError);
  const navigate = useNavigate();

  const surface = useMemo(() => UnlockSurfaceUiFactory.createFor('desktop'), []);
  const bridge = useMemo(() => PlatformAuthBridgeFactory.createFor('main-window'), []);

  const leaveUnlock = (to: '/vault' | '/setup'): void => {
    void bridge.setCompactWindowMode(false).catch(() => {});
    void navigate({ to, replace: to === '/vault' });
  };

  return (
    <section className="mx-auto w-full max-w-[460px]">
      <UnlockCard
        surface={surface}
        bridge={bridge}
        hasVault={Boolean(status?.hasVault)}
        unlockRef="desktop"
        pin={pin}
        biometric={biometric}
        busy={busy}
        error={error}
        onClearError={clearError}
        onNavigateSetup={() => {
          clearError();
          leaveUnlock('/setup');
        }}
        onSubmitPassword={async (password) => {
          if (await unlockVault(password)) {
            leaveUnlock('/vault');
          }
        }}
        onSubmitPin={async (pinValue) => {
          if (await unlockWithPin(pinValue)) {
            leaveUnlock('/vault');
          }
        }}
        onBiometricUnlocked={async () => {
          await refresh();
          if (!useVaultStore.getState().status?.unlocked) {
            throw new Error('Vault refresh failed');
          }
          void bridge.setCompactWindowMode(false).catch(() => {});
          await navigate({ to: '/vault', replace: true });
        }}
      />
    </section>
  );
}
