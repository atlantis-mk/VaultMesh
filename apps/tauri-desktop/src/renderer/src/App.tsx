import { useEffect } from 'react';
import { RouterProvider } from '@tanstack/react-router';

import { useActivityMonitor } from './hooks/use-activity-monitor';
import { router } from './routes';
import { useVaultStore } from './stores/vault-store';

export function App() {
  const ready = useVaultStore((state) => state.ready);
  const refresh = useVaultStore((state) => state.refresh);
  const handleLocked = useVaultStore((state) => state.handleLocked);
  useActivityMonitor();

  useEffect(() => {
    void refresh();
    const removeLockedListener = window.vaultMesh.vault.onLocked(() => {
      handleLocked();
      void router.navigate({ to: '/unlock', replace: true });
    });
    const removeChangedListener = window.vaultMesh.vault.onChanged(() => { void refresh().then(() => router.invalidate()); });
    const onFocus = (): void => void refresh();
    window.addEventListener('focus', onFocus);
    return () => {
      removeLockedListener();
      removeChangedListener();
      window.removeEventListener('focus', onFocus);
    };
  }, [handleLocked, refresh]);

  if (!ready) {
    return <div className="grid min-h-svh place-items-center text-sm text-muted-foreground">正在打开 VaultMesh…</div>;
  }

  return <RouterProvider router={router} />;
}
