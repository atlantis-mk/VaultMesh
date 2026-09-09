import {
  createHashHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Navigate,
  redirect,
} from '@tanstack/react-router';

import { AppShell } from '@/components/AppShell';
import { CreateVaultPage } from '@/pages/CreateVaultPage';
import { ItemEditorPage } from '@/pages/ItemEditorPage';
import { UnlockPage } from '@/pages/UnlockPage';
import { VaultPage } from '@/pages/VaultPage';
import { SecurityCenterPage } from '@/pages/SecurityCenterPage';
import { PaymentCardEditorPage } from '@/pages/PaymentCardEditorPage';
import { SshCredentialEditorPage } from '@/pages/SshCredentialEditorPage';
import { IdentityEditorPage } from '@/pages/IdentityEditorPage';
import { SecretItemEditorPage } from '@/pages/SecretItemEditorPage';
import { EmailOtpPage } from '@/pages/EmailOtpPage';
import { AgentManagementPage } from '@/pages/AgentManagementPage';
import { ServiceHubPage } from '@/pages/ServiceHubPage';
import { NearbyDevicesPage } from '@/pages/NearbyDevicesPage';
import { useVaultStore } from '@/stores/vault-store';

function RootLayout() {
  return <AppShell />;
}

function redirectHome(): never {
  const { status } = useVaultStore.getState();
  throw redirect({ to: status?.unlocked ? '/vault' : status?.hasVault ? '/unlock' : '/setup', replace: true });
}

function requireUnlocked(): void {
  if (!useVaultStore.getState().status?.unlocked) {
    throw redirect({ to: '/unlock', replace: true });
  }
}

const rootRoute = createRootRoute({ component: RootLayout });

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: redirectHome,
});

const setupRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'setup',
  beforeLoad: () => {
    if (useVaultStore.getState().status?.unlocked) {
      throw redirect({ to: '/vault', replace: true });
    }
  },
  component: CreateVaultPage,
});

const unlockRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'unlock',
  beforeLoad: () => {
    if (useVaultStore.getState().status?.unlocked) {
      throw redirect({ to: '/vault', replace: true });
    }
  },
  component: UnlockPage,
});

const vaultRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault',
  beforeLoad: requireUnlocked,
  component: VaultPage,
});

const serviceHubRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/services',
  beforeLoad: requireUnlocked,
  component: ServiceHubPage,
});

const newItemRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/items/new',
  beforeLoad: requireUnlocked,
  component: () => <ItemEditorPage />,
});

const securityRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/security',
  beforeLoad: requireUnlocked,
  component: SecurityCenterPage,
});

const agentManagementRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/security/agent',
  beforeLoad: requireUnlocked,
  component: AgentManagementPage,
});

const nearbyDevicesRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'nearby',
  beforeLoad: requireUnlocked,
  component: NearbyDevicesRoute,
});

function NearbyDevicesRoute() {
  const unlocked = useVaultStore((state) => state.status?.unlocked);
  // Also unmount immediately when a status refresh observes a lock without an event.
  return unlocked ? <NearbyDevicesPage /> : <Navigate to="/unlock" replace />;
}

const emailOtpRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/email-otp',
  beforeLoad: requireUnlocked,
  component: EmailOtpPage,
});

const editItemRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/items/$itemId',
  beforeLoad: requireUnlocked,
  component: EditItemRoute,
});

const newCardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/cards/new',
  beforeLoad: requireUnlocked,
  component: () => <PaymentCardEditorPage />,
});

const editCardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/cards/$cardId',
  beforeLoad: requireUnlocked,
  component: EditCardRoute,
});

const newSshRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/ssh/new',
  beforeLoad: requireUnlocked,
  component: () => <SshCredentialEditorPage />,
});

const editSshRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: 'vault/ssh/$sshId',
  beforeLoad: requireUnlocked,
  component: EditSshRoute,
});
const newIdentityRoute = createRoute({ getParentRoute: () => rootRoute, path: 'vault/identities/new', beforeLoad: requireUnlocked, component: () => <IdentityEditorPage /> });
const editIdentityRoute = createRoute({ getParentRoute: () => rootRoute, path: 'vault/identities/$identityId', beforeLoad: requireUnlocked, component: EditIdentityRoute });
const newSecretRoute = createRoute({ getParentRoute: () => rootRoute, path: 'vault/secrets/new', beforeLoad: requireUnlocked, component: () => <SecretItemEditorPage /> });
const editSecretRoute = createRoute({ getParentRoute: () => rootRoute, path: 'vault/secrets/$secretId', beforeLoad: requireUnlocked, component: EditSecretRoute });

function EditSshRoute() {
  const { sshId } = editSshRoute.useParams();
  return <SshCredentialEditorPage sshId={sshId} />;
}

function EditCardRoute() {
  const { cardId } = editCardRoute.useParams();
  return <PaymentCardEditorPage cardId={cardId} />;
}
function EditIdentityRoute() { const { identityId } = editIdentityRoute.useParams(); return <IdentityEditorPage identityId={identityId} />; }
function EditSecretRoute() { const { secretId } = editSecretRoute.useParams(); return <SecretItemEditorPage secretId={secretId} />; }

function EditItemRoute() {
  const { itemId } = editItemRoute.useParams();
  return <ItemEditorPage itemId={itemId} />;
}

const routeTree = rootRoute.addChildren([
  indexRoute,
  setupRoute,
  unlockRoute,
  vaultRoute,
  serviceHubRoute,
  securityRoute,
  agentManagementRoute,
  nearbyDevicesRoute,
  emailOtpRoute,
  newItemRoute,
  editItemRoute,
  newCardRoute,
  editCardRoute,
  newSshRoute,
  editSshRoute,
  newIdentityRoute,
  editIdentityRoute,
  newSecretRoute,
  editSecretRoute,
]);

export const router = createRouter({
  routeTree,
  history: createHashHistory(),
});

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router;
  }
}
