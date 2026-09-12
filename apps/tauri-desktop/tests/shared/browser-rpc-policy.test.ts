import { describe, expect, it } from 'vitest';
import { NativeLoginPlanSchema } from '../../src/shared/browser-native-login-plan';
import { NativeItemPlanSchema } from '../../src/shared/browser-native-item-plan';
import { GeneratedValueSchema } from '../../src/shared/browser-generated-value';
import { BrowserRecoveryFileInputSchema, PreparedBrowserRecoveryFileSchema } from '../../src/shared/browser-recovery-file';

import { BROWSER_RPC_VERSION, BrowserRpcOperationSchema, type BrowserRpcRequest } from '../../src/shared/browser-rpc';
import { authorizeBrowserRpc, BROWSER_RPC_POLICIES } from '../../src/shared/browser-rpc-policy';

function request(operation: BrowserRpcRequest['operation'], input: Record<string, unknown> = {}): BrowserRpcRequest {
  return {
    kind: 'vaultmesh.rpc', version: BROWSER_RPC_VERSION,
    requestId: '953370ec-4dc7-4c77-a6e0-f2a4f6e37f03',
    issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 30_000).toISOString(),
    operation, input,
  };
}

describe('browser RPC command authorization', () => {
  it('CT-AUTOFILL-001/CT-BROWSER-003 closes item sources and requires gestures for generated copying', () => {
    expect(NativeItemPlanSchema.safeParse([{ handle: crypto.randomUUID(), source: 'card:number' }]).success).toBe(true);
    for (const source of ['card:pin', 'password', 'identity:secret']) expect(NativeItemPlanSchema.safeParse([{ handle: crypto.randomUUID(), source }]).success).toBe(false);
    expect(authorizeBrowserRpc(request('browser.autofill.execute', { nativeItemPlan: [], mode: 'automatic' }), true)).toMatchObject({ authorized: false, code: 'invalid-request' });
    expect(authorizeBrowserRpc(request('browser.generated.copy'), false).authorized).toBe(false);
    expect(authorizeBrowserRpc(request('browser.generated.copy'), true).authorized).toBe(false);
    expect(authorizeBrowserRpc(request('browser.generated.copy', { userGestureId: crypto.randomUUID() }), true).authorized).toBe(true);
    expect(GeneratedValueSchema.safeParse({ mode: 'password', value: 'synthetic' }).success).toBe(true);
    for (const value of ['', 'a'.repeat(1025), 'a\nb']) expect(GeneratedValueSchema.safeParse({ mode: 'password', value }).success).toBe(false);
  });
  it('CT-RECOVERY-CODES-001 keeps both file phases on the same unlock/gesture/confirmation policy', () => {
    expect(BROWSER_RPC_POLICIES['items.recovery-codes.import-file']).toEqual({ capability: 'system-dialog', requiresUnlock: true, requiresGesture: true, requiresConfirmation: true });
    for (const input of [{}, { phase: 'prepare' }, { phase: 'finish', cleanupId: '33333333-3333-4333-8333-333333333333' }]) {
      expect(BrowserRecoveryFileInputSchema.safeParse(input).success).toBe(true);
    }
    for (const input of [{ phase: 'finish' }, { phase: 'prepare', path: '/synthetic/path' }, { phase: 'delete' }]) {
      expect(BrowserRecoveryFileInputSchema.safeParse(input).success).toBe(false);
    }
    expect(PreparedBrowserRecoveryFileSchema.safeParse({ codes: ['synthetic-code'], fileName: 'synthetic.txt', sourceFileStatus: 'deleted', cleanup: { id: '33333333-3333-4333-8333-333333333333', expiresAt: 10 } }).success).toBe(false);
  });
  it('assigns every operation an explicit capability policy', () => {
    expect(Object.keys(BROWSER_RPC_POLICIES).sort()).toEqual([...BrowserRpcOperationSchema.options].sort());
  });

  it('allows status and unlock history while locked but rejects protected metadata', () => {
    expect(authorizeBrowserRpc(request('vault.status'), false).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('vault.unlock-history'), false).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('items.list'), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
    expect(authorizeBrowserRpc(request('confirmation.request', { operation: 'vault.create', userGestureId: crypto.randomUUID() }), false).authorized).toBe(true);
  });

  it('requires a fresh gesture identifier for mutations and copies', () => {
    expect(authorizeBrowserRpc(request('items.add'), true)).toMatchObject({ authorized: false, code: 'invalid-request' });
    expect(authorizeBrowserRpc(request('items.add', { userGestureId: crypto.randomUUID() }), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('items.copy-password', { userGestureId: crypto.randomUUID() }), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('vault.unlock'), false)).toMatchObject({ authorized: false, code: 'invalid-request' });
    expect(authorizeBrowserRpc(request('vault.unlock', { userGestureId: crypto.randomUUID() }), false).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('pin.unlock', { pin: '123456', userGestureId: crypto.randomUUID() }), false).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('pin.enable', { pin: '123456', failureLimit: 5, userGestureId: crypto.randomUUID() }), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
  });

  it('allows automatic autofill without a synthetic gesture only while unlocked', () => {
    expect(authorizeBrowserRpc(request('browser.autofill.candidates'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.autofill.profile'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.autofill.profile'), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
    expect(authorizeBrowserRpc(request('browser.autofill.execute'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.card.capture-status'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.login.password-changed'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.fill.record'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.fill.history'), true).authorized).toBe(true);
    expect(authorizeBrowserRpc(request('browser.autofill.execute'), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
    expect(authorizeBrowserRpc(request('browser.card.capture-status'), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
    expect(authorizeBrowserRpc(request('browser.login.password-changed'), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
    expect(authorizeBrowserRpc(request('browser.fill.record'), false)).toMatchObject({ authorized: false, code: 'unlock-required' });
    expect(authorizeBrowserRpc(request('browser.fill.request'), true)).toMatchObject({ authorized: false, code: 'invalid-request' });
  });

  it('requires a gesture for a native Login plan without changing legacy automatic fill policy', () => {
    expect(authorizeBrowserRpc(request('browser.autofill.execute', { nativeLoginPlan: [] }), true))
      .toMatchObject({ authorized: false, code: 'invalid-request' });
    expect(authorizeBrowserRpc(request('browser.autofill.execute', { nativeLoginPlan: [], userGestureId: crypto.randomUUID() }), true).authorized).toBe(true);
  });

  it('validates native Login sources without allowing protected values or duplicate handles', () => {
    const entry = { handle: crypto.randomUUID(), source: 'password' };
    expect(NativeLoginPlanSchema.safeParse([entry]).success).toBe(true);
    for (const source of [{ ...entry, source: 'totpCode' }, { ...entry, source: 'totpCode', index: 5 }, { ...entry, source: 'custom', index: 0, name: 'tenant' }]) {
      expect(NativeLoginPlanSchema.safeParse([source]).success).toBe(true);
    }
    for (const input of [[], [entry, entry], [{ ...entry, source: 'totpCode', index: 6 }], [{ ...entry, source: 'custom' }], [{ ...entry, index: 1 }], [{ ...entry, value: 'not-allowed' }]]) {
      expect(NativeLoginPlanSchema.safeParse(input).success).toBe(false);
    }
  });
});
