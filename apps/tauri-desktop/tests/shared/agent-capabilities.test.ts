import { describe, expect, it } from 'vitest';

import {
  AGENT_CAPABILITY_REGISTRY,
  agentToolInputSchema,
  assertAgentCapabilityRegistry,
} from '../../src/shared/agent-capabilities';

const permanentlyForbidden = /(get_(?:password|api_key|private_key|cookie|otp|recovery_code)|export_secret|dump_vault|reveal|copy_secret|run_arbitrary_shell|raw_dom|unlock_with_password|read_backup|read_import)/;

describe('CT-AGENT-PROTOCOL-001 Agent capability registry', () => {
  it('is exhaustive, unique, versioned, strict and contains no secret getter', () => {
    expect(() => assertAgentCapabilityRegistry()).not.toThrow();
    expect(AGENT_CAPABILITY_REGISTRY.protocolVersion).toBe(2);
    expect(AGENT_CAPABILITY_REGISTRY.tools).toHaveLength(30);
    const agentOpen = AGENT_CAPABILITY_REGISTRY.tools.find(({ name }) => name === 'vaultmesh_ssh_agent_open');
    expect(agentOpen).toMatchObject({ version: 1, capability: 'ssh-agent', risk: 'R1', confirmation: 'none', requiresAccount: true });
    const agentClose = AGENT_CAPABILITY_REGISTRY.tools.find(({ name }) => name === 'vaultmesh_ssh_agent_close');
    expect(agentClose).toMatchObject({ version: 1, capability: 'ssh-agent', risk: 'R0', requiresAccount: false });
    const legacyExec = AGENT_CAPABILITY_REGISTRY.tools.find(({ name }) => name === 'vaultmesh_ssh_exec');
    expect(legacyExec?.deprecated).toBe(true);
    expect(AGENT_CAPABILITY_REGISTRY.tools.map(({ name }) => name).join('\n')).not.toMatch(permanentlyForbidden);
    expect(AGENT_CAPABILITY_REGISTRY.tools.map(({ name }) => name)).not.toEqual(
      expect.arrayContaining([
        'vaultmesh_session_status',
        'vaultmesh_access_lock',
        'vaultmesh_credential_generate_and_store',
        'vaultmesh_credential_test',
        'vaultmesh_credential_rotate',
        'vaultmesh_credential_revoke',
      ]),
    );
    for (const tool of AGENT_CAPABILITY_REGISTRY.tools) {
      expect(agentToolInputSchema(tool)).toMatchObject({ type: 'object', additionalProperties: false });
    }
  });

  it('keeps account-bound tools on the unified permission policy', () => {
    const accounts = AGENT_CAPABILITY_REGISTRY.tools.find(({ name }) => name === 'vaultmesh_accounts_list');
    const ssh = AGENT_CAPABILITY_REGISTRY.tools.find(({ name }) => name === 'vaultmesh_ssh_exec');
    expect(accounts?.parameters.map(({ name }) => name)).toEqual([
      'cursor',
      'limit',
      'query',
      'kinds',
      'capabilities',
      'environments',
    ]);
    expect(ssh).toMatchObject({ version: 2, requiresAccount: true, risk: 'R1' });
    expect(ssh?.parameters.map(({ name }) => name)).toEqual(['program', 'arguments']);
    expect(
      AGENT_CAPABILITY_REGISTRY.tools
        .filter((tool) => tool.requiresAccount && tool.name !== 'vaultmesh_ssh_agent_open')
        .every((tool) => tool.confirmation === 'permission')
    ).toBe(true);
  });
});
