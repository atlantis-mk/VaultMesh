import registryJson from './agent-capabilities.json';

export type AgentRiskTier = 'R0' | 'R1' | 'R2' | 'R3' | 'R4';
export type AgentConfirmation = 'none' | 'permission' | 'session' | 'first-target' | 'fresh' | 'privileged' | 'risk-dependent';
export type AgentParameterType = 'string' | 'string-array' | 'integer' | 'object';

export type AgentToolParameter = {
  name: string;
  type: AgentParameterType;
  required: boolean;
  maxLength?: number;
  maxItems?: number;
  maxBytes?: number;
};

export type AgentToolDefinition = {
  name: string;
  version: 1 | 2 | 3;
  capability: string;
  risk: AgentRiskTier;
  requiresAccount: boolean;
  confirmation: AgentConfirmation;
  deprecated?: boolean;
  parameters: readonly AgentToolParameter[];
};

export type AgentCapabilityRegistry = {
  protocolVersion: 2;
  tools: readonly AgentToolDefinition[];
};

export const AGENT_CAPABILITY_REGISTRY = Object.freeze(registryJson as AgentCapabilityRegistry);

export function agentToolInputSchema(tool: AgentToolDefinition): Record<string, unknown> {
  const properties = Object.fromEntries(tool.parameters.map((parameter) => {
    const schema: Record<string, unknown> = parameter.type === 'integer'
      ? { type: 'integer', minimum: 0 }
      : parameter.type === 'object'
        ? { type: 'object' }
        : parameter.type === 'string-array'
          ? { type: 'array', items: { type: 'string', maxLength: parameter.maxLength }, maxItems: parameter.maxItems }
          : { type: 'string', maxLength: parameter.maxLength };
    return [parameter.name, schema];
  }));
  return {
    type: 'object',
    additionalProperties: false,
    properties,
    required: tool.parameters.filter((parameter) => parameter.required).map((parameter) => parameter.name),
  };
}

export function assertAgentCapabilityRegistry(registry = AGENT_CAPABILITY_REGISTRY): void {
  if (registry.protocolVersion !== 2 || registry.tools.length === 0) throw new Error('Agent capability registry version is invalid.');
  const names = new Set<string>();
  for (const tool of registry.tools) {
    if (!/^vaultmesh_[a-z0-9_]+$/.test(tool.name) || names.has(tool.name) || ![1, 2, 3].includes(tool.version)) throw new Error(`Invalid Agent tool: ${tool.name}`);
    names.add(tool.name);
    const parameters = new Set<string>();
    for (const parameter of tool.parameters) {
      if (!/^[a-z][A-Za-z0-9]*$/.test(parameter.name) || parameters.has(parameter.name)) throw new Error(`Invalid Agent parameter: ${tool.name}.${parameter.name}`);
      parameters.add(parameter.name);
    }
  }
}
