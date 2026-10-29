import { useEffect, useState, type ReactNode } from 'react';
import { ArrowRightIcon, BotIcon, KeyRoundIcon, RefreshCwIcon, ShieldCheckIcon } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, FieldGroup, FieldLabel } from '@/components/ui/field';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { DEFAULT_SECURITY_SETTINGS } from '../../../shared/contracts';
import { AGENT_RISK_LABELS, formatAgentPermissionDisplay, formatAgentPermissionTarget, formatAgentToolType } from '../../../shared/agent-permission-display';
import type { SecurityCenterModel } from './security-center-model';
import { ConfirmAction, EmptyState, SecurityFeatureCard, formatDuration } from './security-center-ui';

type AgentManagementSurfaceProps = {
  busy: boolean;
  children: ReactNode;
  page: boolean;
  summary: string;
  onRefresh: () => void;
};

const AGENT_RISK_VARIANTS = {
  R0: 'risk-r0',
  R1: 'risk-r1',
  R2: 'risk-r2',
  R3: 'risk-r3',
  R4: 'risk-r4',
} as const;

function AgentManagementSurface({ busy, children, page, summary, onRefresh }: AgentManagementSurfaceProps) {
  if (!page) {
    return (
      <Card className="h-full">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BotIcon />
            本地 Agent 能力代理
          </CardTitle>
          <CardDescription>MCP 客户端完成一次配对后会保持信任；具体工具调用仍按账号、操作与风险控制。</CardDescription>
        </CardHeader>
        <CardContent className="flex-1">
          <p className="text-sm text-muted-foreground">{summary}</p>
        </CardContent>
        <CardFooter>
          <Button className="w-full" variant="outline" asChild>
            <a href="#/vault/security/agent">
              管理 Agent 授权
              <ArrowRightIcon data-icon="inline-end" />
            </a>
          </Button>
        </CardFooter>
      </Card>
    );
  }

  return (
    <section className="grid gap-4" aria-label="本地 Agent 能力代理管理">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BotIcon />
            Agent 管理概览
          </CardTitle>
          <CardDescription>MCP 使用独立解锁状态；在这里统一管理访问租约、授权规则、客户端和审计记录。</CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">{summary}</p>
        </CardContent>
        <CardFooter>
          <Button variant="outline" type="button" disabled={busy} onClick={onRefresh}>
            <RefreshCwIcon data-icon="inline-start" />
            刷新
          </Button>
        </CardFooter>
      </Card>
      {children}
    </section>
  );
}

export function SecurityCenterProtectionCards({ model, agentPage = false }: { model: SecurityCenterModel; agentPage?: boolean }) {
  const { agentStatus, busy, confirmation, disablePin, pinConfirmation, pinFailureLimit, pinStatus, pinValue, reload, run, savePin, saveSecuritySettings, securityDraft, securitySettings, setAgentStatus, setPinConfirmation, setPinFailureLimit, setPinValue, setSecurityDraft, updateSecurityDraft } = model;
  const pendingAgentActions = agentStatus?.permissionRequests.length ?? 0;
  const [agentPin, setAgentPin] = useState('');
  const [agentPinConfirmation, setAgentPinConfirmation] = useState('');
  const [agentPinFailureLimit, setAgentPinFailureLimit] = useState(5);
  const [agentIdleTimeoutMs, setAgentIdleTimeoutMs] = useState(15 * 60_000);
  const [agentMaxUnlockDurationMs, setAgentMaxUnlockDurationMs] = useState<number | null>(8 * 60 * 60_000);
  const [agentUnlockScope, setAgentUnlockScope] = useState<'connection' | 'client'>('connection');
  useEffect(() => {
    if (!agentStatus) return;
    setAgentIdleTimeoutMs(agentStatus.access.settings.idleTimeoutMs);
    setAgentMaxUnlockDurationMs(agentStatus.access.settings.maxUnlockDurationMs);
    setAgentUnlockScope(agentStatus.access.settings.unlockScope);
  }, [agentStatus]);
  return <>
        <AgentManagementSurface
          page={agentPage}
          busy={busy}
          summary={agentStatus
            ? `${pendingAgentActions} 个待处理动作 · ${agentStatus.access.activeLeaseCount} 条 MCP 解锁租约`
            : '正在读取本地 Agent 状态…'}
          onRefresh={() => void run(reload, 'Agent 状态已刷新。')}
        >
          <Card size="sm">
            <CardHeader>
              <CardTitle>不披露凭据</CardTitle>
              <CardDescription>配对按 integration key 持久保存，但不代表保险库已解锁。每条 MCP 连接都必须在独立窗口完成自己的解锁；桌面端与浏览器扩展的锁定状态不会代替它。</CardDescription>
            </CardHeader>
          </Card>
          {agentStatus ? (
            <Card size="sm">
              <CardHeader>
                <CardTitle>独立 MCP 解锁</CardTitle>
                <CardDescription>
                  当前有 {agentStatus.access.activeLeaseCount} 条有效解锁租约。最后一条租约锁定或断开后，Agent 解密运行时会立即清除。
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form className="grid gap-3" onSubmit={(event) => {
                  event.preventDefault();
                  if (agentPin !== agentPinConfirmation) {
                    toast.error('两次输入的 Agent PIN 不一致。');
                    return;
                  }
                  void run(async () => {
                    await window.vaultMesh.agent.enablePin({ pin: agentPin, failureLimit: agentPinFailureLimit });
                    setAgentStatus(await window.vaultMesh.agent.status());
                    setAgentPin('');
                    setAgentPinConfirmation('');
                  }, agentStatus.pin.enabled ? 'Agent PIN 已更新。' : 'Agent PIN 快速解锁已启用。');
                }}>
                  <FieldGroup className="grid gap-3 sm:grid-cols-3">
                    <Field>
                      <FieldLabel htmlFor="agent-pin">Agent PIN</FieldLabel>
                      <Input id="agent-pin" type="password" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="new-password" value={agentPin} onChange={(event) => setAgentPin(event.target.value)} placeholder="6 位数字" required />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="agent-pin-confirmation">确认 PIN</FieldLabel>
                      <Input id="agent-pin-confirmation" type="password" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} autoComplete="new-password" value={agentPinConfirmation} onChange={(event) => setAgentPinConfirmation(event.target.value)} placeholder="再次输入" required />
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="agent-pin-limit">失败锁定</FieldLabel>
                      <Select value={String(agentPinFailureLimit)} onValueChange={(value) => setAgentPinFailureLimit(Number(value))}>
                        <SelectTrigger id="agent-pin-limit"><SelectValue /></SelectTrigger>
                        <SelectContent><SelectGroup>{[3, 5, 7, 10].map((value) => <SelectItem key={value} value={String(value)}>{value} 次</SelectItem>)}</SelectGroup></SelectContent>
                      </Select>
                    </Field>
                  </FieldGroup>
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" type="submit" disabled={busy}>{agentStatus.pin.enabled ? '更新 Agent PIN' : '启用 Agent PIN'}</Button>
                    {agentStatus.pin.enabled ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void run(async () => {
                      await window.vaultMesh.agent.disablePin();
                      setAgentStatus(await window.vaultMesh.agent.status());
                    }, 'Agent PIN 快速解锁已关闭。')}>关闭 Agent PIN</Button> : null}
                    <Button size="sm" variant="destructive" type="button" disabled={busy || agentStatus.access.activeLeaseCount === 0} onClick={() => void run(async () => {
                      await window.vaultMesh.agent.lockAllAccess();
                      setAgentStatus(await window.vaultMesh.agent.status());
                    }, '所有 MCP 解锁租约和敏感会话均已清除。')}>锁定全部 MCP 连接</Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          ) : null}
          {agentStatus ? (
            <Card size="sm">
              <CardHeader>
                <CardTitle>Agent 自动锁定</CardTitle>
                <CardDescription>{agentUnlockScope === 'client' ? '同一已配对客户端的并行 MCP 连接共享解锁计时。' : '每条 MCP 连接单独计时。'}MCP 活动会刷新空闲时限，但不会延长有限的最长连续解锁时间。</CardDescription>
              </CardHeader>
              <CardContent>
                <form className="grid gap-3" onSubmit={(event) => {
                  event.preventDefault();
                  void run(async () => {
                    await window.vaultMesh.agent.updateAccessSettings({
                      unlockScope: agentUnlockScope,
                      idleTimeoutMs: agentIdleTimeoutMs as 300000 | 900000 | 1800000 | 3600000,
                      maxUnlockDurationMs: agentMaxUnlockDurationMs as 3600000 | 14400000 | 28800000 | null,
                    });
                    setAgentStatus(await window.vaultMesh.agent.status());
                  }, 'Agent 自动锁定策略已更新。');
                }}>
                  <FieldGroup className="grid gap-3 sm:grid-cols-2">
                    <div className="flex items-center justify-between gap-4 rounded-md border p-3 sm:col-span-2">
                      <div className="grid gap-1">
                        <FieldLabel htmlFor="agent-client-shared-unlock">同一客户端只解锁一次</FieldLabel>
                        <p className="text-xs text-muted-foreground">关闭时每条连接分别解锁；开启后同一已配对客户端的并行连接共享一次解锁，最后一条连接断开时锁定。</p>
                      </div>
                      <Switch id="agent-client-shared-unlock" checked={agentUnlockScope === 'client'} onCheckedChange={(checked) => setAgentUnlockScope(checked ? 'client' : 'connection')} />
                    </div>
                    <Field>
                      <FieldLabel htmlFor="agent-idle-timeout">空闲自动锁定</FieldLabel>
                      <Select value={String(agentIdleTimeoutMs)} onValueChange={(value) => setAgentIdleTimeoutMs(Number(value))}>
                        <SelectTrigger id="agent-idle-timeout"><SelectValue /></SelectTrigger>
                        <SelectContent><SelectGroup>
                          <SelectItem value="300000">5 分钟</SelectItem>
                          <SelectItem value="900000">15 分钟（默认）</SelectItem>
                          <SelectItem value="1800000">30 分钟</SelectItem>
                          <SelectItem value="3600000">60 分钟</SelectItem>
                        </SelectGroup></SelectContent>
                      </Select>
                    </Field>
                    <Field>
                      <FieldLabel htmlFor="agent-max-unlock-duration">最长连续解锁</FieldLabel>
                      <Select value={agentMaxUnlockDurationMs === null ? 'shutdown' : String(agentMaxUnlockDurationMs)} onValueChange={(value) => {
                        if (value === 'shutdown') {
                          setAgentMaxUnlockDurationMs(null);
                          return;
                        }
                        const duration = Number(value);
                        if ([3600000, 14400000, 28800000].includes(duration)) {
                          setAgentMaxUnlockDurationMs(duration);
                        }
                      }}>
                        <SelectTrigger id="agent-max-unlock-duration"><SelectValue /></SelectTrigger>
                        <SelectContent><SelectGroup>
                          <SelectItem value="3600000">1 小时</SelectItem>
                          <SelectItem value="14400000">4 小时</SelectItem>
                          <SelectItem value="28800000">8 小时（默认）</SelectItem>
                          <SelectItem value="shutdown">直到关机</SelectItem>
                        </SelectGroup></SelectContent>
                      </Select>
                    </Field>
                  </FieldGroup>
                  <div className="flex flex-wrap items-center gap-3">
                    <Button size="sm" type="submit" disabled={busy}>保存自动锁定策略</Button>
                    <p className="text-xs text-muted-foreground">系统锁屏、睡眠、撤销和退出仍会立即锁定；共享模式在客户端最后一条连接断开时锁定。</p>
                  </div>
                </form>
              </CardContent>
            </Card>
          ) : null}
          {agentStatus?.permissionRequests.map((permission) => {
            const client = agentStatus.clients.find((candidate) => candidate.activities.some((activity) => activity.clientId === permission.clientId));
            const isSshExec = permission.tool === 'vaultmesh_ssh_exec';
            const isWebsiteCapability = permission.tool.startsWith('vaultmesh_http_') || permission.tool.startsWith('vaultmesh_web_');
            const exactActionLabel = isSshExec ? '当前命令' : '当前动作';
            const allActionLabel = isSshExec ? '所有命令' : isWebsiteCapability ? '此网站此能力' : '此连接器此能力';
            const resolve = async (choice: { effect: 'allow' | 'deny'; scope: 'exact' | 'path' | 'safe' | 'all'; duration: 'once' | 'connection' | 'permanent'; pathPattern?: string }, message: string) => run(async () => {
              await window.vaultMesh.agent.resolvePermission(permission.permissionRef, choice);
              setAgentStatus(await window.vaultMesh.agent.status());
            }, message);
            const allowDirect = async (scope: 'exact' | 'path' | 'safe' | 'all', duration: 'once' | 'connection' | 'permanent', message: string, pathPattern?: string) => run(async () => {
              await window.vaultMesh.agent.activateAction(permission.permissionRef, { effect: 'allow', scope, duration, ...(pathPattern ? { pathPattern } : {}) });
              setAgentStatus(await window.vaultMesh.agent.status());
            }, message);
            return (
              <Card size="sm" key={permission.permissionRef}>
                <CardHeader>
                  <CardTitle className="flex items-center justify-between gap-2">
                    <span>{client?.clientKey ?? '未知 MCP 集成'} 请求 {permission.activationRequired ? '授权当前动作' : '权限'}</span>
                    <Badge variant={AGENT_RISK_VARIANTS[permission.risk]}>{AGENT_RISK_LABELS[permission.risk]}</Badge>
                  </CardTitle>
                  <CardDescription>
                    {formatAgentPermissionDisplay(permission)}
                  </CardDescription>
                </CardHeader>
                <CardContent className="grid gap-3 text-xs text-muted-foreground">
                  <p>目标：{formatAgentPermissionTarget(permission)} · 环境：{permission.environment}</p>
                  <p>工具类型：{formatAgentToolType(permission.tool)}</p>
                  <div className="grid gap-1">
                    <p className="font-medium text-foreground">{isSshExec ? '执行的命令' : '执行的动作'}</p>
                    {isSshExec ? <pre className="overflow-x-auto rounded-md border bg-muted p-3 font-mono text-sm text-foreground"><code>{permission.actionDisplay}</code></pre> : <p className="break-all">{permission.actionDisplay}</p>}
                  </div>
                  <p>{permission.activationRequired ? (isSshExec ? 'VaultMesh 会从账号构建目标、Host Key、风险和输出边界；Agent 不会接触中间配置。' : permission.tool === 'vaultmesh_http_request' && permission.sourceItemKind === 'secret' ? 'VaultMesh 由 access-token Secret 固定 HTTPS 目标，Agent 只提交方法、路径和请求数据。' : 'VaultMesh 会从账号构建目标、风险和输出边界。') : '授权仍受系统策略、session 时限、风险等级和原生适配器约束。'}</p>
                </CardContent>
                <CardFooter className="flex flex-wrap gap-2">
                  {permission.activationRequired ? (
                    <>
                      {permission.availableAllowDurations.includes('once') ? <Button size="sm" variant={AGENT_RISK_VARIANTS[permission.risk]} type="button" disabled={busy} onClick={() => void allowDirect('exact', 'once', `已允许${exactActionLabel}执行一次。`)}>{exactActionLabel} · 一次</Button> : null}
                      {permission.availableAllowDurations.includes('connection') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('exact', 'connection', `本次 Agent 连接可执行该精确${isSshExec ? '命令' : '动作'}。`)}>{exactActionLabel} · 本次连接</Button> : null}
                      {permission.availableAllowDurations.includes('permanent') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('exact', 'permanent', `已永久允许该精确${isSshExec ? '命令' : '动作'}；目标或参数变化会重新询问。`)}>{exactActionLabel} · 永久</Button> : null}
                      {permission.availableScopes.includes('path') ? (permission.availablePathPatterns ?? []).flatMap((pattern) => [
                        permission.availableAllowDurations.includes('connection') ? <Button key={`${pattern}-connection`} size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('path', 'connection', `本次 Agent 连接已允许路径 ${pattern}。`, pattern)}>{pattern} · 本次连接</Button> : null,
                        permission.availableAllowDurations.includes('permanent') ? <Button key={`${pattern}-permanent`} size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('path', 'permanent', `已记住同方法路径规则 ${pattern}。`, pattern)}>{pattern} · 永久</Button> : null,
                      ]) : null}
                      {permission.availableScopes.includes('safe') && permission.availableAllowDurations.includes('once') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('safe', 'once', '已允许安全目录中的当前命令执行一次。')}>安全命令 · 一次</Button> : null}
                      {permission.availableScopes.includes('safe') && permission.availableAllowDurations.includes('connection') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('safe', 'connection', '本次 Agent 连接可执行安全目录中的命令。')}>安全命令 · 本次连接</Button> : null}
                      {permission.availableScopes.includes('safe') && permission.availableAllowDurations.includes('permanent') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('safe', 'permanent', '已永久允许当前版本安全目录中的命令。')}>安全命令 · 永久</Button> : null}
                      {permission.availableScopes.includes('all') && permission.availableAllowDurations.includes('once') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('all', 'once', `已允许${allActionLabel}执行一次。`)}>{allActionLabel} · 一次</Button> : null}
                      {permission.availableScopes.includes('all') && permission.availableAllowDurations.includes('connection') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void allowDirect('all', 'connection', `本次 Agent 连接可执行${allActionLabel}；风险等级和硬策略保持不变。`)}>{allActionLabel} · 本次连接</Button> : null}
                      {permission.availableScopes.includes('all') && permission.availableAllowDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void allowDirect('all', 'permanent', `已永久允许${allActionLabel}；风险等级和硬策略保持不变。`)}>{allActionLabel} · 永久</Button> : null}
                    </>
                  ) : (
                    <>
                      {permission.availableAllowDurations.includes('once') ? <Button size="sm" variant={AGENT_RISK_VARIANTS[permission.risk]} type="button" disabled={busy} onClick={() => void resolve({ effect: 'allow', scope: 'exact', duration: 'once' }, '已允许一次；该授权只能消费一次。')}>允许一次</Button> : null}
                      {permission.availableAllowDurations.includes('connection') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void resolve({ effect: 'allow', scope: 'exact', duration: 'connection' }, '已允许到本次 Agent 连接结束。')}>本次连接允许</Button> : null}
                      {permission.availableAllowDurations.includes('permanent') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void resolve({ effect: 'allow', scope: 'exact', duration: 'permanent' }, '已永久允许该精确动作；风险等级和硬策略保持不变。')}>永久允许</Button> : null}
                      {permission.availableScopes.includes('all') && permission.availableAllowDurations.includes('connection') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void resolve({ effect: 'allow', scope: 'all', duration: 'connection' }, `本次 Agent 连接已允许${allActionLabel}；风险等级和硬策略保持不变。`)}>{allActionLabel} · 本次连接</Button> : null}
                      {permission.availableScopes.includes('all') && permission.availableAllowDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'allow', scope: 'all', duration: 'permanent' }, `已永久允许${allActionLabel}；风险等级和硬策略保持不变。`)}>{allActionLabel} · 永久</Button> : null}
                    </>
                  )}
                  {permission.availableDenyDurations.includes('once') ? <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'exact', duration: 'once' }, '已拒绝本次权限申请。')}>拒绝</Button> : null}
                  {permission.activationRequired && permission.availableDenyDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'exact', duration: 'permanent' }, '已永久拒绝该精确动作。')}>{exactActionLabel} · 永久拒绝</Button> : null}
                  {permission.activationRequired && permission.availableScopes.includes('path') && permission.availableDenyDurations.includes('permanent') ? (permission.availablePathPatterns ?? []).map((pattern) => <Button key={`${pattern}-deny`} size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'path', duration: 'permanent', pathPattern: pattern }, `已永久拒绝同方法路径规则 ${pattern}。`)}>{pattern} · 永久拒绝</Button>) : null}
                  {permission.activationRequired && permission.availableScopes.includes('safe') && permission.availableDenyDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'safe', duration: 'permanent' }, '已永久拒绝安全目录中的命令。')}>安全命令 · 永久拒绝</Button> : null}
                  {permission.activationRequired && permission.availableScopes.includes('all') && permission.availableDenyDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'all', duration: 'permanent' }, `已永久拒绝${allActionLabel}。`)}>{allActionLabel} · 永久拒绝</Button> : null}
                  {!permission.activationRequired && permission.availableDenyDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'exact', duration: 'permanent' }, '已永久拒绝该精确动作。')}>永久拒绝</Button> : null}
                  {!permission.activationRequired && permission.availableScopes.includes('all') && permission.availableDenyDurations.includes('permanent') ? <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void resolve({ effect: 'deny', scope: 'all', duration: 'permanent' }, `已永久拒绝${allActionLabel}。`)}>{allActionLabel} · 永久拒绝</Button> : null}
                </CardFooter>
              </Card>
            );
          })}
          {agentStatus ? (
            <Card size="sm">
              <CardHeader>
                <CardTitle>永久权限规则</CardTitle>
                <CardDescription>没有匹配规则时一律询问。规则绑定 MCP 集成、Vault、账号、目标、能力和动作范围。</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-2 text-xs">
                {agentStatus.authorizationRules.map((rule) => (
                  <div className="grid gap-2 rounded-md border p-3" key={rule.id}>
                    <div>
                      <p className="font-medium text-foreground">{rule.effect === 'allow' ? '永久允许' : '永久拒绝'} · {rule.scope === 'exact' ? '当前动作' : rule.scope === 'path' ? '路径规则' : rule.scope === 'safe' ? '安全动作' : '全部结构化动作'}</p>
                      <p className="text-muted-foreground">{rule.tool}{rule.httpMethod && rule.pathPattern ? ` · ${rule.httpMethod} ${rule.pathPattern}` : ''} · {rule.clientKey} · 账号 {rule.accountRef.slice(0, 8)}…</p>
                    </div>
                    <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void run(async () => {
                      await window.vaultMesh.agent.resetAuthorizationRule(rule.id);
                      setAgentStatus(await window.vaultMesh.agent.status());
                    }, '该永久授权规则已删除，后续调用将重新询问。')}>删除规则</Button>
                  </div>
                ))}
                {agentStatus.authorizationRules.length === 0 ? <p className="text-muted-foreground">尚无永久规则；所有账号动作当前默认询问。</p> : null}
              </CardContent>
            </Card>
          ) : null}
          {agentStatus ? (
            <Card size="sm">
              <CardHeader>
                <CardTitle>连接本地 MCP 客户端</CardTitle>
                <CardDescription>
                  为每个 MCP 配置选择稳定且唯一的 client key；它是自报集成 ID，不是密码或软件品牌认证。
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-3 text-xs">
                {agentStatus.shimAvailable ? (
                  <>
                    <div className="grid gap-1">
                      <p className="font-medium text-foreground">通用 stdio 配置</p>
                      <pre className="overflow-x-auto rounded-md bg-muted p-3">{`command = ${JSON.stringify(agentStatus.shimPath)}\nargs = ["--client", "your-stable-client-key"]`}</pre>
                    </div>
                    <div className="grid gap-1">
                      <p className="font-medium text-foreground">OpenCode 示例</p>
                      <pre className="overflow-x-auto rounded-md bg-muted p-3">{JSON.stringify({
                        $schema: 'https://opencode.ai/config.json',
                        mcp: {
                          vaultmesh: {
                            type: 'local',
                            command: [agentStatus.shimPath, '--client', 'my-opencode'],
                            enabled: true,
                            timeout: 30000,
                          },
                        },
                      }, null, 2)}</pre>
                    </div>
                  </>
                ) : (
                  <p className="text-muted-foreground">当前是未包含 Agent shim 的开发运行；请使用正式 packaged app。</p>
                )}
              </CardContent>
            </Card>
          ) : null}
          {agentStatus ? (
            <Card size="sm">
              <CardHeader>
                <CardTitle>加密 Agent 审计 · {agentStatus.auditEvents.length} 条</CardTitle>
                <CardDescription>仅记录账号标签、批准目标、工具、风险、决策和结果分类；不记录凭据、请求/响应正文、命令输出或本地路径。</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-2 text-xs">
                {agentStatus.auditEvents.slice(-20).reverse().map((event) => (
                  <div className="rounded-md border p-3" key={event.eventId}>
                    <p className="font-medium text-foreground">{event.tool} · {event.risk} · {event.resultClass}</p>
                    <p className="text-muted-foreground">{event.accountLabel} / {event.environment} · {event.targetClass}: {event.approvedDisplay}</p>
                    <p className="text-muted-foreground">{new Date(event.occurredAt).toLocaleString()} · {event.clientKind} · {event.decision}</p>
                  </div>
                ))}
                {agentStatus.auditEvents.length === 0 ? <p className="text-muted-foreground">暂无 Agent 审计记录。</p> : null}
              </CardContent>
              {agentStatus.auditEvents.length > 0 ? (
                <CardFooter>
                  <ConfirmAction
                    triggerLabel="清除 Agent 审计"
                    title="清除全部 Agent 审计记录？"
                    description="这只清除 Vault 内的加密 Agent 审计，不影响客户端配对、内部连接定义或权限规则。"
                    disabled={busy}
                    onConfirm={async () => run(async () => {
                      await window.vaultMesh.agent.clearAudit();
                      setAgentStatus(await window.vaultMesh.agent.status());
                    }, 'Agent 审计记录已清除。')}
                  />
                </CardFooter>
              ) : null}
            </Card>
          ) : null}
          {agentStatus?.clients.length ? agentStatus.clients.map((client) => (
            <Card size="sm" key={client.clientId}>
              <CardHeader>
                <CardTitle>{client.clientKey} · {client.pairingState === 'pending' ? '等待配对' : '已配对'}</CardTitle>
                <CardDescription>{client.activities.length} 个活动连接 · {client.activeSessionCount} 个活动 session</CardDescription>
              </CardHeader>
              <CardContent className="grid gap-3 text-xs text-muted-foreground">
                {client.activities.map((activity) => {
                  return (
                    <div className="grid gap-2 rounded-md border p-3" key={activity.clientId}>
                      <p className="font-medium text-foreground">当前连接 · PID {activity.processId}</p>
                      <p>{activity.activeSessionCount > 0 ? '连接 session 活动中' : '等待 session 建立'}</p>
                      <Button size="sm" variant="outline" type="button" disabled={busy} onClick={() => void run(async () => {
                        await window.vaultMesh.agent.lockClientAccess(activity.clientId);
                        setAgentStatus(await window.vaultMesh.agent.status());
                      }, '该 MCP 连接已锁定。')}>立即锁定此连接</Button>
                    </div>
                  );
                })}
                {client.activities.length === 0 ? <p>当前没有活动连接；配对记录会保留，下一次同一客户端连接时无需重新配对。</p> : null}
              </CardContent>
              <CardFooter className="flex flex-wrap gap-2">
                {client.pairingState === 'pending' ? <p className="text-xs text-muted-foreground">请在独立的系统配对窗口中处理该请求。</p> : null}
                <Button size="sm" variant="destructive" type="button" disabled={busy} onClick={() => void run(async () => {
                  await window.vaultMesh.agent.revokeClient(client.clientId);
                  setAgentStatus(await window.vaultMesh.agent.status());
                }, 'MCP 集成配对与当前连接 session 已撤销。')}>撤销 MCP 集成</Button>
              </CardFooter>
            </Card>
          )) : (
            <EmptyState icon={BotIcon} title="没有 MCP 客户端" description="尚未配对本地 MCP 客户端；新的 integration key 会在独立窗口请求确认。" />
          )}
        </AgentManagementSurface>
        {!agentPage ? <>
        <SecurityFeatureCard
          icon={ShieldCheckIcon}
          title="自动锁定与剪贴板"
          description="在离开应用或设备休眠时保护保险库，并自动清除已复制的敏感内容。"
          summary={securitySettings
            ? `失焦${securitySettings.lockOnBlur ? '锁定' : '不锁定'} · 空闲 ${formatDuration(securitySettings.idleTimeoutMs)} · 休眠${securitySettings.lockOnSleep ? '锁定' : '不锁定'} · 剪贴板 ${formatDuration(securitySettings.clipboardClearTimeoutMs)} · SSH 会话 ${securitySettings.sshSessionDurationMinutes ?? 15} 分钟`
            : '正在读取安全策略…'}
          actionLabel="配置安全策略"
          onOpenChange={(open) => {
            if (open) setSecurityDraft(securitySettings);
          }}
          footer={
            <>
              <Button
                variant="outline"
                type="button"
                disabled={busy}
                onClick={() => setSecurityDraft({ ...DEFAULT_SECURITY_SETTINGS })}
              >
                恢复安全默认值
              </Button>
              <Button type="button" disabled={busy || !securityDraft} onClick={() => void saveSecuritySettings()}>
                保存并生效
              </Button>
            </>
          }
        >
          <Card size="sm">
            <CardHeader>
              <CardTitle>失焦锁定</CardTitle>
              <CardDescription>应用窗口失去焦点时立即锁定保险库。</CardDescription>
            </CardHeader>
            <CardContent>
              <Field>
                <FieldLabel htmlFor="lock-on-blur">窗口失焦时</FieldLabel>
                <Select
                  value={String(securityDraft?.lockOnBlur ?? DEFAULT_SECURITY_SETTINGS.lockOnBlur)}
                  onValueChange={(value) => updateSecurityDraft({ lockOnBlur: value === 'true' })}
                >
                  <SelectTrigger id="lock-on-blur"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup><SelectItem value="true">立即锁定（推荐）</SelectItem><SelectItem value="false">保持解锁</SelectItem></SelectGroup></SelectContent>
                </Select>
              </Field>
            </CardContent>
          </Card>
          <Card size="sm">
            <CardHeader>
              <CardTitle>空闲锁定</CardTitle>
              <CardDescription>未检测到键盘、鼠标或输入活动后自动锁定。</CardDescription>
            </CardHeader>
            <CardContent>
              <Field>
                <FieldLabel htmlFor="idle-timeout">空闲时长</FieldLabel>
                <Select
                  value={String(securityDraft?.idleTimeoutMs ?? DEFAULT_SECURITY_SETTINGS.idleTimeoutMs)}
                  onValueChange={(value) => updateSecurityDraft({ idleTimeoutMs: Number(value) })}
                >
                  <SelectTrigger id="idle-timeout"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup>
                    <SelectItem value="60000">1 分钟</SelectItem><SelectItem value="300000">5 分钟（推荐）</SelectItem><SelectItem value="600000">10 分钟</SelectItem><SelectItem value="900000">15 分钟</SelectItem><SelectItem value="1800000">30 分钟</SelectItem>
                  </SelectGroup></SelectContent>
                </Select>
              </Field>
            </CardContent>
          </Card>
          <Card size="sm">
            <CardHeader>
              <CardTitle>休眠锁定</CardTitle>
              <CardDescription>设备进入休眠时立即锁定保险库。</CardDescription>
            </CardHeader>
            <CardContent>
              <Field>
                <FieldLabel htmlFor="lock-on-sleep">设备休眠时</FieldLabel>
                <Select
                  value={String(securityDraft?.lockOnSleep ?? DEFAULT_SECURITY_SETTINGS.lockOnSleep)}
                  onValueChange={(value) => updateSecurityDraft({ lockOnSleep: value === 'true' })}
                >
                  <SelectTrigger id="lock-on-sleep"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup><SelectItem value="true">立即锁定（推荐）</SelectItem><SelectItem value="false">保持解锁</SelectItem></SelectGroup></SelectContent>
                </Select>
              </Field>
            </CardContent>
          </Card>
          <Card size="sm">
            <CardHeader>
              <CardTitle>剪贴板清除</CardTitle>
              <CardDescription>只会清除仍由 VaultMesh 写入、且之后未被替换的内容。</CardDescription>
            </CardHeader>
            <CardContent>
              <Field>
                <FieldLabel htmlFor="clipboard-timeout">保留时长</FieldLabel>
                <Select
                  value={String(securityDraft?.clipboardClearTimeoutMs ?? DEFAULT_SECURITY_SETTINGS.clipboardClearTimeoutMs)}
                  onValueChange={(value) => updateSecurityDraft({ clipboardClearTimeoutMs: Number(value) })}
                >
                  <SelectTrigger id="clipboard-timeout"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup>
                    <SelectItem value="10000">10 秒</SelectItem><SelectItem value="30000">30 秒（推荐）</SelectItem><SelectItem value="60000">1 分钟</SelectItem><SelectItem value="120000">2 分钟</SelectItem>
                  </SelectGroup></SelectContent>
                </Select>
              </Field>
            </CardContent>
          </Card>
          <Card size="sm">
            <CardHeader>
              <CardTitle>SSH 会话与登录</CardTitle>
              <CardDescription>配置外部客户端（终端、VS Code）打开服务器时的短时 SSH-Agent 会话时长及密码自动复制行为。</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Field>
                <FieldLabel htmlFor="ssh-session-duration">临时会话有效期</FieldLabel>
                <Select
                  value={String(securityDraft?.sshSessionDurationMinutes ?? DEFAULT_SECURITY_SETTINGS.sshSessionDurationMinutes)}
                  onValueChange={(value) => updateSecurityDraft({ sshSessionDurationMinutes: Number(value) })}
                >
                  <SelectTrigger id="ssh-session-duration"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectGroup>
                      <SelectItem value="5">5 分钟（高安全）</SelectItem>
                      <SelectItem value="15">15 分钟（默认）</SelectItem>
                      <SelectItem value="30">30 分钟</SelectItem>
                      <SelectItem value="60">60 分钟（上限）</SelectItem>
                    </SelectGroup>
                  </SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel htmlFor="copy-ssh-password-on-launch">打开服务器时</FieldLabel>
                <Select
                  value={String(securityDraft?.copySshPasswordOnLaunch ?? DEFAULT_SECURITY_SETTINGS.copySshPasswordOnLaunch)}
                  onValueChange={(value) => updateSecurityDraft({ copySshPasswordOnLaunch: value === 'true' })}
                >
                  <SelectTrigger id="copy-ssh-password-on-launch"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup><SelectItem value="true">自动复制密码（推荐）</SelectItem><SelectItem value="false">不自动复制</SelectItem></SelectGroup></SelectContent>
                </Select>
              </Field>
            </CardContent>
          </Card>
        </SecurityFeatureCard>

        <SecurityFeatureCard
          icon={KeyRoundIcon}
          title="桌面端 PIN 解锁"
          description="PIN 只用于这台设备的桌面端，与浏览器插件的 PIN 完全独立。"
          summary={pinStatus?.enabled
            ? pinStatus.locked
              ? `已锁定 · 达到 ${pinStatus.failureLimit} 次失败上限`
              : `已启用 · 失败上限 ${pinStatus.failureLimit} 次`
            : '默认关闭；启用并设置后，锁屏页会优先使用 PIN。'}
          actionLabel={pinStatus?.enabled ? '管理桌面端 PIN' : '设置桌面端 PIN'}
          fitDialogToContent
        >
          <form className="flex flex-col gap-4" onSubmit={(event) => void savePin(event)}>
            {pinStatus?.locked ? (
              <Card size="sm">
                <CardHeader>
                  <CardTitle>PIN 已锁定</CardTitle>
                  <CardDescription>下次使用主密码成功解锁桌面端后，会恢复 PIN 尝试次数。</CardDescription>
                </CardHeader>
              </Card>
            ) : null}
            <FieldGroup>
              <Field>
                <FieldLabel htmlFor="desktop-pin">{pinStatus?.enabled ? '新 6 位 PIN' : '6 位 PIN'}</FieldLabel>
                <Input id="desktop-pin" type="password" inputMode="numeric" value={pinValue} minLength={6} maxLength={6} autoComplete="new-password" onChange={(event) => setPinValue(event.target.value.replace(/\D/g, '').slice(0, 6))} />
              </Field>
              <Field data-invalid={pinConfirmation.length > 0 && pinValue !== pinConfirmation}>
                <FieldLabel htmlFor="desktop-pin-confirmation">确认 6 位 PIN</FieldLabel>
                <Input id="desktop-pin-confirmation" type="password" inputMode="numeric" value={pinConfirmation} minLength={6} maxLength={6} autoComplete="new-password" aria-invalid={pinConfirmation.length > 0 && pinValue !== pinConfirmation} onChange={(event) => setPinConfirmation(event.target.value.replace(/\D/g, '').slice(0, 6))} />
              </Field>
              <Field>
                <FieldLabel htmlFor="desktop-pin-limit">连续失败次数上限</FieldLabel>
                <Select value={String(pinFailureLimit)} onValueChange={(value) => setPinFailureLimit(Number(value))}>
                  <SelectTrigger id="desktop-pin-limit"><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup>
                    {[3, 4, 5, 6, 7, 8, 9, 10].map((value) => <SelectItem key={value} value={String(value)}>{value} 次{value === 5 ? '（默认）' : ''}</SelectItem>)}
                  </SelectGroup></SelectContent>
                </Select>
              </Field>
              <div className="flex flex-wrap gap-2">
                <Button type="submit" disabled={busy || pinValue.length !== 6 || pinValue !== pinConfirmation}>
                  {pinStatus?.enabled ? '更新 PIN' : '启用 PIN 解锁'}
                </Button>
                {pinStatus?.enabled ? <Button variant="destructive" type="button" disabled={busy} onClick={() => void disablePin()}>关闭桌面端 PIN</Button> : null}
              </div>
            </FieldGroup>
          </form>
        </SecurityFeatureCard>
        </> : null}
  </>;
}
