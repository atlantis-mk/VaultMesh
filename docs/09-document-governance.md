# AI 文档、Work 与版本治理

本文件是 VaultMesh 文档治理的唯一所有者。系统优化目标是紧凑的当前事实和可执行约束；日常变更历史由 Git 保存。

## 1. 文档职责

- `AGENTS.md`：简短、执行关键的规则和禁止行为。
- `docs/`：当前产品、范围、Requirement、架构、数据、安全、全局测试政策和生成的 Traceability。
- `specs/`：Requirement 和代码合约无法清晰表达的专项当前行为。
- `adr/`：代码无法解释的重大持久化决策和被拒绝方案。
- `changes/<WORK-ID>/change.yaml`：跨任务临时状态或受控边界协调。
- `changes/archive.json`：仅为 legacy 已封存 Work 保留的兼容注册表。
- `releases/vX.Y.Z.md` 和同名 Git Tag：交付版本及发布证据。

Requirement 拥有当前行为，代码拥有完整合约，测试拥有可执行验收，ADR 拥有例外原因，Git 拥有日常历史。不得把这些事实复制进 Work。

## 2. 治理路径

### Direct 是默认路径

对于能在当前任务完成的日常功能、行为和规格更新、明确根因的 Bug、重构、UI、测试、开发工具和可逆且无生产依赖的改进，使用 Direct change。行为变化时同时更新其唯一当前主规格和测试；不创建 Work、审批状态、证据文件或 archive 记录。

### Work 是例外

仅当至少一个条件成立时建立 Work：

- 未完成的上下文、风险或下一步必须跨任务保存。
- 开放的产品或架构决定需要用户显式批准后才能实施。
- 改变安全/信任、秘密、数据所有权、持久化/schema、公共 API/RPC/IPC、兼容/迁移、生产依赖/许可、不可逆行为、平台/范围或发布/回滚边界。
- 严重、反复、安全/数据丢失或根因不明的 Bug 需要长期协调。
- 跨模块、平台或版本的工作无法作为一个完整任务验证。

行为或文档变化本身不构成 Work 理由。重大持久化、特权、公共契约、凭据、插件/MCP 信任、sandbox/授权、平台或不可逆决定还必须有 ADR。不得合并无关工作。

## 3. 新 Work schema

schema-v2 Work 只有一个 `change.yaml`，保存身份、目标、当前状态、路由、受控边界、风险和下一步；不保存正文、任务表、验收散文、命令记录、证据 JSON、profile、specification-delta 或每 Work hash。

```yaml
schema: "2"
id: "CHG-YYYY-NNN-change-name"
title: "Change title"
type: "feature"
status: "Draft"
spec_revision: "0.1.53-active"
target_release: null
goal: "Why this state must survive the current task"
requirements: []
tests: []
adrs: []
context_refs: []
related_changes: []
boundaries: []
risks: []
next: []
```

复杂的长期推理使用 ADR、专项规格或可选设计文档，不把 YAML 扩张为第二份规格。

## 4. 上下文路由

- `requirements`、`adrs`、`context_refs` 和 `related_changes` 是初始读取集。
- `context_refs` 使用仓库根目录相对路径和可选 `#<标题或稳定 ID>` 选择器，不能指向另一个 Work。
- 搜索命中、共享 ID、路径或模块不构成依赖。未声明 Work 只能用于解决具体冲突或受控边界。
- 已知 Work ID 时读取 YAML 及可选 legacy 正文，然后沿声明路由展开一层。未知 ID 时从 `docs/00-spec-index.md` 开始，只搜索文件名/YAML 元数据。
- 已封存与 Done Work 是历史，不是默认上下文。

## 5. 生命周期

新 Work 使用 `Draft → Active → Done`；未实施提案可以进入 `Rejected`。

- `Draft`：调查和提案；受控实现尚未开始。
- `Active`：`pnpm work:start -- <WORK-ID>` 记录明确开始决定并刷新 Traceability。
- `Done`：`pnpm work:finish -- <WORK-ID>` 运行适用检查，仅修改状态、刷新 Traceability 并验证结果。

命令结果留在任务/CI 输出和 Git 历史。新 Work 不创建 `verification.json` 或 archive digest。Done Work 提交后由 Git 保留；后续可在独立、可审查提交中删除不再被引用的小 YAML。

## 6. Legacy 兼容

没有 `schema: "2"` 的 Work 保持创建时的生命周期和字段。既有 Draft、Accepted、Implementing、Verified、Released 和 Rejected 状态继续可读；Verified、Released 和 Rejected legacy Work 仍须有历史 archive 条目，所有既有 archive 目录和摘要永久不可变。

不得迁移或重算 legacy 封存 Work。legacy Active Work 仍按其历史完成和封存契约推进；`pnpm work:finish` 提供兼容路径。

## 7. 生成的 Traceability

`docs/03-functional-requirements.md` 拥有 Requirement 文本和 Test ID。Work YAML 拥有临时 routing。`pnpm docs:trace` 生成 `docs/08-traceability.md` 中的活跃 Work 与已完成证据索引；`pnpm docs:check` 在文件过期时失败。

Traceability 是索引，不是证据存储。功能验收清单与命令结果不属于该文件。

## 8. ID、当前事实与历史

- Work、Requirement、Test、ADR 和 OPEN ID 永不复用或改写原意。
- 当前规格只描述当前接受行为；Git 展示它如何变化。
- 仅在当前兼容要求时，已取代的 Requirement 保留简短替代或移除指针。
- Git commit 和 tag 取代日常变化的叙事过程 archive。
- 在考虑移除 legacy archive 兼容性之前，应启用受保护分支和签名发布 tag。

## 9. 发布最小信息

Release 记录版本、日期、同名 Git Tag、组件/schema/contract build、适用的 Done 或 legacy sealed Work、兼容/迁移、平台证据、已知问题、回滚限制和补偿。它不得重新定义 Requirement。

发布就绪是明确的操作员决定。文档和测试证据仍是可审查指引，但不独自授权或阻止发布。自动化在无法绑定版本、构建必需 artifact、保留不可变字节或发布自洽更新合约时仍必须 fail closed。

## 10. 完成门禁

- `pnpm docs:trace` 第二次运行无 diff，`pnpm docs:check` 验证 schema、routing、ID、命令、生成的 Traceability、Release 和 legacy archive。
- 治理或发布脚本改变时运行 `pnpm scripts:test`。
- `pnpm test`、`pnpm typecheck` 和 `pnpm tauri:build` 按受影响 runtime surface 运行。
- 迁移、安全、公共契约、依赖、平台和发布机制仍为改变该边界的 Work 保持 fail closed。
