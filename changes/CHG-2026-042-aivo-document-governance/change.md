# 将文档治理升级为 Aivo schema-v2 模式

## 问题或目标

VaultMesh 目前要求大多数规格或行为变化建立并封存完整 Work，使日常同任务改动的文档负担过高。将治理迁移至 Aivo 的 Direct-default 模式：只有跨任务状态或受控边界使用轻量 schema-v2 Work，并让 Traceability 从 Requirements 与 Work routing 自动生成。

## 预期行为

新 Work 只含 `change.yaml`，使用 `Draft → Active → Done`；`pnpm work:new`、`work:start`、`work:finish` 和 `docs:trace` 管理生命周期与生成的 Traceability。既有 Work、已封存目录和 `changes/archive.json` 完全保留其原有状态机与摘要校验。

## 非目标

不改变 Vault、浏览器、Agent、桌面运行时或发布 artifact 的产品行为；不修改既有封存 Work。

## 影响范围

文档治理、Work 模板、Traceability、文档检查和相关脚本。仅文档/脚本 surface；无 Vault format、RPC/IPC/ABI、秘密生命周期或依赖影响。

## 实现约束

新治理只改写当前规格与工具。旧 Work 必须继续可读、验证并按其历史规则封存；封存目录和 archive 条目不可变。Traceability 仍以 Requirement/Test 为来源，且必须由生成器校验为最新。

## 任务

| Task | Requirement | 可验证输出 | Test | 状态 |
| --- | --- | --- | --- | --- |
| GOV-042-1 | N/A | schema-v2 治理、模板和生命周期命令 | N/A | Pass |
| GOV-042-2 | N/A | generated Traceability 与兼容验证 | N/A | Pass |

## 验收与证据

- `pnpm docs:trace` 无第二次 diff，`pnpm docs:check` 通过。
- `pnpm scripts:test` 覆盖新增治理脚本的解析、生命周期与旧 archive 兼容路径。
- 完成后按本 Work 创建时的 legacy 规则封存本目录。

证据（2026-09-09）：`pnpm docs:trace && pnpm docs:check && pnpm scripts:test` 通过；`scripts:test` 共 108 项通过。新增 lifecycle tests 同时验证 schema-v2 Done 不创建 archive 与 legacy Work 的 Verified/archive 路径。

## 安全与数据生命周期

无秘密或受保护数据进入新文档、Traceability 或脚本输出。

## 兼容与迁移

新 Work 使用 schema-v2；所有旧 YAML、完成态 archive 条目及其 SHA-256 验证保持原样。现有 legacy Work 仍依历史状态机完成与封存。
