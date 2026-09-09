# AI Work Packages

Direct change 是默认路径：可在当前任务完成的日常功能、行为与规格更新、明确根因的 Bug、重构、UI、测试和工具改动，不建立 Work。只有跨任务未完成状态、待批准决定或安全/秘密/数据所有权/持久化/公共契约/兼容迁移/生产依赖/平台/发布边界才建立 Work；完整阈值见 `../docs/09-document-governance.md`。

常用 ID：

- 新功能/行为变化：`CHG-2026-002-windows-hello-unlock`
- 实现偏离 Requirement：`BUG-2026-001-final-lock-keeps-email-session`
- 其他变化仍使用稳定 ID，并设置 `type: security|dependency|migration|technical_debt|governance`

使用 `pnpm work:new -- <WORK-ID> --title "..." --type <type> --goal "..."` 创建 schema-v2 Work。它只有一个 `change.yaml`；`pnpm work:start` 显式进入 Active，`pnpm work:finish` 执行适用检查、标记 Done 并刷新 Traceability。日常历史由 Git 保存，不将命令抄录、验收正文或摘要复制进新 Work。

既有 legacy Work 保持原状态机、正文及封存规则；已封存目录与 `changes/archive.json` 的既有摘要永久只读。新 schema-v2 Done Work 不产生 archive hash；Release 可以引用 Done schema-v2 Work 或已封存 legacy Work。

完整规则见 `../docs/09-document-governance.md`。
