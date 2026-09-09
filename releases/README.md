# Releases

每个正式或预发布版本从 `_template.md` 创建记录，例如 `v0.1.0.md` 或 `v0.2.0-rc.1.md`。

Release 只保存 AI 判断“实际交付什么、兼容性如何、证据在哪里”所需的事实，并且只能引用 schema-v2 的 Done Work 或已列入 `../changes/archive.json` 的 legacy Work。Release 不回写历史 Work，也不重新定义需求；完整历史规格由同名 Git Tag 冻结。
