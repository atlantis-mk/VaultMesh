# Vault 数据模型与格式

`crates/vault-core/src/format.rs` 和 `crates/vault-core/src/model.rs` 是实现定位；本文件拥有格式兼容意图。对应 `REQ-VAULT-*`、`REQ-ITEM-*`、`REQ-RECOVERY-001`、`NFR-COMPAT-001`。

## Envelope format 4

```text
VaultEnvelope v4
  header
    format_version = 4
    salt[16]
    kdf = Argon2id(memory_kib=65536, iterations=3, parallelism=1, output=32)
    wrapped_vault_key_nonce[24]
    wrapped_vault_key_ciphertext[48]
  payload_nonce[24]
  payload_ciphertext[n + 16]
```

Format 4 是当前唯一写入 Vault envelope。它可以持久化 `agent_connector_definitions` 与 Agent audit，且 version 4
进入 wrapping-key 与 payload 两层 AAD。常规 Reader 只接受 format 4；format 3 仅由受控主密码迁移入口验证。

随机 32-byte `vault_key` 使用 XChaCha20-Poly1305 加密 payload。主密码经 Argon2id 派生独立 wrapping key，并使用独立 nonce 包装 `vault_key`。Format version、salt 和固定 KDF 参数是两次加密的 AAD。解析必须在运行 Argon2 前拒绝非受支持格式、非固定 KDF 参数或非法固定长度。

更换主密码为同一 `vault_key` 生成新 salt、wrapping nonce/key。Header 是 payload AAD，因此 payload 在同一原子提交中重新加密。Backup 是完整加密 envelope，不是 plaintext export。

## Payload 所有权

`VaultPayload` 包含：

- login item、trash、bounded revision history；
- payment card、card trash/history；
- SSH credential、SSH trash/history；
- identity、identity trash/history；
- developer/service `secrets`；
- default-empty `services`、`service_trash`、bounded `service_history` 与 service aggregation decisions；Service 只保存
  非秘密组织 metadata 和 typed opaque item reference，不保存或复制源 item 的受保护值与 target authority；
- default-empty `api_environments`、`api_environment_trash` 与 bounded `api_environment_history`；Environment 保存
  Service ID、canonical origin/base path、可选 openapiUrl、typed auth/Header binding、opaque credential reference、
  revision 与 policy digest，不保存 credential value、派生 snapshot 或独立 Agent enable 状态；
- default-empty `agent_connector_definitions`，只保存 managed-web recipe 与 SSH tunnel 无法从 exact Vault item
  推导的内部 adapter 约束；不保存账号、client permission 或 Agent 可见 definition ID；
- bounded `agent_audit_events`（最多 500 条），只包含安全的 client/account/tool/target class/risk/decision/
  result/count metadata，不包含参数、正文、header、credential、command/output 或本地路径；
- bounded unlock 和 browser-fill audit metadata。

新增 collection/field 必须评估旧 writer 丢字段风险并明确是否提升 format；不得因为 serde default 就绕过
格式所有权。缺失 `password_changed_at` 表示 unknown，不是 old。Renderer DTO 不是 on-disk schema。

由 `vaultmesh_ssh_host_setup` 生成的专属密钥仍是普通、用户可见的 SSH key item。该 item 的可选
`managed_ssh_host` 字段在 ciphertext 内保存 account ID、alias、host、port、username 与 Host Key 指纹，作为
OpenSSH alias 绑定的唯一所有者；renderer-safe summary/detail 只可以投影 `managedSshAlias`，不得投影 account
ID、host、port、username 或 Host Key，本地不得另存
`manifest.json`。公私钥仍使用 SSH item 的既有 protected 字段，桌面 runtime 只能在有界特权流程中读取并物化
到 owner-only OpenSSH 文件。

format 4 必须保留 managed SSH ownership；同步仅复制 SSH 凭据的可移植字段，本机部署绑定不得传输。

内部 ConnectorDefinition 的 credential reference、生产 target 和 adapter policy 是 encrypted payload；Agent/MCP
metadata 只从对应 Vault item 派生 opaque account ID、用户标签、kind、capability 与 environment，不暴露 definition
存在性、来源或 ID。Client pairing proof 使用
OS-protected storage；active task lease、confirmation、session、continuation 和 child resource 只存在于内存。
未配置 Vault item 的 Agent discovery candidate 不持久化，只在 Vault 已解锁时从 Login、SSH account 与
developer/service secret 派生 opaque item ID、kind、label 和类型化 tool；cursor 与 pending authorization 只存在于
broker 内存，不能包含 username、target、notes 或 secret。
Agent audit、ConnectorDefinition 与 ApiEnvironment 始终写入 format 4；不存在降级或旧 writer 兼容路径。

Service 与 ApiEnvironment collections 必须保留其 exact relationship、revision 与 policy digest。缺失/已删除关系必须由 live validation 拒绝，不能复用旧 target 或权限。format-3 兼容理由见 ADR-0014/0015；当前 format-4 同步与迁移由 ADR-0019 所有。

`sync` 是加密 payload 内的同步状态：Vault 身份、副本 epoch、HLC/已见版本、记录摘要、永久 tombstone、加密冲突历史和本机 peer 授权。它不得出现在非秘密索引或同步 payload 投影中；线上只发送 allowlisted 记录与版本清单。协议与删除语义见 `specs/lan-vault-sync.md`。所有数据入口必须在原子保存前更新版本。

旧 Agent 账号配置、其权限规则与 format-2 compatibility 不属于当前数据模型，也不存在读取或投影路径。
当前设备的 persistent Agent authorization 使用独立本地加密规则库：随机 256-bit key 由
Keychain/Credential Manager 保护，owner-only 文件只保存 AEAD ciphertext，AAD 绑定 Agent protocol epoch、Vault
canonical-path namespace 与当前 OS 用户。规则只包含 client key、opaque account、target digest、capability、typed
predicate、lifetime/effect、policy revision 与时间，不包含 secret、请求/响应正文或 active lease。文件/key 损坏、
缺失或 Vault 移动统一回到 Ask；connection lease 与 pending challenge 只在 broker 内存。Permission challenge 最长
保留到其 connection session 结束；30 秒只是当前工具调用等待时限，不是持久授权或 permission pending 的生命周期。

## 受保护数据

- Login password、TOTP seed、2FA recovery codes 和 protected custom field 保持在 ciphertext 内；
  recovery codes 在安全 summary/detail 中只暴露存在性，值只经逐次主密码验证的特权操作读取。
- Card full number、security code 和 PIN 不进入 list/detail。
- SSH password、private key 和 passphrase 不进入 summary/detail；algorithm/fingerprint 可以展示。
- managed SSH host binding 只有 alias 可以进入 summary/detail，用于信息卡片、只读编辑字段、搜索和 MCP 完成
  结果；account ID、target 与 Host Key 不得进入 renderer DTO。
- Developer/service secret value 只允许 replace 或 privileged copy。
- `access-token` Secret 可以作为 Agent authenticated HTTP/lifecycle account；`website` 固定 canonical HTTP(S)
  origin 与可选 base path。Lifecycle state 为 `active/revoked/needs-review`，其中 revoked/needs-review 不进入 Agent
  discovery 或 secret use；rollback/restore 失败必须原子写 needs-review，不能只存在于内存或日志。
- Identity、deleted item 和 pre-edit revision 与活动 item 使用同一 authenticated payload。
- Service name、说明、标签、地址、关系来源和纠错决定位于 ciphertext；summary/detail 只投影站点数量、item kind count
  与可导航的 typed opaque reference，不投影 username、SSH host 或任何 protected value。
- ApiEnvironment origin/base path、auth、Header 与 credential selector 位于 ciphertext。Desktop detail 可以投影
  ordinary literal 和不可展开 typed reference 供用户编辑，但不得投影 credential value；Agent 只获得 opaque ref、批准的
  label/kind/http capability 与可选 openapiUrl，不能获得其他 Environment 字段。
- Audit 只可包含 coarse time、origin、item kind/ID/title、field count；禁止 field name/value 和 device identifier。

## Passkey 表示

软件 Passkey 复用 kind 为 `authenticator-key` 的 protected `SecretItem`，scope 为 `vaultmesh:passkey:v1`。Protected value 保存 RP ID、credential/user handle、P-256 private JWK、counter 和时间戳。

关联 login 的 credential 增加 `login:<uuid>` scope；创建或导入优先使用经 desktop 按当前 RP/origin
重新验证的默认 Login，缺失时可以唯一用户名匹配。未关联 credential 在 UI 中表示为 Passkey-only
login，不得进入普通 Secret/密钥分类。Summary 只包含安全 RP/account metadata、Passkey 标记和
Login/credential opaque ID；WebAuthn response 不包含 private JWK。

## 迁移规则

- 新建和所有 mutation 仅写 format 4；主密码/KDF/AEAD 保持既有机制。
- format 3 必须由 desktop 主密码验证，再保存 owner-only 原加密备份，最后原子写 format 4；任一步失败保留原文件与旧状态。未知版本、非固定 KDF 或长度在 KDF 前拒绝。
- Browser、Agent 与 quick unlock 只读 format 4，不得隐式升级；主密码升级后可以重新使用同一 Vault Key 的本机 quick-unlock wrapper。
- 恢复备份必须轮换副本 epoch 和 Vault 同步绑定身份、清除授权；恢复的条目版本和 tombstone 保留，重新授权后合并。
- 旧客户端必须拒绝 format 4，不提供降级 writer。回退恢复升级前加密备份，不包含升级后修改。
- 加密或文件提交失败必须保留旧文件和旧 unlocked state。测试必须覆盖旧加密 Fixture、错误密码、恶意输入、备份失败、原子回滚、密码轮换和重启恢复。
