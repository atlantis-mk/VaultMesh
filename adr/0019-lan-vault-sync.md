# ADR-0019：局域网 Vault 同步、format 4 与可备份 Passkey

## 状态

Accepted。用户已明确批准实施本方案。

## 决策

采用仅桌面解锁期间运行的局域网自动双向同步。配对协议升级后，新配对表示双方授权当前 Vault 的适用凭据同步；旧设备信任不得自动提升，须双方补充授权。授权绑定设备证书和双方 Vault 身份，不传播本地授权。服务使用固定证书的 mutual TLS，密码与 Vault Key 不传输，接收数据以本地 Key 加密。

Core 拥有同步投影、HLC 版本、整记录 LWW、历史与永久 tombstone。不同条目 UUID 不自动归并；失败落盘不发布状态、不确认接收。浏览器和 Agent mutation 同样进入版本化事务，但其解锁不授权 LAN 服务。

format 4 在加密 payload 内保存同步版本、墓碑、冲突历史与本地同步授权。format 3 只允许由主密码驱动的受控迁移，先保留原加密备份再原子升级，旧 reader 必须拒绝 format 4。恢复备份轮换副本 epoch 并清除同步授权，重新授权后才能同步。回滚仅恢复旧备份，不保留升级后的修改。

旧 Passkey 的 BE=0 不得改变；新注册可同步 Passkey 从开始使用 BE=1、counter=0，BS 只在副本持久化成功后更新。私钥仍仅在 Rust 内部使用，浏览器只获得既有 public response。

## 后果与拒绝方案

拒绝覆盖整个 Vault、传输主密码或 Vault Key、文件外非原子同步日志、仅按网站/账号去重、以普通 wall clock 作为唯一版本、自动丢弃 tombstone、锁定期间保留同步权限。HLC 提供确定性收敛，不是物理时间真实性证明。撤销不删除已在对端保存的副本。现有密码学与平台发布 Gate 仍适用。

Passkey 依据：[WebAuthn credential backup state](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup)。
