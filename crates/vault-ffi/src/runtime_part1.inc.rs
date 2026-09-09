use std::{path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use vaultmesh_core::{
    AgentAuditEvent, AgentConnectorDefinition, AgentConnectorDefinitionSummary,
    ApiRequestExecutionPlan, ApiRequestInput, ApiRequestPlanSummary, NewAgentAuditEvent,
    NewAgentConnectorDefinition, SecretItemKind, SshCredentialRecordKind, UnlockEventSource,
    VaultError, VaultSession,
};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    VAULTMESH_ITEM_KIND_LOGIN, VAULTMESH_ITEM_KIND_PAYMENT_CARD, VAULTMESH_ITEM_KIND_SECRET,
    VAULTMESH_ITEM_KIND_SSH_CREDENTIAL, VAULTMESH_PROTECTED_FIELD_LOGIN_TOTP,
    VAULTMESH_STATUS_AUTH_FAILED, VAULTMESH_STATUS_CONFLICT, VAULTMESH_STATUS_CORE_ERROR,
    VAULTMESH_STATUS_INVALID_ARGUMENT, VAULTMESH_STATUS_IO_ERROR, VAULTMESH_STATUS_LOCKED,
    VAULTMESH_STATUS_NOT_FOUND, VAULTMESH_STATUS_REAUTH_REQUIRED,
    VAULTMESH_STATUS_VALUE_UNAVAILABLE, VAULTMESH_STATUS_VAULT_EXISTS, VaultmeshStatus,
    VaultmeshVault,
    browser_ops::{camel_value, execute_core_operation, transaction},
    privileged::protected_value,
    storage::{read_vault, write_vault},
    vault::{map_core_error, vault_fingerprint},
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopRuntimeStatus {
    pub unlocked: bool,
    pub has_vault: bool,
    pub item_count: u32,
}

/// Protected key material for an OpenSSH alias whose binding is owned by the
/// encrypted Vault. This type is Rust-only and is never serialized across the
/// renderer or C ABI boundaries.
pub struct ManagedSshHostKeyMaterial {
    pub key_item_id: Uuid,
    pub public_key: Zeroizing<String>,
    pub private_key: Zeroizing<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DesktopRuntimeError {
    status: VaultmeshStatus,
    message: Option<&'static str>,
}

impl DesktopRuntimeError {
    pub fn status(self) -> VaultmeshStatus {
        self.status
    }

    pub fn public_message(self) -> &'static str {
        if let Some(message) = self.message { return message; }
        match self.status {
            VAULTMESH_STATUS_INVALID_ARGUMENT => "请求参数无效。",
            VAULTMESH_STATUS_LOCKED => "请先解锁保险库。",
            VAULTMESH_STATUS_IO_ERROR => "无法安全读写保险库文件。",
            VAULTMESH_STATUS_AUTH_FAILED => "主密码不正确。",
            VAULTMESH_STATUS_VAULT_EXISTS => "保险库已经存在。",
            VAULTMESH_STATUS_NOT_FOUND => "未找到请求的条目。",
            VAULTMESH_STATUS_REAUTH_REQUIRED => "需要重新验证主密码。",
            VAULTMESH_STATUS_VALUE_UNAVAILABLE => "该受保护字段不可用。",
            VAULTMESH_STATUS_CONFLICT => "保险库已被另一会话更新，请重新解锁后再试。",
            _ => "保险库操作失败。",
        }
    }
}

impl From<VaultmeshStatus> for DesktopRuntimeError {
    fn from(status: VaultmeshStatus) -> Self {
        Self { status, message: None }
    }
}
