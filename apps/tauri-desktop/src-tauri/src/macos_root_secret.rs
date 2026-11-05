//! macOS root secret: data-protection Keychain access group when the process is
//! Team-signed, otherwise a legacy item whose ACL names only the two in-bundle
//! executables.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::ptr;
use std::sync::{Mutex, OnceLock};

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::array::{
    CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex, CFArrayRef,
};
use core_foundation_sys::base::{CFGetTypeID, CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::data::CFDataGetTypeID;
use core_foundation_sys::dictionary::{CFDictionaryGetValue, CFDictionaryRef};
use core_foundation_sys::string::CFStringGetTypeID;
use rand_core::{OsRng, RngCore};
use security_framework::os::macos::access::SecAccess;
use security_framework::passwords::{
    PasswordOptions, generic_password, set_generic_password_options,
};
use security_framework_sys::base::{SecAccessRef, errSecDuplicateItem, errSecItemNotFound};
use security_framework_sys::code_signing::{
    SecCodeCopySelf, SecCodeRef, SecStaticCodeCreateWithPath, SecStaticCodeRef,
};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecMatchLimit,
    kSecMatchLimitAll, kSecReturnAttributes, kSecReturnRef, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching};
use sha2::Digest;
use zeroize::Zeroizing;

use crate::device_credentials::{ROOT_KEYRING_ACCOUNT, ROOT_KEYRING_SERVICE};
use crate::keychain_share::{
    NATIVE_HOST_EXECUTABLE_NAME, SEC_CS_SIGNING_INFORMATION, entitled_access_group,
    in_bundle_executable_paths, is_direct_bundle_executable, partition_ids_for_share,
    partition_plist_hex, partitions_are_exact, select_keychain_access_groups,
};

const ERR_SEC_MISSING_ENTITLEMENT: OSStatus = -34018;
const KEYCHAIN_DESCRIPTOR: &str = "VaultMesh device root";
const ACL_AUTH_ENCRYPT: &str = "ACLAuthorizationEncrypt";
const ACL_AUTH_DECRYPT: &str = "ACLAuthorizationDecrypt";
const ACL_AUTH_DERIVE: &str = "ACLAuthorizationDerive";
const ACL_AUTH_CHANGE: &str = "ACLAuthorizationChangeACL";
const ACL_AUTH_INTEGRITY: &str = "ACLAuthorizationIntegrity";
const ACL_AUTH_PARTITION: &str = "ACLAuthorizationPartitionID";
const ACL_LOCK_FILE_NAME: &str = ".keychain-acl.lock";
const ACL_PLAN_MARKER_FILE_NAME: &str = ".keychain-acl-plan";

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecAttrAccess: CFStringRef;
    static kSecCodeInfoEntitlements: CFStringRef;
    static kSecCodeInfoEntitlementsDict: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;

    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
    fn SecTrustedApplicationCreateFromPath(
        path: *const libc::c_char,
        app: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecAccessCreate(
        descriptor: core_foundation_sys::string::CFStringRef,
        trustedlist: core_foundation_sys::array::CFArrayRef,
        access: *mut SecAccessRef,
    ) -> OSStatus;
    fn SecAccessCopyACLList(access: SecAccessRef, acl_list: *mut CFTypeRef) -> OSStatus;
    fn SecACLCreateWithSimpleContents(
        access: SecAccessRef,
        application_list: CFArrayRef,
        description: core_foundation_sys::string::CFStringRef,
        prompt_selector: u16,
        new_acl: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecACLCopyContents(
        acl: CFTypeRef,
        application_list: *mut CFTypeRef,
        description: *mut core_foundation_sys::string::CFStringRef,
        prompt_selector: *mut u16,
    ) -> OSStatus;
    fn SecACLSetContents(
        acl: CFTypeRef,
        application_list: core_foundation_sys::array::CFArrayRef,
        description: core_foundation_sys::string::CFStringRef,
        prompt_selector: u16,
    ) -> OSStatus;
    fn SecACLCopyAuthorizations(acl: CFTypeRef) -> CFArrayRef;
    fn SecACLUpdateAuthorizations(acl: CFTypeRef, authorizations: CFArrayRef) -> OSStatus;
    fn SecKeychainItemCopyAccess(item: CFTypeRef, access: *mut SecAccessRef) -> OSStatus;
    fn SecTrustedApplicationCopyData(
        app: CFTypeRef,
        data: *mut core_foundation_sys::data::CFDataRef,
    ) -> OSStatus;
}

use core_foundation_sys::string::CFStringRef;

static LEGACY_ACL_RESULT: OnceLock<Mutex<Option<Result<(), String>>>> = OnceLock::new();

enum ProtectedRead {
    Secret(Zeroizing<[u8; 32]>),
    Missing,
    Unavailable,
}

struct SigningFacts {
    team: Option<String>,
    cdhash: Option<String>,
    groups: Vec<String>,
}

pub fn get_or_create_root_secret() -> Result<Zeroizing<[u8; 32]>, String> {
    if let Some(group) = current_access_group() {
        match read_protected(&group) {
            ProtectedRead::Secret(secret) => return Ok(secret),
            ProtectedRead::Missing => {
                if let Some(secret) = try_read_legacy_root() {
                    if write_protected(&group, secret.as_slice()).is_ok() {
                        let _ = delete_legacy_root();
                        return Ok(secret);
                    }
                    return Ok(secret);
                }
                let secret = random_secret();
                if write_protected(&group, secret.as_slice()).is_ok() {
                    return Ok(secret);
                }
            }
            ProtectedRead::Unavailable => {}
        }
    }
    legacy_root_secret()
}

pub fn list_legacy_generic_passwords(service: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let query = dictionary(&[
        (
            static_key(unsafe { kSecClass }),
            static_type(unsafe { kSecClassGenericPassword }),
        ),
        (
            static_key(unsafe { kSecAttrService }),
            CFString::from(service).into_CFType(),
        ),
        (
            static_key(unsafe { kSecMatchLimit }),
            static_type(unsafe { kSecMatchLimitAll }),
        ),
        (
            static_key(unsafe { kSecReturnAttributes }),
            CFBoolean::from(true).into_CFType(),
        ),
    ]);
    let mut result: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == errSecItemNotFound {
        return Ok(Vec::new());
    }
    if status != 0 {
        return Err(format!("无法枚举旧钥匙串条目 ({status})"));
    }
    let owned = unsafe { CFType::wrap_under_create_rule(result) };
    let mut secrets = Vec::new();
    for account in parse_legacy_accounts(&owned)? {
        match generic_password(PasswordOptions::new_generic_password(service, &account)) {
            Ok(secret) => secrets.push((account, secret)),
            Err(error) if error.code() == errSecItemNotFound => {}
            Err(error) => {
                return Err(format!("无法读取旧钥匙串条目 ({})", error.code()));
            }
        }
    }
    Ok(secrets)
}

/// A release `.app` whose binaries cannot produce a complete share plan
/// (unsigned, or main/host signed inconsistently) must not touch the production
/// root item: the plain `keyring` fallback makes macOS ask for access and the
/// user's "Always Allow" then pollutes the ACL with that build's identity.
fn must_refuse_unplanned_bundle(release_build: bool, in_bundle: bool, has_plan: bool) -> bool {
    release_build && in_bundle && !has_plan
}

fn running_inside_app_bundle() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|path| in_bundle_executable_paths(&path).ok())
        .is_some()
}

fn legacy_root_secret() -> Result<Zeroizing<[u8; 32]>, String> {
    let plan = share_plan();
    if must_refuse_unplanned_bundle(
        !cfg!(debug_assertions),
        running_inside_app_bundle(),
        plan.is_some(),
    ) {
        return Err("应用包未签名或签名不完整，拒绝访问生产根钥匙串条目".to_owned());
    }
    if let Some(plan) = plan {
        return legacy_root_secret_with_plan(&plan);
    }
    let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
        .map_err(|error| format!("无法创建钥匙串入口 ({})", error_code(&error)))?;
    match entry.get_secret() {
        Ok(bytes) => return Ok(normalize_secret(&bytes)),
        Err(keyring::Error::NoEntry) => {}
        Err(error) => return Err(format!("无法读取根钥匙串条目 ({})", error_code(&error))),
    }
    let secret = random_secret();
    entry
        .set_secret(secret.as_slice())
        .map_err(|error| format!("无法在钥匙串中保存根密钥 ({})", error_code(&error)))?;
    Ok(secret)
}

fn legacy_root_secret_with_plan(plan: &SharePlan) -> Result<Zeroizing<[u8; 32]>, String> {
    let _lock = LegacyAclLock::acquire()?;
    let item = legacy_item_ref()?;
    let migrated = plan_marker_matches(plan);
    match legacy_acl_action(is_native_host_process(), item.is_some(), migrated) {
        LegacyAclAction::Read => {}
        LegacyAclAction::Migrate => run_legacy_acl_once(|| migrate_legacy_root(plan))?,
        LegacyAclAction::Create => run_legacy_acl_once(|| create_fresh_legacy_root(plan))?,
        LegacyAclAction::RequireDesktopMigrate => {
            return Err("根钥匙串需要由桌面主程序迁移".to_owned());
        }
        LegacyAclAction::RequireDesktopCreate => {
            return Err("根钥匙串条目需要由桌面主程序创建".to_owned());
        }
    }
    read_legacy_root()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LegacyAclAction {
    Read,
    Migrate,
    Create,
    RequireDesktopMigrate,
    RequireDesktopCreate,
}

/// `migrated` means this exact main/host cdhash pair already ran the one-time
/// migration. A system-added default PartitionID ACL always sits next to ours,
/// so structural ACL equality is unreachable and must never gate repairs.
fn legacy_acl_action(
    native_host: bool,
    item_exists: bool,
    migrated: bool,
) -> LegacyAclAction {
    match (native_host, item_exists, migrated) {
        (_, true, true) => LegacyAclAction::Read,
        (false, true, false) => LegacyAclAction::Migrate,
        (false, false, _) => LegacyAclAction::Create,
        (true, true, false) => LegacyAclAction::RequireDesktopMigrate,
        (true, false, _) => LegacyAclAction::RequireDesktopCreate,
    }
}

fn is_native_host_process() -> bool {
    std::env::current_exe()
        .is_ok_and(|path| is_native_host_path(&path))
}

fn is_native_host_path(path: &Path) -> bool {
    path.file_name() == Some(std::ffi::OsStr::new(NATIVE_HOST_EXECUTABLE_NAME))
}

struct LegacyAclLock {
    file: File,
}

impl LegacyAclLock {
    fn acquire() -> Result<Self, String> {
        let app_data = crate::device_credentials::default_desktop_app_data_dir()
            .ok_or("无法解析 VaultMesh 应用支持目录")?;
        Self::acquire_in(&app_data)
    }

    fn acquire_in(app_data: &Path) -> Result<Self, String> {
        fs::create_dir_all(app_data).map_err(|_| "无法创建 VaultMesh 应用支持目录".to_owned())?;
        fs::set_permissions(app_data, fs::Permissions::from_mode(0o700))
            .map_err(|_| "无法保护 VaultMesh 应用支持目录".to_owned())?;
        let lock_path = app_data.join(ACL_LOCK_FILE_NAME);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&lock_path)
            .map_err(|_| "无法打开根钥匙串 ACL 锁".to_owned())?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "无法保护根钥匙串 ACL 锁".to_owned())?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err("无法等待根钥匙串 ACL 锁".to_owned());
        }
        Ok(Self { file })
    }
}

impl Drop for LegacyAclLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn read_legacy_root() -> Result<Zeroizing<[u8; 32]>, String> {
    let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
        .map_err(|error| format!("无法创建根钥匙串入口 ({})", error_code(&error)))?;
    let bytes = entry
        .get_secret()
        .map_err(|error| format!("无法读取根钥匙串条目 ({})", error_code(&error)))?;
    Ok(normalize_secret(&bytes))
}

fn try_read_legacy_root() -> Option<Zeroizing<[u8; 32]>> {
    read_legacy_root().ok()
}

fn delete_legacy_root() -> Result<(), String> {
    let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
        .map_err(|_| "无法删除旧根钥匙串条目".to_owned())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err("无法删除旧根钥匙串条目".to_owned()),
    }
}

fn protected_options(group: &str) -> PasswordOptions {
    let mut options =
        PasswordOptions::new_generic_password(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT);
    options.set_access_group(group);
    options.use_protected_keychain();
    options.set_access_synchronized(Some(false));
    options
}

fn read_protected(group: &str) -> ProtectedRead {
    match generic_password(protected_options(group)) {
        Ok(bytes) => ProtectedRead::Secret(normalize_secret(&bytes)),
        Err(error) => match error.code() {
            code if code == errSecItemNotFound => ProtectedRead::Missing,
            ERR_SEC_MISSING_ENTITLEMENT => ProtectedRead::Unavailable,
            _ => ProtectedRead::Unavailable,
        },
    }
}

fn write_protected(group: &str, secret: &[u8]) -> Result<(), ()> {
    set_generic_password_options(secret, protected_options(group)).map_err(|_| ())
}

fn current_access_group() -> Option<String> {
    let facts = signing_facts_for_self().ok()?;
    let team = facts.team.as_deref()?;
    entitled_access_group(team, &facts.groups)
}

struct SharePlan {
    paths: crate::keychain_share::InBundleExecutables,
    partitions: Vec<String>,
}

fn share_plan() -> Option<SharePlan> {
    let current = std::env::current_exe().ok()?;
    let paths = in_bundle_executable_paths(&current).ok()?;
    if !is_direct_bundle_executable(&paths.main_executable, &paths.macos_dir)
        || !is_direct_bundle_executable(&paths.native_host, &paths.macos_dir)
    {
        return None;
    }
    let main = signing_facts_for_path(&paths.main_executable).ok()?;
    let host = signing_facts_for_path(&paths.native_host).ok()?;
    let partitions = partition_ids_for_share(
        main.team.as_deref(),
        host.team.as_deref(),
        main.cdhash.as_deref()?,
        host.cdhash.as_deref()?,
    )?;
    Some(SharePlan { paths, partitions })
}

/// One-time, never additive. `SecKeychainItemSetAccess` appends ACLs (three
/// more on every call) and always asks for the login password, so it is not
/// used. The item is rebuilt instead: read the secret, delete the polluted
/// item, add a clean one that trusts only the two bundle executables.
fn migrate_legacy_root(plan: &SharePlan) -> Result<(), String> {
    let secret = read_legacy_root()?;
    delete_legacy_root()?;
    if let Err(error) = create_legacy_root_with_plan(&secret, plan) {
        // Never lose the root secret: put it back with default access.
        let restored = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
            .and_then(|entry| entry.set_secret(secret.as_slice()));
        return Err(match (error, restored) {
            (CreateLegacyRootError::Message(message), Ok(())) => {
                format!("{message}；已恢复原根钥匙串条目")
            }
            (CreateLegacyRootError::Duplicate, Ok(())) => "根钥匙串条目并发出现；已恢复".to_owned(),
            (_, Err(_)) => "无法重建根钥匙串条目，且恢复失败".to_owned(),
        });
    }
    write_plan_marker(plan)
}

fn create_fresh_legacy_root(plan: &SharePlan) -> Result<(), String> {
    let secret = random_secret();
    match create_legacy_root_with_plan(&secret, plan) {
        Ok(()) => write_plan_marker(plan),
        // Another desktop process created it with the same plan under the lock.
        Err(CreateLegacyRootError::Duplicate) => write_plan_marker(plan),
        Err(CreateLegacyRootError::Message(error)) => Err(error),
    }
}

fn plan_digest(plan: &SharePlan) -> String {
    let digest = sha2::Sha256::digest(plan.partitions.join("\n").as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn plan_marker_in(app_data: &Path) -> std::path::PathBuf {
    app_data.join(ACL_PLAN_MARKER_FILE_NAME)
}

fn plan_marker_matches(plan: &SharePlan) -> bool {
    crate::device_credentials::default_desktop_app_data_dir()
        .is_some_and(|dir| plan_marker_matches_in(&dir, plan))
}

fn plan_marker_matches_in(app_data: &Path, plan: &SharePlan) -> bool {
    fs::read_to_string(plan_marker_in(app_data))
        .is_ok_and(|text| text.trim() == plan_digest(plan))
}

fn write_plan_marker(plan: &SharePlan) -> Result<(), String> {
    let app_data = crate::device_credentials::default_desktop_app_data_dir()
        .ok_or("无法解析 VaultMesh 应用支持目录")?;
    write_plan_marker_in(&app_data, plan)
}

fn write_plan_marker_in(app_data: &Path, plan: &SharePlan) -> Result<(), String> {
    let path = plan_marker_in(app_data);
    fs::write(&path, plan_digest(plan)).map_err(|_| "无法记录根钥匙串迁移标记".to_owned())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "无法保护根钥匙串迁移标记".to_owned())
}

fn run_legacy_acl_once(operation: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    run_once(&LEGACY_ACL_RESULT, operation)
}

fn run_once<T: Clone>(
    cache: &OnceLock<Mutex<Option<Result<T, String>>>>,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    let cache = cache.get_or_init(|| Mutex::new(None));
    let mut state = cache
        .lock()
        .map_err(|_| "根钥匙串 ACL 互斥锁中毒".to_owned())?;
    if let Some(result) = state.as_ref() {
        return result.clone();
    }
    let result = operation();
    *state = Some(result.clone());
    result
}

enum CreateLegacyRootError {
    Duplicate,
    Message(String),
}

impl From<String> for CreateLegacyRootError {
    fn from(value: String) -> Self {
        Self::Message(value)
    }
}

fn create_legacy_root_with_plan(
    secret: &[u8; 32],
    plan: &SharePlan,
) -> Result<(), CreateLegacyRootError> {
    let access = access_for_plan(plan)?;
    let mut options =
        PasswordOptions::new_generic_password(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT);
    options
        .query
        .push((static_key(unsafe { kSecAttrAccess }), access.into_CFType()));
    options.query.push((
        static_key(unsafe { kSecValueData }),
        CFData::from_buffer(secret).into_CFType(),
    ));
    let params = CFDictionary::from_CFType_pairs(&options.query);
    let mut ignored: CFTypeRef = ptr::null();
    let status = unsafe { SecItemAdd(params.as_concrete_TypeRef(), &mut ignored) };
    if !ignored.is_null() {
        unsafe { CFRelease(ignored) };
    }
    if status == 0 {
        return Ok(());
    }
    if status == errSecDuplicateItem {
        return Err(CreateLegacyRootError::Duplicate);
    }
    Err(format!("无法创建共享根钥匙串条目 ({status})").into())
}

fn access_for_plan(plan: &SharePlan) -> Result<SecAccess, String> {
    let trusted = trusted_applications(&[&plan.paths.main_executable, &plan.paths.native_host])?;
    let mut raw: SecAccessRef = ptr::null_mut();
    let descriptor = CFString::from(KEYCHAIN_DESCRIPTOR);
    let status = unsafe {
        SecAccessCreate(
            descriptor.as_concrete_TypeRef(),
            trusted.array.as_CFTypeRef() as _,
            &mut raw,
        )
    };
    if status != 0 || raw.is_null() {
        return Err(format!("无法创建钥匙串访问控制 ({status})"));
    }
    let access = unsafe { SecAccess::wrap_under_create_rule(raw) };
    let hex = partition_plist_hex(&plan.partitions).ok_or("分区列表无效")?;
    ensure_partition_acl(
        access.as_concrete_TypeRef(),
        &empty_trusted_applications(),
        &hex,
    )?;
    Ok(access)
}

struct TrustedApplications {
    array: CFType,
    #[cfg_attr(not(test), allow(dead_code))]
    identities: BTreeSet<Vec<u8>>,
}

fn trusted_applications(paths: &[&Path]) -> Result<TrustedApplications, String> {
    if paths.len() != 2 {
        return Err("共享钥匙串只允许包内主程序和 Native Host".to_owned());
    }
    let mut apps = Vec::with_capacity(paths.len());
    let mut identities = BTreeSet::new();
    for path in paths {
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if !crate::keychain_share::is_allowed_bundle_executable(name) {
            return Err("拒绝将非产品二进制加入钥匙串信任列表".to_owned());
        }
        let bytes = path.as_os_str().as_bytes();
        let c_path = CString::new(bytes).map_err(|_| "可执行文件路径无效".to_owned())?;
        let mut app: CFTypeRef = ptr::null();
        let status = unsafe { SecTrustedApplicationCreateFromPath(c_path.as_ptr(), &mut app) };
        if status != 0 || app.is_null() {
            return Err(format!("无法信任包内可执行文件 ({status})"));
        }
        let app = unsafe { CFType::wrap_under_create_rule(app) };
        let identity = trusted_application_identity(app.as_CFTypeRef())?;
        if !identities.insert(identity) {
            return Err("包内主程序和 Native Host 的钥匙串身份重复".to_owned());
        }
        apps.push(app);
    }
    Ok(TrustedApplications {
        array: CFArray::from_CFTypes(&apps).into_CFType(),
        identities,
    })
}

fn empty_trusted_applications() -> CFType {
    CFArray::<CFType>::from_CFTypes(&[]).into_CFType()
}

fn trusted_application_identity(app: CFTypeRef) -> Result<Vec<u8>, String> {
    let mut data: core_foundation_sys::data::CFDataRef = ptr::null_mut();
    let status = unsafe { SecTrustedApplicationCopyData(app, &mut data) };
    if status != 0 || data.is_null() {
        return Err(format!("无法读取钥匙串信任应用身份 ({status})"));
    }
    let data = unsafe { CFData::wrap_under_create_rule(data) };
    Ok(data.bytes().to_vec())
}

fn ensure_partition_acl(
    access: SecAccessRef,
    applications: &CFType,
    hex_plist: &str,
) -> Result<(), String> {
    let records = copy_access_acl_records(access)?;
    let partitions: Vec<&AclRecord> = records
        .iter()
        .filter(|record| acl_role(&record.authorizations) == AclRole::Partition)
        .collect();
    if let Some(partition) = partitions.first() {
        set_acl_contents(partition.acl.as_CFTypeRef(), applications, hex_plist, 0)?;
        return Ok(());
    }
    create_partition_acl(access, applications, hex_plist)?;
    Ok(())
}

fn create_partition_acl(
    access: SecAccessRef,
    applications: &CFType,
    hex_plist: &str,
) -> Result<CFType, String> {
    let description = CFString::from(hex_plist);
    let mut raw_acl: CFTypeRef = ptr::null();
    let status = unsafe {
        SecACLCreateWithSimpleContents(
            access,
            applications.as_CFTypeRef() as _,
            description.as_concrete_TypeRef(),
            0,
            &mut raw_acl,
        )
    };
    if status != 0 || raw_acl.is_null() {
        return Err(format!("无法创建钥匙串分区 ACL ({status})"));
    }
    let acl = unsafe { CFType::wrap_under_create_rule(raw_acl) };
    let authorization = [CFString::from_static_string(ACL_AUTH_PARTITION)];
    let authorizations = CFArray::from_CFTypes(&authorization);
    let status = unsafe {
        SecACLUpdateAuthorizations(acl.as_CFTypeRef(), authorizations.as_concrete_TypeRef())
    };
    if status != 0 {
        return Err(format!("无法写入钥匙串分区授权 ({status})"));
    }
    Ok(acl)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AclRole {
    Encrypt,
    Decrypt,
    Change,
    Integrity,
    Partition,
    Other,
}

fn acl_role(authorizations: &[String]) -> AclRole {
    if authorizations.iter().any(|value| value == ACL_AUTH_CHANGE) {
        AclRole::Change
    } else if authorizations
        .iter()
        .any(|value| value == ACL_AUTH_PARTITION)
    {
        AclRole::Partition
    } else if authorizations
        .iter()
        .any(|value| value == ACL_AUTH_INTEGRITY)
    {
        AclRole::Integrity
    } else if authorizations.iter().any(|value| value == ACL_AUTH_DECRYPT)
        && authorizations.iter().any(|value| value == ACL_AUTH_DERIVE)
    {
        AclRole::Decrypt
    } else if authorizations.iter().any(|value| value == ACL_AUTH_ENCRYPT) {
        AclRole::Encrypt
    } else {
        AclRole::Other
    }
}

struct AclRecord {
    acl: CFType,
    applications: Vec<Vec<u8>>,
    authorizations: Vec<String>,
    description: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AclFacts {
    applications: Vec<Vec<u8>>,
    authorizations: Vec<String>,
    description: String,
}

impl From<&AclRecord> for AclFacts {
    fn from(record: &AclRecord) -> Self {
        Self {
            applications: record.applications.clone(),
            authorizations: record.authorizations.clone(),
            description: record.description.clone(),
        }
    }
}

fn copy_access_acl_records(access: SecAccessRef) -> Result<Vec<AclRecord>, String> {
    let mut acl_list: CFTypeRef = ptr::null();
    let status = unsafe { SecAccessCopyACLList(access, &mut acl_list) };
    if status != 0 || acl_list.is_null() {
        return Err(format!("无法读取钥匙串 ACL ({status})"));
    }
    let list = unsafe { CFType::wrap_under_create_rule(acl_list) };
    let count = unsafe { CFArrayGetCount(list.as_CFTypeRef() as _) };
    let mut records = Vec::with_capacity(count.max(0) as usize);
    for index in 0..count {
        let raw_acl = unsafe { CFArrayGetValueAtIndex(list.as_CFTypeRef() as _, index) };
        if raw_acl.is_null() {
            return Err("钥匙串 ACL 包含空条目".to_owned());
        }
        let acl = unsafe { CFType::wrap_under_get_rule(raw_acl) };
        let contents = copy_acl_contents(raw_acl)?;
        records.push(AclRecord {
            applications: contents.applications,
            authorizations: copy_acl_authorizations(raw_acl)?,
            description: contents.description,
            acl,
        });
    }
    Ok(records)
}

struct AclContents {
    applications: Vec<Vec<u8>>,
    description: String,
}

fn copy_acl_contents(acl: CFTypeRef) -> Result<AclContents, String> {
    let mut apps: CFTypeRef = ptr::null();
    let mut description: CFStringRef = ptr::null_mut();
    let mut prompt_selector = 0_u16;
    let status = unsafe {
        SecACLCopyContents(acl, &mut apps, &mut description, &mut prompt_selector)
    };
    if status != 0 {
        return Err(format!("无法读取钥匙串 ACL 内容 ({status})"));
    }
    let description = if description.is_null() {
        String::new()
    } else {
        unsafe { CFString::wrap_under_create_rule(description) }.to_string()
    };
    let mut identities = Vec::new();
    if !apps.is_null() {
        let apps = unsafe { CFType::wrap_under_create_rule(apps) };
        let count = unsafe { CFArrayGetCount(apps.as_CFTypeRef() as _) };
        identities.reserve(count.max(0) as usize);
        for index in 0..count {
            let app = unsafe { CFArrayGetValueAtIndex(apps.as_CFTypeRef() as _, index) };
            if app.is_null() {
                return Err("钥匙串信任应用列表包含空条目".to_owned());
            }
            identities.push(trusted_application_identity(app)?);
        }
    }
    identities.sort();
    Ok(AclContents {
        applications: identities,
        description,
    })
}

fn copy_acl_authorizations(acl: CFTypeRef) -> Result<Vec<String>, String> {
    let tags = unsafe { SecACLCopyAuthorizations(acl) };
    if tags.is_null() {
        return Err("无法读取钥匙串 ACL 授权".to_owned());
    }
    let tags = unsafe { CFType::wrap_under_create_rule(tags as CFTypeRef) };
    Ok(cf_array_strings(tags.as_CFTypeRef()))
}

#[cfg(test)]
fn acl_is_exact(item: &CFType, plan: &SharePlan) -> Result<bool, String> {
    let access = copy_item_access(item)?;
    let trusted = trusted_applications(&[&plan.paths.main_executable, &plan.paths.native_host])?;
    let records = copy_access_acl_records(access.as_concrete_TypeRef())?;
    Ok(acl_records_are_exact(
        &records,
        &trusted.identities,
        &plan.partitions,
    ))
}

#[cfg(test)]
fn acl_records_are_exact(
    records: &[AclRecord],
    expected_applications: &BTreeSet<Vec<u8>>,
    expected_partitions: &[String],
) -> bool {
    let facts: Vec<AclFacts> = records.iter().map(AclFacts::from).collect();
    acl_facts_are_exact(&facts, expected_applications, expected_partitions)
}

fn acl_facts_are_exact(
    records: &[AclFacts],
    expected_applications: &BTreeSet<Vec<u8>>,
    expected_partitions: &[String],
) -> bool {
    let mut observed_applications = BTreeSet::new();
    let mut data_acl_count = 0_usize;
    let mut partition_acl_count = 0_usize;
    for record in records {
        let role = acl_role(&record.authorizations);
        if !record.applications.is_empty() {
            if role != AclRole::Decrypt || record.applications.len() != 2 {
                return false;
            }
            data_acl_count += 1;
            observed_applications.extend(record.applications.iter().cloned());
        }
        if role == AclRole::Partition {
            partition_acl_count += 1;
            if !partitions_are_exact(&record.description, expected_partitions) {
                return false;
            }
        }
    }
    data_acl_count == 1
        && partition_acl_count >= 1
        && observed_applications == *expected_applications
}

fn copy_item_access(item: &CFType) -> Result<SecAccess, String> {
    let mut access: SecAccessRef = ptr::null_mut();
    let status = unsafe { SecKeychainItemCopyAccess(item.as_CFTypeRef(), &mut access) };
    if status != 0 || access.is_null() {
        return Err(format!("无法读取根钥匙串访问控制 ({status})"));
    }
    Ok(unsafe { SecAccess::wrap_under_create_rule(access) })
}

fn set_acl_contents(
    acl: CFTypeRef,
    applications: &CFType,
    description: &str,
    prompt_selector: u16,
) -> Result<(), String> {
    let description = CFString::from(description);
    let status = unsafe {
        SecACLSetContents(
            acl,
            applications.as_CFTypeRef() as _,
            description.as_concrete_TypeRef(),
            prompt_selector,
        )
    };
    if status != 0 {
        return Err(format!("无法写入钥匙串 ACL ({status})"));
    }
    Ok(())
}

fn legacy_item_ref() -> Result<Option<CFType>, String> {
    let query = dictionary(&[
        (
            static_key(unsafe { kSecClass }),
            static_type(unsafe { kSecClassGenericPassword }),
        ),
        (
            static_key(unsafe { kSecAttrService }),
            CFString::from(ROOT_KEYRING_SERVICE).into_CFType(),
        ),
        (
            static_key(unsafe { kSecAttrAccount }),
            CFString::from(ROOT_KEYRING_ACCOUNT).into_CFType(),
        ),
        (
            static_key(unsafe { kSecReturnRef }),
            CFBoolean::from(true).into_CFType(),
        ),
    ]);
    let mut result: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
    if status == errSecItemNotFound {
        return Ok(None);
    }
    if status != 0 || result.is_null() {
        return Err(format!("无法定位根钥匙串条目 ({status})"));
    }
    Ok(Some(unsafe { CFType::wrap_under_create_rule(result) }))
}

fn signing_facts_for_self() -> Result<SigningFacts, ()> {
    let mut code: SecCodeRef = ptr::null_mut();
    if unsafe { SecCodeCopySelf(0, &mut code) } != 0 || code.is_null() {
        return Err(());
    }
    let facts = signing_facts_from_code(code as SecStaticCodeRef);
    unsafe { CFRelease(code as CFTypeRef) };
    facts
}

fn signing_facts_for_path(path: &Path) -> Result<SigningFacts, ()> {
    let url = CFURL::from_path(path, false).ok_or(())?;
    let mut code: SecStaticCodeRef = ptr::null_mut();
    if unsafe { SecStaticCodeCreateWithPath(url.as_concrete_TypeRef(), 0, &mut code) } != 0
        || code.is_null()
    {
        return Err(());
    }
    let facts = signing_facts_from_code(code);
    unsafe { CFRelease(code as CFTypeRef) };
    facts
}

fn signing_facts_from_code(code: SecStaticCodeRef) -> Result<SigningFacts, ()> {
    let mut info: CFDictionaryRef = ptr::null_mut();
    if unsafe { SecCodeCopySigningInformation(code, SEC_CS_SIGNING_INFORMATION, &mut info) } != 0
        || info.is_null()
    {
        return Err(());
    }
    let info = unsafe { CFType::wrap_under_create_rule(info as CFTypeRef) };
    let team = dictionary_string(info.as_CFTypeRef(), unsafe { kSecCodeInfoTeamIdentifier });
    let cdhash = dictionary_data_hex(info.as_CFTypeRef(), unsafe { kSecCodeInfoUnique });
    let dict_groups = nested_string_array(
        info.as_CFTypeRef(),
        unsafe { kSecCodeInfoEntitlementsDict },
        "keychain-access-groups",
    );
    let blob = dictionary_data_bytes(info.as_CFTypeRef(), unsafe { kSecCodeInfoEntitlements });
    let mut groups = select_keychain_access_groups(dict_groups, blob.as_deref());
    if groups.is_empty() {
        if let Some(bytes) = blob.as_deref() {
            if let Some(parsed) = access_groups_from_property_list(bytes) {
                groups = parsed;
            }
        }
    }
    if cdhash.is_none() {
        return Err(());
    }
    Ok(SigningFacts {
        team,
        cdhash,
        groups,
    })
}

fn dictionary_string(dict: CFTypeRef, key: CFStringRef) -> Option<String> {
    if dict.is_null()
        || unsafe { CFGetTypeID(dict) }
            != unsafe { core_foundation_sys::dictionary::CFDictionaryGetTypeID() }
    {
        return None;
    }
    let value = unsafe { CFDictionaryGetValue(dict as _, key as _) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return None;
    }
    let text = unsafe { CFString::wrap_under_get_rule(value as _) }.to_string();
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn dictionary_data_hex(dict: CFTypeRef, key: CFStringRef) -> Option<String> {
    if dict.is_null()
        || unsafe { CFGetTypeID(dict) }
            != unsafe { core_foundation_sys::dictionary::CFDictionaryGetTypeID() }
    {
        return None;
    }
    let value = unsafe { CFDictionaryGetValue(dict as _, key as _) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return None;
    }
    let data = unsafe { CFData::wrap_under_get_rule(value as _) };
    Some(
        data.bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

fn dictionary_string_array(dict: CFTypeRef, key: CFStringRef) -> Option<Vec<String>> {
    if dict.is_null()
        || unsafe { CFGetTypeID(dict) }
            != unsafe { core_foundation_sys::dictionary::CFDictionaryGetTypeID() }
    {
        return None;
    }
    let value = unsafe { CFDictionaryGetValue(dict as _, key as _) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFArrayGetTypeID() } {
        return None;
    }
    Some(cf_array_strings(value))
}

fn dictionary_data_bytes(dict: CFTypeRef, key: CFStringRef) -> Option<Vec<u8>> {
    if dict.is_null()
        || unsafe { CFGetTypeID(dict) }
            != unsafe { core_foundation_sys::dictionary::CFDictionaryGetTypeID() }
    {
        return None;
    }
    let value = unsafe { CFDictionaryGetValue(dict as _, key as _) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFDataGetTypeID() } {
        return None;
    }
    let data = unsafe { CFData::wrap_under_get_rule(value as _) };
    Some(data.bytes().to_vec())
}

fn access_groups_from_property_list(bytes: &[u8]) -> Option<Vec<String>> {
    use core_foundation::propertylist::{CFPropertyList, create_with_data};
    use core_foundation_sys::propertylist::kCFPropertyListImmutable;

    let data = CFData::from_buffer(bytes);
    let (raw, _) = create_with_data(data, kCFPropertyListImmutable).ok()?;
    let plist = unsafe { CFPropertyList::wrap_under_create_rule(raw as _) };
    let dict = plist.downcast::<core_foundation::dictionary::CFDictionary>()?;
    let key = CFString::from("keychain-access-groups");
    dictionary_string_array(dict.as_CFTypeRef(), key.as_concrete_TypeRef())
}

fn nested_string_array(dict: CFTypeRef, key: CFStringRef, nested_key: &str) -> Option<Vec<String>> {
    if dict.is_null()
        || unsafe { CFGetTypeID(dict) }
            != unsafe { core_foundation_sys::dictionary::CFDictionaryGetTypeID() }
    {
        return None;
    }
    let value = unsafe { CFDictionaryGetValue(dict as _, key as _) };
    if value.is_null() {
        return None;
    }
    let nested = CFString::from(nested_key);
    dictionary_string_array(value, nested.as_concrete_TypeRef())
}

fn cf_array_strings(value: CFTypeRef) -> Vec<String> {
    let count = unsafe { CFArrayGetCount(value as _) };
    let mut groups = Vec::new();
    for index in 0..count {
        let item = unsafe { CFArrayGetValueAtIndex(value as _, index) };
        if item.is_null() || unsafe { CFGetTypeID(item) } != unsafe { CFStringGetTypeID() } {
            continue;
        }
        groups.push(unsafe { CFString::wrap_under_get_rule(item as _) }.to_string());
    }
    groups
}

fn parse_legacy_accounts(value: &CFType) -> Result<Vec<String>, String> {
    let mut dicts = Vec::new();
    if unsafe { CFGetTypeID(value.as_CFTypeRef()) } == unsafe { CFArrayGetTypeID() } {
        let count = unsafe { CFArrayGetCount(value.as_CFTypeRef() as _) };
        if count > 64 {
            return Err("旧钥匙串条目过多".to_owned());
        }
        for index in 0..count {
            let item = unsafe { CFArrayGetValueAtIndex(value.as_CFTypeRef() as _, index) };
            if !item.is_null() {
                dicts.push(item);
            }
        }
    } else {
        dicts.push(value.as_CFTypeRef());
    }
    let mut accounts = Vec::new();
    for dict in dicts {
        let Some(account) = dictionary_string(dict, unsafe { kSecAttrAccount }) else {
            continue;
        };
        accounts.push(account);
    }
    Ok(accounts)
}

fn dictionary(pairs: &[(CFString, CFType)]) -> CFDictionary<CFString, CFType> {
    CFDictionary::from_CFType_pairs(pairs)
}

fn static_key(key: CFStringRef) -> CFString {
    unsafe { CFString::wrap_under_get_rule(key) }
}

fn static_type(key: CFStringRef) -> CFType {
    static_key(key).into_CFType()
}

fn normalize_secret(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    if bytes.len() == 32 {
        secret.copy_from_slice(bytes);
    } else {
        let hash = sha2::Sha256::digest(bytes);
        secret.copy_from_slice(&hash);
    }
    secret
}

fn random_secret() -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(secret.as_mut());
    secret
}

fn error_code(error: &keyring::Error) -> String {
    match error {
        keyring::Error::NoEntry => "missing".to_owned(),
        _ => "platform".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn expected_applications() -> BTreeSet<Vec<u8>> {
        BTreeSet::from([
            b"/Applications/VaultMesh.app\0".to_vec(),
            b"/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host\0".to_vec(),
        ])
    }

    fn partition_description(extra: Option<&str>) -> String {
        let mut partitions = vec![
            format!("cdhash:{}", "a".repeat(40)),
            format!("cdhash:{}", "b".repeat(40)),
        ];
        if let Some(extra) = extra {
            partitions.push(extra.to_owned());
        }
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Partitions</key><array>",
        );
        for partition in partitions {
            xml.push_str("<string>");
            xml.push_str(&partition);
            xml.push_str("</string>");
        }
        xml.push_str("</array></dict></plist>");
        xml.bytes().fold(String::new(), |mut hex, byte| {
            hex.push_str(&format!("{byte:02x}"));
            hex
        })
    }

    fn fact(authorizations: &[&str], applications: &[&[u8]], description: &str) -> AclFacts {
        AclFacts {
            applications: applications.iter().map(|value| value.to_vec()).collect(),
            authorizations: authorizations
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            description: description.to_owned(),
        }
    }

    fn expected_partitions() -> Vec<String> {
        vec![
            format!("cdhash:{}", "a".repeat(40)),
            format!("cdhash:{}", "b".repeat(40)),
        ]
    }

    #[test]
    fn exact_acl_requires_only_two_trusted_apps_and_one_exact_partition() {
        let expected = expected_applications();
        let partitions = expected_partitions();
        let exact = [
            fact(&[ACL_AUTH_ENCRYPT], &[], KEYCHAIN_DESCRIPTOR),
            fact(
                &[ACL_AUTH_DECRYPT, ACL_AUTH_DERIVE],
                &[
                    b"/Applications/VaultMesh.app\0",
                    b"/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host\0",
                ],
                KEYCHAIN_DESCRIPTOR,
            ),
            fact(&[ACL_AUTH_CHANGE], &[], KEYCHAIN_DESCRIPTOR),
            fact(&[ACL_AUTH_PARTITION], &[], &partition_description(None)),
        ];
        assert!(acl_facts_are_exact(&exact, &expected, &partitions));
    }

    #[test]
    fn polluted_acl_rejects_extra_debug_unsigned_and_duplicate_trust() {
        let expected = expected_applications();
        let partitions = expected_partitions();
        let mut polluted = vec![
            fact(&[ACL_AUTH_ENCRYPT], &[], KEYCHAIN_DESCRIPTOR),
            fact(
                &[ACL_AUTH_DECRYPT, ACL_AUTH_DERIVE],
                &[
                    b"/Applications/VaultMesh.app\0",
                    b"/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host\0",
                ],
                KEYCHAIN_DESCRIPTOR,
            ),
            fact(&[ACL_AUTH_CHANGE], &[], KEYCHAIN_DESCRIPTOR),
            fact(&[ACL_AUTH_PARTITION], &[], &partition_description(None)),
        ];
        assert!(acl_facts_are_exact(&polluted, &expected, &partitions));

        polluted.push(fact(
            &[ACL_AUTH_DECRYPT, ACL_AUTH_DERIVE],
            &[b"/tmp/vaultmesh-tauri-desktop\0"],
            KEYCHAIN_DESCRIPTOR,
        ));
        assert!(!acl_facts_are_exact(&polluted, &expected, &partitions));

        polluted.pop();
        polluted.push(fact(
            &[ACL_AUTH_ENCRYPT],
            &[b"/tmp/vaultmesh-native-host\0"],
            KEYCHAIN_DESCRIPTOR,
        ));
        assert!(!acl_facts_are_exact(&polluted, &expected, &partitions));

        polluted.pop();
        polluted.push(fact(
            &[ACL_AUTH_DECRYPT, ACL_AUTH_DERIVE],
            &[
                b"/Applications/VaultMesh.app\0",
                b"/Applications/VaultMesh.app\0",
            ],
            KEYCHAIN_DESCRIPTOR,
        ));
        assert!(!acl_facts_are_exact(&polluted, &expected, &partitions));
    }

    #[test]
    fn missing_or_stale_partition_is_not_exact_and_duplicate_partitions_must_agree() {
        let expected = expected_applications();
        let partitions = expected_partitions();
        let mut records = vec![
            fact(&[ACL_AUTH_ENCRYPT], &[], KEYCHAIN_DESCRIPTOR),
            fact(
                &[ACL_AUTH_DECRYPT, ACL_AUTH_DERIVE],
                &[
                    b"/Applications/VaultMesh.app\0",
                    b"/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host\0",
                ],
                KEYCHAIN_DESCRIPTOR,
            ),
            fact(&[ACL_AUTH_CHANGE], &[], KEYCHAIN_DESCRIPTOR),
        ];
        assert!(!acl_facts_are_exact(&records, &expected, &partitions));

        records.push(fact(
            &[ACL_AUTH_PARTITION],
            &[],
            &partition_description(Some("unsigned:")),
        ));
        assert!(!acl_facts_are_exact(&records, &expected, &partitions));

        records.pop();
        records.push(fact(
            &[ACL_AUTH_PARTITION],
            &[],
            &partition_description(None),
        ));
        assert!(acl_facts_are_exact(&records, &expected, &partitions));

        records.push(fact(
            &[ACL_AUTH_PARTITION],
            &[],
            &partition_description(None),
        ));
        assert!(acl_facts_are_exact(&records, &expected, &partitions));

        records.pop();
        records.push(fact(
            &[ACL_AUTH_PARTITION],
            &[],
            &partition_description(Some(&format!("cdhash:{}", "c".repeat(40)))),
        ));
        assert!(!acl_facts_are_exact(&records, &expected, &partitions));
    }

    #[test]
    fn security_authorization_api_can_patch_an_in_memory_partition_acl() {
        let empty = empty_trusted_applications();
        let descriptor = CFString::from(KEYCHAIN_DESCRIPTOR);
        let mut raw_access: SecAccessRef = ptr::null_mut();
        let status = unsafe {
            SecAccessCreate(
                descriptor.as_concrete_TypeRef(),
                empty.as_CFTypeRef() as _,
                &mut raw_access,
            )
        };
        assert_eq!(status, 0);
        assert!(!raw_access.is_null());
        let access = unsafe { SecAccess::wrap_under_create_rule(raw_access) };

        let initial = copy_access_acl_records(access.as_concrete_TypeRef()).unwrap();
        assert!(
            initial
                .iter()
                .any(|record| acl_role(&record.authorizations) == AclRole::Decrypt)
        );
        assert!(
            initial
                .iter()
                .any(|record| acl_role(&record.authorizations) == AclRole::Encrypt)
        );
        assert!(
            initial
                .iter()
                .any(|record| acl_role(&record.authorizations) == AclRole::Change)
        );

        let partitions = expected_partitions();
        let description = partition_description(None);
        ensure_partition_acl(access.as_concrete_TypeRef(), &empty, &description).unwrap();
        let patched = copy_access_acl_records(access.as_concrete_TypeRef()).unwrap();
        let partition_records: Vec<_> = patched
            .iter()
            .filter(|record| acl_role(&record.authorizations) == AclRole::Partition)
            .collect();
        assert_eq!(partition_records.len(), 1);
        assert!(partitions_are_exact(
            &partition_records[0].description,
            &partitions
        ));
    }

    #[test]
    fn acl_repair_attempt_is_cached_for_the_process_lifetime() {
        let cache = OnceLock::new();
        let attempts = AtomicUsize::new(0);
        let operation = || {
            attempts.fetch_add(1, Ordering::SeqCst);
            Err::<(), String>("cancelled".to_owned())
        };

        assert_eq!(run_once(&cache, &operation).unwrap_err(), "cancelled");
        assert_eq!(run_once(&cache, &operation).unwrap_err(), "cancelled");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn native_host_never_mutates_legacy_acl_or_creates_the_root_item() {
        assert_eq!(
            legacy_acl_action(false, true, true),
            LegacyAclAction::Read
        );
        assert_eq!(
            legacy_acl_action(false, true, false),
            LegacyAclAction::Migrate
        );
        assert_eq!(
            legacy_acl_action(false, false, false),
            LegacyAclAction::Create
        );
        assert_eq!(
            legacy_acl_action(true, true, true),
            LegacyAclAction::Read
        );
        assert_eq!(
            legacy_acl_action(true, true, false),
            LegacyAclAction::RequireDesktopMigrate
        );
        assert_eq!(
            legacy_acl_action(true, false, false),
            LegacyAclAction::RequireDesktopCreate
        );
    }

    #[test]
    fn unsigned_release_bundle_never_reaches_the_production_root_item() {
        assert!(must_refuse_unplanned_bundle(true, true, false));
        assert!(!must_refuse_unplanned_bundle(true, true, true));
        // Development builds and non-bundle executables keep the plain path.
        assert!(!must_refuse_unplanned_bundle(false, true, false));
        assert!(!must_refuse_unplanned_bundle(true, false, false));
    }

    fn sample_plan(main_hash: char) -> SharePlan {
        let hash = |c: char| c.to_string().repeat(40);
        SharePlan {
            paths: crate::keychain_share::InBundleExecutables {
                macos_dir: "/Applications/VaultMesh.app/Contents/MacOS".into(),
                main_executable: "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-tauri-desktop".into(),
                native_host: "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host".into(),
            },
            partitions: vec![format!("cdhash:{}", hash(main_hash)), format!("cdhash:{}", hash('b'))],
        }
    }

    #[test]
    fn migration_marker_is_bound_to_the_cdhash_pair_so_each_build_migrates_once() {
        let root = std::env::temp_dir().join(format!("vaultmesh-marker-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let first = sample_plan('a');
        assert!(!plan_marker_matches_in(&root, &first));
        write_plan_marker_in(&root, &first).unwrap();
        assert!(plan_marker_matches_in(&root, &first));
        // A new build changes the cdhash, so exactly one new migration is due.
        assert!(!plan_marker_matches_in(&root, &sample_plan('c')));
        assert_eq!(
            fs::metadata(plan_marker_in(&root)).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn migrated_item_is_read_without_any_acl_change_by_main_and_host() {
        assert_eq!(legacy_acl_action(false, true, true), LegacyAclAction::Read);
        assert_eq!(legacy_acl_action(true, true, true), LegacyAclAction::Read);
    }

    #[test]
    fn the_product_native_host_name_is_read_only() {
        assert!(is_native_host_path(Path::new(
            "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-native-host"
        )));
        assert!(is_native_host_path(Path::new(
            "/tmp/vaultmesh-native-host"
        )));
        assert!(!is_native_host_path(Path::new(
            "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-tauri-desktop"
        )));
        assert!(!is_native_host_path(Path::new(
            "/Applications/VaultMesh.app/Contents/MacOS/vaultmesh-bitwarden-dev-host"
        )));
    }

    #[test]
    fn inspect_live_acl_metadata_when_requested() {
        if std::env::var_os("VAULTMESH_INSPECT_ACL").is_none() {
            return;
        }
        let main = std::env::var_os("VAULTMESH_INSPECT_APP")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(
                    "target/release/bundle/macos/VaultMesh.app/Contents/MacOS/vaultmesh-tauri-desktop",
                )
            });
        let main = main.as_path();
        let paths = in_bundle_executable_paths(main).unwrap();
        let host = signing_facts_for_path(&paths.native_host).unwrap();
        let expected = signing_facts_for_path(&paths.main_executable).unwrap();
        let partitions = partition_ids_for_share(
            expected.team.as_deref(),
            host.team.as_deref(),
            expected.cdhash.as_deref().unwrap(),
            host.cdhash.as_deref().unwrap(),
        )
        .unwrap();
        let plan = SharePlan { paths, partitions };
        let trusted =
            trusted_applications(&[&plan.paths.main_executable, &plan.paths.native_host]).unwrap();
        let item = legacy_item_ref().unwrap().expect("root item missing");
        let access = copy_item_access(&item).unwrap();
        let records = copy_access_acl_records(access.as_concrete_TypeRef()).unwrap();
        let fingerprint = |identity: &[u8]| {
            let digest = sha2::Sha256::digest(identity);
            digest[..8]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        println!(
            "expected={:?}",
            trusted
                .identities
                .iter()
                .map(|identity| fingerprint(identity))
                .collect::<Vec<_>>()
        );
        for record in &records {
            println!(
                "role={:?} apps={:?} auths={:?} description_bytes={}",
                acl_role(&record.authorizations),
                record
                    .applications
                    .iter()
                    .map(|identity| fingerprint(identity))
                    .collect::<Vec<_>>(),
                record.authorizations,
                record.description.len()
            );
        }
        println!(
            "exact={}",
            acl_records_are_exact(&records, &trusted.identities, &plan.partitions)
        );
        let replacement = access_for_plan(&plan).unwrap();
        let replacement_records =
            copy_access_acl_records(replacement.as_concrete_TypeRef()).unwrap();
        println!(
            "replacement_exact={}",
            acl_records_are_exact(
                &replacement_records,
                &trusted.identities,
                &plan.partitions
            )
        );
        for record in &replacement_records {
            println!(
                "replacement_role={:?} apps={:?} auths={:?} description_bytes={}",
                acl_role(&record.authorizations),
                record
                    .applications
                    .iter()
                    .map(|identity| fingerprint(identity))
                    .collect::<Vec<_>>(),
                record.authorizations,
                record.description.len()
            );
        }
    }

    #[test]
    fn acl_lock_file_stays_inside_owner_only_app_data() {
        let root =
            std::env::temp_dir().join(format!("vaultmesh-keychain-lock-{}", uuid::Uuid::new_v4()));
        {
            let _lock = LegacyAclLock::acquire_in(&root).unwrap();
            assert_eq!(
                fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(root.join(ACL_LOCK_FILE_NAME))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
