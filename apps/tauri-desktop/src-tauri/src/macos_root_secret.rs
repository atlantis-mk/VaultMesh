//! macOS root secret: data-protection Keychain access group when the process is
//! Team-signed, otherwise a legacy item whose ACL names only the two in-bundle
//! executables.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use core_foundation::array::CFArray;
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_foundation::url::CFURL;
use core_foundation_sys::array::{CFArrayGetCount, CFArrayGetTypeID, CFArrayGetValueAtIndex};
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
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate};
use sha2::Digest;
use zeroize::Zeroizing;

use crate::device_credentials::{ROOT_KEYRING_ACCOUNT, ROOT_KEYRING_SERVICE};
use crate::keychain_share::{
    SEC_CS_SIGNING_INFORMATION, entitled_access_group, in_bundle_executable_paths,
    is_direct_bundle_executable, partition_ids_for_share, partition_plist_hex,
    partitions_are_exact, same_executable_set, select_keychain_access_groups,
};

const ERR_SEC_MISSING_ENTITLEMENT: OSStatus = -34018;

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
    fn SecACLCopyAuthorizations(acl: CFTypeRef, tags: *mut CFTypeRef) -> OSStatus;
    fn SecKeychainItemCopyAccess(item: CFTypeRef, access: *mut SecAccessRef) -> OSStatus;
    fn SecKeychainItemSetAccess(item: CFTypeRef, access: SecAccessRef) -> OSStatus;
    fn SecTrustedApplicationCopyData(
        app: CFTypeRef,
        data: *mut core_foundation_sys::data::CFDataRef,
    ) -> OSStatus;
}

use core_foundation_sys::string::CFStringRef;

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
                if let Some(secret) = read_legacy_root() {
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

fn legacy_root_secret() -> Result<Zeroizing<[u8; 32]>, String> {
    if let Some(secret) = read_legacy_root() {
        let _ = ensure_shared_legacy_acl();
        return Ok(secret);
    }
    let secret = random_secret();
    if let Some(plan) = share_plan() {
        if write_legacy_with_plan(&secret, &plan).is_ok() {
            return Ok(secret);
        }
    }
    let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT)
        .map_err(|error| format!("无法创建钥匙串入口 ({})", error_code(&error)))?;
    entry
        .set_secret(secret.as_slice())
        .map_err(|error| format!("无法在钥匙串中保存根密钥 ({})", error_code(&error)))?;
    Ok(secret)
}

fn read_legacy_root() -> Option<Zeroizing<[u8; 32]>> {
    let entry = keyring::Entry::new(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT).ok()?;
    let bytes = entry.get_secret().ok()?;
    Some(normalize_secret(&bytes))
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
            errSecItemNotFound => ProtectedRead::Missing,
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

fn ensure_shared_legacy_acl() -> Result<(), String> {
    let Some(plan) = share_plan() else {
        return Ok(());
    };
    let item = legacy_item_ref()?;
    if item_already_shared(&item, &plan) {
        return Ok(());
    }
    let access = access_for_plan(&plan)?;
    let status =
        unsafe { SecKeychainItemSetAccess(item.as_CFTypeRef(), access.as_concrete_TypeRef()) };
    if status != 0 {
        return Err(format!("无法更新根钥匙串授权 ({status})"));
    }
    Ok(())
}

fn write_legacy_with_plan(secret: &[u8; 32], plan: &SharePlan) -> Result<(), String> {
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
    if status != errSecDuplicateItem {
        return Err(format!("无法创建共享根钥匙串条目 ({status})"));
    }
    let query = PasswordOptions::new_generic_password(ROOT_KEYRING_SERVICE, ROOT_KEYRING_ACCOUNT);
    let update_access = access_for_plan(plan)?;
    let update = vec![
        (
            static_key(unsafe { kSecValueData }),
            CFData::from_buffer(secret).into_CFType(),
        ),
        (
            static_key(unsafe { kSecAttrAccess }),
            update_access.into_CFType(),
        ),
    ];
    let query_dict = CFDictionary::from_CFType_pairs(&query.query);
    let update_dict = CFDictionary::from_CFType_pairs(&update);
    let status = unsafe {
        SecItemUpdate(
            query_dict.as_concrete_TypeRef(),
            update_dict.as_concrete_TypeRef(),
        )
    };
    if status != 0 {
        return Err(format!("无法更新共享根钥匙串条目 ({status})"));
    }
    Ok(())
}

fn access_for_plan(plan: &SharePlan) -> Result<SecAccess, String> {
    let trusted = trusted_applications(&[&plan.paths.main_executable, &plan.paths.native_host])?;
    let mut raw: SecAccessRef = ptr::null_mut();
    let descriptor = CFString::from("VaultMesh device root");
    let status = unsafe {
        SecAccessCreate(
            descriptor.as_concrete_TypeRef(),
            trusted.as_CFTypeRef() as _,
            &mut raw,
        )
    };
    if status != 0 || raw.is_null() {
        return Err(format!("无法创建钥匙串访问控制 ({status})"));
    }
    let access = unsafe { SecAccess::wrap_under_create_rule(raw) };
    let hex = partition_plist_hex(&plan.partitions).ok_or("分区列表无效")?;
    patch_partition_acl(access.as_concrete_TypeRef(), &trusted, &hex)?;
    Ok(access)
}

fn trusted_applications(paths: &[&Path]) -> Result<CFType, String> {
    if paths.len() != 2 {
        return Err("共享钥匙串只允许包内主程序和 Native Host".to_owned());
    }
    let mut apps = Vec::with_capacity(paths.len());
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
        apps.push(unsafe { CFType::wrap_under_create_rule(app) });
    }
    Ok(CFArray::from_CFTypes(&apps).into_CFType())
}

fn patch_partition_acl(
    access: SecAccessRef,
    trusted: &CFType,
    hex_plist: &str,
) -> Result<(), String> {
    let mut acl_list: CFTypeRef = ptr::null();
    let status = unsafe { SecAccessCopyACLList(access, &mut acl_list) };
    if status != 0 || acl_list.is_null() {
        return Err(format!("无法读取钥匙串 ACL ({status})"));
    }
    let list = unsafe { CFType::wrap_under_create_rule(acl_list) };
    let count = unsafe { CFArrayGetCount(list.as_CFTypeRef() as _) };
    let description = CFString::from(hex_plist);
    for index in 0..count {
        let acl = unsafe { CFArrayGetValueAtIndex(list.as_CFTypeRef() as _, index) };
        if acl.is_null() || !acl_is_partition(acl) {
            continue;
        }
        let status = unsafe {
            SecACLSetContents(
                acl,
                trusted.as_CFTypeRef() as _,
                description.as_concrete_TypeRef(),
                0,
            )
        };
        if status != 0 {
            return Err(format!("无法写入钥匙串分区 ({status})"));
        }
    }
    Ok(())
}

fn acl_is_partition(acl: CFTypeRef) -> bool {
    let mut tags: CFTypeRef = ptr::null();
    if unsafe { SecACLCopyAuthorizations(acl, &mut tags) } != 0 || tags.is_null() {
        return false;
    }
    let owned = unsafe { CFType::wrap_under_create_rule(tags) };
    let count = unsafe { CFArrayGetCount(owned.as_CFTypeRef() as _) };
    for index in 0..count {
        let tag = unsafe { CFArrayGetValueAtIndex(owned.as_CFTypeRef() as _, index) };
        if tag.is_null() || unsafe { CFGetTypeID(tag) } != unsafe { CFStringGetTypeID() } {
            continue;
        }
        let text = unsafe { CFString::wrap_under_get_rule(tag as _) }.to_string();
        if text.contains("Partition") {
            return true;
        }
    }
    false
}

fn item_already_shared(item: &CFType, plan: &SharePlan) -> bool {
    let mut access: SecAccessRef = ptr::null_mut();
    if unsafe { SecKeychainItemCopyAccess(item.as_CFTypeRef(), &mut access) } != 0
        || access.is_null()
    {
        return false;
    }
    let access = unsafe { SecAccess::wrap_under_create_rule(access) };
    let mut acl_list: CFTypeRef = ptr::null();
    if unsafe { SecAccessCopyACLList(access.as_concrete_TypeRef(), &mut acl_list) } != 0
        || acl_list.is_null()
    {
        return false;
    }
    let list = unsafe { CFType::wrap_under_create_rule(acl_list) };
    let count = unsafe { CFArrayGetCount(list.as_CFTypeRef() as _) };
    let mut saw_exact_clients = false;
    let mut saw_partitions = false;
    for index in 0..count {
        let acl = unsafe { CFArrayGetValueAtIndex(list.as_CFTypeRef() as _, index) };
        if acl.is_null() {
            continue;
        }
        let mut apps: CFTypeRef = ptr::null();
        let mut description: CFStringRef = ptr::null_mut();
        let mut prompt = 0_u16;
        if unsafe { SecACLCopyContents(acl, &mut apps, &mut description, &mut prompt) } != 0 {
            continue;
        }
        if !apps.is_null() {
            let paths = trusted_application_paths(apps);
            let expected = [
                plan.paths.main_executable.clone(),
                plan.paths.native_host.clone(),
            ];
            if same_executable_set(&paths, &expected) {
                saw_exact_clients = true;
            }
            unsafe { CFRelease(apps) };
        }
        if !description.is_null() {
            let text = unsafe { CFString::wrap_under_create_rule(description) }.to_string();
            if partitions_are_exact(&text, &plan.partitions) {
                saw_partitions = true;
            }
        }
    }
    saw_exact_clients && saw_partitions
}

fn trusted_application_paths(apps: CFTypeRef) -> Vec<std::path::PathBuf> {
    let count = unsafe { CFArrayGetCount(apps as _) };
    let mut paths = Vec::new();
    for index in 0..count {
        let app = unsafe { CFArrayGetValueAtIndex(apps as _, index) };
        if app.is_null() {
            continue;
        }
        let mut data: core_foundation_sys::data::CFDataRef = ptr::null_mut();
        if unsafe { SecTrustedApplicationCopyData(app, &mut data) } != 0 || data.is_null() {
            continue;
        }
        let data = unsafe { CFData::wrap_under_create_rule(data) };
        let bytes = data.bytes();
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        if let Ok(text) = std::str::from_utf8(&bytes[..end]) {
            if !text.is_empty() {
                paths.push(std::path::PathBuf::from(text));
            }
        }
    }
    paths
}

fn legacy_item_ref() -> Result<CFType, String> {
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
    if status != 0 || result.is_null() {
        return Err(format!("无法定位根钥匙串条目 ({status})"));
    }
    Ok(unsafe { CFType::wrap_under_create_rule(result) })
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
