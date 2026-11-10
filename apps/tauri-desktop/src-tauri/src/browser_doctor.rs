// browser_doctor.rs
// Diagnostics and Auto-Repair for Desktop & Browser Integration (CHG-2026-081, ADR-0056)

use std::fs;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::RuntimeState;
use crate::browser_host_registration::{
    BROWSER_HOST_NAME, DEFAULT_DEVELOPMENT_EXTENSION_ID,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserDoctorItem {
    pub id: String,
    pub name: String,
    pub installed: bool,
    pub manifest_registered: bool,
    pub manifest_path: Option<String>,
    pub extension_installed: bool,
    pub store_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorCheckItem {
    pub id: String,
    pub label: String,
    pub status: String, // "ok" | "warn" | "error"
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserDoctorReport {
    pub supported: bool,
    pub ready: bool,
    pub broker_ready: bool,
    pub host_registered: bool,
    pub extension_id: String,
    pub error_code: Option<String>,
    pub api_port: Option<u16>,
    pub check_items: Vec<DoctorCheckItem>,
    pub browsers: Vec<BrowserDoctorItem>,
}

struct BrowserDefinition {
    id: &'static str,
    name: &'static str,
    is_firefox: bool,
    #[cfg(target_os = "macos")]
    app_names: &'static [&'static str],
    #[cfg(target_os = "macos")]
    app_support_dir: &'static str,
    #[cfg(target_os = "macos")]
    manifest_subpath: &'static str,
    store_url: &'static str,
}

const CHROME_STORE_URL: &str = "https://chromewebstore.google.com/detail/vaultmesh-password-manage/bdneegbnjbheblmamalplnddbodcghbg";
const GITHUB_RELEASE_URL: &str = concat!("https://github.com/atlantis-mk/VaultMesh/releases/tag/v", env!("CARGO_PKG_VERSION"));

const BROWSERS: &[BrowserDefinition] = &[
    BrowserDefinition {
        id: "chrome",
        name: "Google Chrome",
        is_firefox: false,
        #[cfg(target_os = "macos")]
        app_names: &["Google Chrome.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "Google/Chrome",
        #[cfg(target_os = "macos")]
        manifest_subpath: "Google/Chrome/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: CHROME_STORE_URL,
    },
    BrowserDefinition {
        id: "edge",
        name: "Microsoft Edge",
        is_firefox: false,
        #[cfg(target_os = "macos")]
        app_names: &["Microsoft Edge.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "Microsoft Edge",
        #[cfg(target_os = "macos")]
        manifest_subpath: "Microsoft Edge/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: GITHUB_RELEASE_URL,
    },
    BrowserDefinition {
        id: "brave",
        name: "Brave Browser",
        is_firefox: false,
        #[cfg(target_os = "macos")]
        app_names: &["Brave Browser.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "BraveSoftware/Brave-Browser",
        #[cfg(target_os = "macos")]
        manifest_subpath: "BraveSoftware/Brave-Browser/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: GITHUB_RELEASE_URL,
    },
    BrowserDefinition {
        id: "arc",
        name: "Arc",
        is_firefox: false,
        #[cfg(target_os = "macos")]
        app_names: &["Arc.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "Arc/User Data",
        #[cfg(target_os = "macos")]
        manifest_subpath: "Arc/User Data/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: GITHUB_RELEASE_URL,
    },
    BrowserDefinition {
        id: "vivaldi",
        name: "Vivaldi",
        is_firefox: false,
        #[cfg(target_os = "macos")]
        app_names: &["Vivaldi.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "Vivaldi",
        #[cfg(target_os = "macos")]
        manifest_subpath: "Vivaldi/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: GITHUB_RELEASE_URL,
    },
    BrowserDefinition {
        id: "chromium",
        name: "Chromium",
        is_firefox: false,
        #[cfg(target_os = "macos")]
        app_names: &["Chromium.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "Chromium",
        #[cfg(target_os = "macos")]
        manifest_subpath: "Chromium/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: GITHUB_RELEASE_URL,
    },
    BrowserDefinition {
        id: "firefox",
        name: "Mozilla Firefox",
        is_firefox: true,
        #[cfg(target_os = "macos")]
        app_names: &["Firefox.app"],
        #[cfg(target_os = "macos")]
        app_support_dir: "Mozilla",
        #[cfg(target_os = "macos")]
        manifest_subpath: "Mozilla/NativeMessagingHosts/com.vaultmesh.browser.json",
        store_url: GITHUB_RELEASE_URL,
    },
];

fn locate_native_host_binary() -> Option<PathBuf> {
    if let Ok(current_exe) = std::env::current_exe() {
        #[cfg(target_os = "macos")]
        {
            if let Ok(bundle) = crate::keychain_share::in_bundle_executable_paths(&current_exe) {
                if bundle.native_host.is_file() {
                    return Some(bundle.native_host);
                }
            }
        }
        if let Some(parent) = current_exe.parent() {
            let candidate_name = if cfg!(windows) {
                "vaultmesh-native-host.exe"
            } else {
                "vaultmesh-native-host"
            };
            let sibling = parent.join(candidate_name);
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn check_macos_browser_installed(browser: &BrowserDefinition, home: &Path) -> bool {
    // 1. Check in /Applications or ~/Applications
    for name in browser.app_names {
        if Path::new("/Applications").join(name).exists() {
            return true;
        }
        if home.join("Applications").join(name).exists() {
            return true;
        }
    }
    // 2. Check Application Support directory
    let support_path = home.join("Library/Application Support").join(browser.app_support_dir);
    if support_path.is_dir() {
        return true;
    }
    false
}

#[cfg(target_os = "macos")]
fn check_macos_manifest_registered(browser: &BrowserDefinition, home: &Path) -> (bool, Option<String>) {
    let manifest_path = home.join("Library/Application Support").join(browser.manifest_subpath);
    if !manifest_path.is_file() {
        return (false, None);
    }
    if let Ok(bytes) = fs::read(&manifest_path) {
        if let Ok(value) = serde_json::from_slice::<Value>(&bytes) {
            let name_matches = value.get("name").and_then(Value::as_str) == Some(BROWSER_HOST_NAME);
            let path_valid = value.get("path").and_then(Value::as_str).is_some_and(|p| !p.is_empty());
            if name_matches && path_valid {
                return (true, Some(manifest_path.display().to_string()));
            }
        }
    }
    (false, Some(manifest_path.display().to_string()))
}

#[cfg(target_os = "macos")]
fn check_macos_extension_installed(browser: &BrowserDefinition, home: &Path) -> bool {
    let support = home.join("Library/Application Support");
    if browser.is_firefox {
        let mozilla_ext = support.join("Mozilla/Extensions");
        if mozilla_ext.exists() {
            if let Ok(entries) = fs::read_dir(&mozilla_ext) {
                for entry in entries.flatten() {
                    if entry.path().join("vaultmesh@atlantis-mk.github.io.xpi").exists() {
                        return true;
                    }
                }
            }
        }
        let firefox_profiles = support.join("Firefox/Profiles");
        if firefox_profiles.is_dir() {
            if let Ok(entries) = fs::read_dir(&firefox_profiles) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.join("extensions/vaultmesh@atlantis-mk.github.io.xpi").exists() {
                        return true;
                    }
                    if let Ok(content) = fs::read_to_string(path.join("extensions.json")) {
                        if content.contains("vaultmesh@atlantis-mk.github.io") {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    // Chromium-based browsers
    let base_dir = support.join(browser.app_support_dir);
    if !base_dir.is_dir() {
        return false;
    }
    // Check Default profile
    if base_dir.join("Default/Extensions").join(DEFAULT_DEVELOPMENT_EXTENSION_ID).is_dir() {
        return true;
    }
    // Check Profile 1, Profile 2, etc.
    if let Ok(entries) = fs::read_dir(&base_dir) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name_str = file_name.to_string_lossy();
            if name_str.starts_with("Profile ") {
                if entry.path().join("Extensions").join(DEFAULT_DEVELOPMENT_EXTENSION_ID).is_dir() {
                    return true;
                }
            }
        }
    }
    false
}

#[cfg(target_os = "windows")]
fn check_windows_browser_installed(browser: &BrowserDefinition) -> bool {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let base = Path::new(&local_app_data);
        match browser.id {
            "chrome" => if base.join("Google/Chrome").is_dir() { return true; },
            "edge" => if base.join("Microsoft/Edge").is_dir() { return true; },
            "brave" => if base.join("BraveSoftware/Brave-Browser").is_dir() { return true; },
            _ => {},
        }
    }
    false
}

pub fn diagnose(state: &RuntimeState, repair: bool) -> Result<Value, String> {
    if repair {
        #[cfg(target_os = "macos")]
        {
            if let Err(err) = crate::browser_host_registration::install_macos_browser_host() {
                eprintln!("doctor repair macos registration error: {err}");
            }
        }
        #[cfg(target_os = "windows")]
        {
            if let Err(err) = crate::browser_host_registration::install_windows_browser_host(&state.app_data) {
                eprintln!("doctor repair windows registration error: {err}");
            }
        }
    }

    let (broker_ready, api_port) = match &state._browser_http_listener {
        Some(listener) if listener.is_healthy() => (true, Some(listener.port())),
        _ => (false, None),
    };

    let host_binary = locate_native_host_binary();
    let host_binary_found = host_binary.is_some();

    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));

    let mut browser_items: Vec<BrowserDoctorItem> = Vec::new();
    for def in BROWSERS {
        #[cfg(target_os = "macos")]
        let (installed, manifest_registered, manifest_path, extension_installed) = {
            let installed = check_macos_browser_installed(def, &home);
            let (reg, path) = check_macos_manifest_registered(def, &home);
            let ext = check_macos_extension_installed(def, &home);
            (installed, reg, path, ext)
        };

        #[cfg(target_os = "windows")]
        let (installed, manifest_registered, manifest_path, extension_installed) = {
            let installed = check_windows_browser_installed(def);
            (installed, false, None, false)
        };

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let (installed, manifest_registered, manifest_path, extension_installed) = (false, false, None, false);

        browser_items.push(BrowserDoctorItem {
            id: def.id.to_string(),
            name: def.name.to_string(),
            installed,
            manifest_registered,
            manifest_path,
            extension_installed,
            store_url: def.store_url.to_string(),
        });
    }

    let registered_count = browser_items.iter().filter(|b| b.manifest_registered).count();
    let installed_browser_count = browser_items.iter().filter(|b| b.installed).count();
    let installed_extension_count = browser_items.iter().filter(|b| b.extension_installed).count();

    // Check items
    let mut check_items = Vec::new();

    // 1. Loopback HTTP API
    if broker_ready {
        check_items.push(DoctorCheckItem {
            id: "loopback-api".to_string(),
            label: "本地回环 API 服务".to_string(),
            status: "ok".to_string(),
            message: format!("服务运行正常（端口: {}）", api_port.unwrap_or(0)),
        });
    } else {
        check_items.push(DoctorCheckItem {
            id: "loopback-api".to_string(),
            label: "本地回环 API 服务".to_string(),
            status: "error".to_string(),
            message: "服务未运行，浏览器扩展无法连接桌面端".to_string(),
        });
    }

    // 2. Native Host binary
    if host_binary_found {
        check_items.push(DoctorCheckItem {
            id: "native-host".to_string(),
            label: "Native Host 中继组件".to_string(),
            status: "ok".to_string(),
            message: "Native Host 无状态中继组件已就绪".to_string(),
        });
    } else {
        check_items.push(DoctorCheckItem {
            id: "native-host".to_string(),
            label: "Native Host 中继组件".to_string(),
            status: "error".to_string(),
            message: "未找到 Native Host 二进制文件".to_string(),
        });
    }

    // 3. Background residence
    check_items.push(DoctorCheckItem {
        id: "background-residence".to_string(),
        label: "后台常驻与开机启动".to_string(),
        status: "ok".to_string(),
        message: "桌面端已支持窗口关闭后台常驻，可通过系统设置配置开机启动".to_string(),
    });

    // 4. Manifest registration
    if registered_count > 0 {
        check_items.push(DoctorCheckItem {
            id: "manifest-registration".to_string(),
            label: "浏览器通信清单 (Manifest)".to_string(),
            status: "ok".to_string(),
            message: format!("已为 {registered_count} 个浏览器就绪 Native Messaging 清单"),
        });
    } else {
        check_items.push(DoctorCheckItem {
            id: "manifest-registration".to_string(),
            label: "浏览器通信清单 (Manifest)".to_string(),
            status: "warn".to_string(),
            message: "尚未检测到已注册的浏览器清单，可点击下方一键修复".to_string(),
        });
    }

    // 5. Extension installation
    if installed_browser_count > 0 && installed_extension_count == 0 {
        check_items.push(DoctorCheckItem {
            id: "extension-install".to_string(),
            label: "浏览器插件安装".to_string(),
            status: "warn".to_string(),
            message: "检测到已安装浏览器但尚未安装 VaultMesh 扩展，可一键前往商店安装".to_string(),
        });
    } else if installed_extension_count > 0 {
        check_items.push(DoctorCheckItem {
            id: "extension-install".to_string(),
            label: "浏览器插件安装".to_string(),
            status: "ok".to_string(),
            message: format!("已在 {installed_extension_count} 个浏览器中检测到 VaultMesh 扩展"),
        });
    } else {
        check_items.push(DoctorCheckItem {
            id: "extension-install".to_string(),
            label: "浏览器插件安装".to_string(),
            status: "ok".to_string(),
            message: "未检测到支持的浏览器或已完成安装".to_string(),
        });
    }

    let host_registered = registered_count > 0;
    let ready = broker_ready && host_binary_found && host_registered;

    let error_code = if !broker_ready {
        Some("broker-unavailable".to_string())
    } else if !host_binary_found {
        Some("host-missing".to_string())
    } else if !host_registered {
        Some("registration-unavailable".to_string())
    } else {
        None
    };

    let report = BrowserDoctorReport {
        supported: true,
        ready,
        broker_ready,
        host_registered,
        extension_id: DEFAULT_DEVELOPMENT_EXTENSION_ID.to_string(),
        error_code,
        api_port,
        check_items,
        browsers: browser_items,
    };

    serde_json::to_value(report).map_err(|e| format!("序列化体检报告失败: {e}"))
}

pub fn handle_open_store(input: Value) -> Result<Value, String> {
    let browser_id = input.get("browserId").and_then(Value::as_str);
    let store_url = match browser_id {
        Some("chrome") => CHROME_STORE_URL,
        Some("edge") | Some("brave") | Some("arc") | Some("vivaldi") | Some("chromium") | Some("firefox") => {
            GITHUB_RELEASE_URL
        }
        _ => {
            if let Some(url) = input.get("storeUrl").and_then(Value::as_str) {
                if url.starts_with("https://chromewebstore.google.com/")
                    || url.starts_with("https://github.com/atlantis-mk/VaultMesh/releases")
                {
                    url
                } else {
                    return Err("非法扩展下载地址。".to_owned());
                }
            } else {
                return Err("未知的浏览器标识。".to_owned());
            }
        }
    };
    open::that_detached(store_url)
        .map(|()| json!({ "opened": true }))
        .map_err(|e| format!("打开扩展下载页面失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_report_schema_roundtrip() {
        let item = BrowserDoctorItem {
            id: "chrome".to_string(),
            name: "Google Chrome".to_string(),
            installed: true,
            manifest_registered: true,
            manifest_path: Some("/tmp/com.vaultmesh.browser.json".to_string()),
            extension_installed: true,
            store_url: "https://chromewebstore.google.com/...".to_string(),
        };
        let check = DoctorCheckItem {
            id: "loopback-api".to_string(),
            label: "本地回环 API 服务".to_string(),
            status: "ok".to_string(),
            message: "服务运行正常".to_string(),
        };
        let report = BrowserDoctorReport {
            supported: true,
            ready: true,
            broker_ready: true,
            host_registered: true,
            extension_id: DEFAULT_DEVELOPMENT_EXTENSION_ID.to_string(),
            error_code: None,
            api_port: Some(42800),
            check_items: vec![check],
            browsers: vec![item],
        };
        let val = serde_json::to_value(&report).unwrap();
        assert_eq!(val["supported"], true);
        assert_eq!(val["apiPort"], 42800);
        assert_eq!(val["browsers"][0]["id"], "chrome");
    }

    #[test]
    fn supported_browsers_cover_all_seven_targets() {
        let ids: Vec<&str> = BROWSERS.iter().map(|b| b.id).collect();
        assert_eq!(ids, vec!["chrome", "edge", "brave", "arc", "vivaldi", "chromium", "firefox"]);
        for b in BROWSERS {
            if b.id == "chrome" {
                assert!(b.store_url.contains("chromewebstore.google.com"));
            } else {
                assert!(b.store_url.contains("github.com/atlantis-mk/VaultMesh/releases/tag/v0.1.7-review"));
            }
        }
    }

    #[test]
    fn handle_open_store_validates_known_ids_and_urls() {
        assert!(handle_open_store(json!({ "browserId": "chrome" })).is_ok());
        assert!(handle_open_store(json!({ "browserId": "firefox" })).is_ok());
        // Unknown browser id without storeUrl fails
        assert!(handle_open_store(json!({ "browserId": "unknown" })).is_err());
        // Non-whitelisted storeUrl fails
        assert!(handle_open_store(json!({ "storeUrl": "https://malicious.site" })).is_err());
    }
}
