import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const read = (path) => fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('CT-ANDROID-JNI-001: launcher uses the desktop-inspired transparent PNG on a white adaptive background', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android:icon="@mipmap\/ic_launcher"/);
  assert.match(manifest, /android:roundIcon="@mipmap\/ic_launcher"/);
  const icon = read('apps/android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml');
  assert.match(icon, /<background android:drawable="@android:color\/white"/);
  assert.match(icon, /<foreground android:drawable="@drawable\/ic_launcher_foreground"/);
  const foreground = read('apps/android/app/src/main/res/drawable/ic_launcher_foreground.xml');
  assert.match(foreground, /android:src="@mipmap\/ic_launcher_artwork"/);
  const png = fs.readFileSync(new URL('../apps/android/app/src/main/res/mipmap-nodpi/ic_launcher_artwork.png', import.meta.url));
  assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  assert.equal(png[25], 6, 'Launcher PNG must retain RGBA transparency');
});

test('CT-ANDROID-JNI-001/CT-ANDROID-LAN-PAIRING-001: manifest keeps Vault storage private and confines LAN access', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android:allowBackup="false"/);
  assert.match(manifest, /android:fullBackupContent="false"/);
  assert.match(manifest, /android:usesCleartextTraffic="false"/);
  assert.doesNotMatch(manifest, /android\.permission\.(READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE)/);
  assert.match(manifest, /android\.permission\.INTERNET/);
  assert.match(manifest, /android\.permission\.ACCESS_LOCAL_NETWORK/);
  assert.match(manifest, /android\.permission\.CHANGE_WIFI_MULTICAST_STATE/);
  assert.match(manifest, /android\.permission\.USE_BIOMETRIC/);

  const extraction = read('apps/android/app/src/main/res/xml/data_extraction_rules.xml');
  assert.match(extraction, /<cloud-backup[\s\S]*<exclude domain="file" path="\."/);
  assert.match(extraction, /<device-transfer>[\s\S]*<exclude domain="file" path="\."/);
});

test('CT-ANDROID-JNI-001: debug install is isolated from the product application data', () => {
  const build = read('apps/android/app/build.gradle.kts');
  assert.match(build, /debug\s*\{[\s\S]*applicationIdSuffix\s*=\s*"\.debug"/);
  assert.match(build, /release\s*\{[\s\S]*isMinifyEnabled\s*=\s*true/);
});

test('CT-ANDROID-JNI-001: activity locks on background and protects its window', () => {
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /window\.addFlags\(WindowManager\.LayoutParams\.FLAG_SECURE\)/);
  assert.match(activity, /private fun lockForLeavingForeground\(\)[\s\S]*viewModel\.lock\(\)/);
  assert.match(activity, /override fun onPause\(\)\s*\{\s*lockForLeavingForeground\(\)\s*super\.onPause\(\)/);
  assert.match(activity, /override fun onStop\(\)[\s\S]*lockForLeavingForeground\(\)\s*super\.onStop\(\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun lock\(\)[\s\S]*markLocked\(\)[\s\S]*synchronized\(nativeCallGate\)[\s\S]*VaultNativeBridge\.lock\(\)/);
  assert.match(activity, /VaultNativeBridge\.initialize\(filesDir\.absolutePath\)/);
});

test('CT-ANDROID-JNI-001: password submit owns the bounded spinner inside the button', () => {
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const locked = activity.slice(activity.indexOf('private fun LockedVaultScreen('),
    activity.indexOf('private fun RestoreBackupDialog('));
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  const submit = viewModel.slice(viewModel.indexOf('private fun submit('),
    viewModel.indexOf('private suspend fun finishMutation('));
  assert.match(locked, /Button\([\s\S]*modifier = Modifier\.fillMaxWidth\(\)\.height\(52\.dp\)/);
  assert.match(locked, /Row\([\s\S]*horizontalArrangement = Arrangement\.Center[\s\S]*if \(state\.authenticating\) \{[\s\S]*CircularProgressIndicator\([\s\S]*Modifier\.size\(18\.dp\)/);
  assert.doesNotMatch(locked, /if \(state\.busy\) \{\s*CircularProgressIndicator/);
  assert.match(submit, /copy\(password = "", busy = true, authenticating = true/);
  assert.match(submit, /authenticating = false/);
  assert.match(viewModel, /private fun endOperation\(\)[\s\S]*copy\(busy = false, authenticating = false, loadingPhase = null\)/);
});

test('CT-ANDROID-JNI-001: successful unlock shows summary loading before the list is read', () => {
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  const submit = viewModel.slice(viewModel.indexOf('private fun submit('),
    viewModel.indexOf('private suspend fun finishMutation('));
  const finish = viewModel.slice(viewModel.indexOf('private suspend fun finishMutation('),
    viewModel.indexOf('private fun performMutation('));
  for (const operation of [submit, finish]) {
    const loading = operation.indexOf('showSummaryLoadingAfterUnlock(result, generation)');
    const read = operation.indexOf('readVaultState()');
    assert.ok(loading >= 0 && read > loading);
    assert.match(operation, /loadingPhase = null/);
  }
  assert.match(viewModel, /result != "ok"[\s\S]*status == "unlocked"\) return[\s\S]*loadingPhase = VaultLoadingPhase\.Summaries/);
  assert.match(viewModel, /fun unlockWithBiometricSecret\([\s\S]*loadingPhase = VaultLoadingPhase\.Opening/);
  assert.match(viewModel, /fun unlockWithPin\([\s\S]*loadingPhase = VaultLoadingPhase\.Opening/);
  assert.match(viewModel, /mutableState\.value = VaultUiState\(status = "locked"/);
  assert.match(activity, /state\.loadingPhase != null -> VaultLoadingScreen\(state\.loadingPhase\)[\s\S]*state\.status == "unlocked" -> UnlockedVaultScreen/);
  assert.match(activity, /private fun VaultLoadingScreen\([\s\S]*CircularProgressIndicator\(\)[\s\S]*正在打开保险库[\s\S]*正在加载保险库条目/);
  assert.match(activity, /private fun unlockWithPin\(\)[\s\S]*viewModel\.beginOpeningVault\(\)[\s\S]*pinUnlock\.readDeviceSecret/);
});

test('CT-ANDROID-JNI-001: unlocked navigation keeps item types and privileged actions reachable', () => {
  const home = read('apps/android/app/src/main/java/com/vaultmesh/app/UnlockedHomeUi.kt');
  const itemUi = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  const row = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultEntryRow.kt');
  assert.match(home, /Vault\("保险库"[\s\S]*Tools\("工具"[\s\S]*Devices\("设备"[\s\S]*Settings\("设置"/);
  assert.match(home, /NavigationBar\([\s\S]*NavigationBarItem\(/);
  assert.match(home, /topBar = \{[\s\S]*UnlockedHomeTopBar/);
  assert.match(home, /internal fun UnlockedHomeTopBar[\s\S]*modifier = Modifier\.statusBarsPadding\(\)\.fillMaxWidth\(\)/);
  for (const type of ['Logins', 'Cards', 'Identities', 'Ssh', 'Secrets']) {
    assert.match(home, new RegExp(`VaultSection\\.${type} to`));
  }
  assert.match(home, /viewModel\.showSection\(selectedCategory \?: VaultSection\.Logins\)[\s\S]*destination = item/);
  assert.match(home, /overviewEntries\(state\)/);
  assert.match(home, /viewModel::requestPasswordHealth/);
  assert.match(home, /viewModel::beginGenerator/);
  assert.match(home, /viewModel::beginPasswordRotation/);
  assert.match(home, /onBackup[\s\S]*onRestore[\s\S]*onNearby/);
  assert.match(home, /viewModel\.showTrashFor\(currentType\)/);
  assert.match(row, /DropdownMenu\(expanded = copyExpanded[\s\S]*DropdownMenu\(expanded = moreExpanded/);
  assert.match(row, /Checkbox\(checked = selected/);
  assert.match(home, /"全选本页"[\s\S]*"已选择 \$\{selected\.size\} 项"[\s\S]*confirmBatchDelete/);
  assert.match(itemUi, /if \(item\.managed\) null else onToggle/);
});

test('CT-ANDROID-HOME-001: every vault list reveals 30 summaries per scroll batch', () => {
  const home = read('apps/android/app/src/main/java/com/vaultmesh/app/UnlockedHomeUi.kt');
  const other = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  assert.match(home, /VAULT_PAGE_SIZE = 30/);
  assert.match(home, /remember\(selectedCategory, state\.section, state\.query\)[\s\S]*mutableIntStateOf\(VAULT_PAGE_SIZE\)/);
  assert.match(home, /snapshotFlow \{ listState\.layoutInfo\.visibleItemsInfo\.lastOrNull\(\)\?\.index[\s\S]*visibleCount \+ VAULT_PAGE_SIZE/);
  assert.match(home, /overview\.take\(visibleCount\)/);
  assert.match(home, /logins\.take\(visibleCount\)/);
  assert.match(home, /trash\.take\(visibleCount\)/);
  for (const type of ['cards', 'ssh', 'identities', 'secrets', 'trash']) {
    assert.match(other, new RegExp(`${type}\\.take\\(visibleCount\\)`));
  }
  assert.match(home, /selectable[\s\S]*take\(visibleCount\)[\s\S]*"全选本页"/);
  assert.match(home, /fun VaultLoadMoreFooter\(\)[\s\S]*加载更多/);
});

test('CT-ANDROID-JNI-001/004/005/006/007/008/009/010/011/012/013/014/015/016/017/018 and CT-ANDROID-LAN-PAIRING-001: JNI exposes only fixed operations', () => {
  const bridge = read('crates/vault-android-runtime/src/jni_bridge.rs');
  const exports = [...bridge.matchAll(/Java_com_vaultmesh_app_VaultNativeBridge_([A-Za-z]+)/g)].map((match) => match[1]);
  assert.deepEqual(exports, [
    'initialize', 'status', 'create', 'unlock', 'changeMasterPassword',
    'prepareBiometricUnlock', 'unlockWithBiometricSecret', 'disableBiometricUnlock',
    'pinStatus', 'enablePinUnlock', 'unlockWithPin', 'disablePinUnlock',
    'prepareEncryptedBackup', 'restoreStagedBackup', 'lock',
    'lanOpen', 'lanStatus', 'lanStart', 'lanStop', 'lanBegin', 'lanClose', 'lanRevoke', 'lanRename',
    'listLogins', 'addLogin', 'updateLogin', 'addLoginComplete', 'updateLoginComplete', 'deleteLogin',
    'listTrash', 'restoreLogin', 'purgeLogin', 'emptyTrash',
    'listLoginHistory', 'restoreLoginRevision', 'clearLoginHistory',
    'listCardHistory', 'restoreCardRevision', 'clearCardHistory',
    'listSshHistory', 'restoreSshRevision', 'clearSshHistory',
    'listIdentityHistory', 'restoreIdentityRevision', 'clearIdentityHistory',
    'setLoginTotp', 'copyLoginTotpCode', 'setLoginRecoveryCodes',
    'viewLoginRecoveryCodes', 'copyLoginRecoveryCode', 'passwordHealth',
    'cardEditorDetail', 'loginEditorDetail', 'secretEditorDetail', 'sshEditorDetail', 'identityEditorDetail',
    'listCards', 'deleteCard', 'listCardTrash', 'restoreCard', 'purgeCard', 'emptyCardTrash',
    'listSsh', 'deleteSsh', 'listSshTrash', 'restoreSsh', 'purgeSsh', 'emptySshTrash',
    'listIdentities', 'deleteIdentity', 'listIdentityTrash', 'restoreIdentity',
    'purgeIdentity', 'emptyIdentityTrash', 'listSecrets', 'deleteSecret',
    'copyLoginPassword', 'copyCardNumber', 'copyCardSecurityCode', 'copyCardPin',
    'copySshPassword', 'copySshPublicKey', 'copySshPrivateKey',
    'copySshKeyPassphrase', 'copySecretValue',
    'addCard', 'addCardComplete', 'updateCard', 'updateCardComplete',
    'addSsh', 'updateSsh', 'addSshComplete', 'updateSshComplete', 'identityBasic', 'addIdentity',
    'updateIdentity', 'addIdentityComplete', 'updateIdentityComplete',
    'addSecret', 'addSecretComplete', 'updateSecret', 'updateSecretComplete',
  ]);
  assert.doesNotMatch(bridge, /Box::into_raw|from_raw|method_name|operation_name/);

  const kotlin = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultNativeBridge.kt');
  const nativeApi = kotlin.slice(kotlin.indexOf('@JvmStatic external'), kotlin.indexOf('fun decodeLogins'));
  assert.doesNotMatch(nativeApi.replace('lanOpen(wrappingKey: ByteArray)', '').replace('syncOpen(wrappingKey: ByteArray)', '').replace('assistOpen(wrappingKey: ByteArray)', '').replace('age: Long, dedup: String', 'dedup: String'), /Long\s*[),:]|ByteArray/);
  assert.match(kotlin, /System\.loadLibrary\("vaultmesh_android_runtime"\)/);
});

test('CT-ANDROID-LAN-PAIRING-001: devices tab owns the paired list without a dialog or discovery prerequisite', () => {
  const home = read('apps/android/app/src/main/java/com/vaultmesh/app/UnlockedHomeUi.kt');
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const ui = read('apps/android/app/src/main/java/com/vaultmesh/app/LanPairingUi.kt');
  const devices = home.slice(home.indexOf('HomeDestination.Devices ->'), home.indexOf('HomeDestination.Settings ->'));
  assert.match(devices, /DisposableEffect\(Unit\)[\s\S]*onNearby\(\)[\s\S]*onDispose \{ onLeaveNearby\(\) \}/);
  assert.match(devices, /nearbyContent\(Modifier.padding\(padding\)\)/);
  assert.doesNotMatch(devices, /HomeActionCard|打开附近设备/);
  assert.match(activity, /onNearby, onLocked, nearbyContent/);
  assert.match(activity, /nearbyContent = \{ modifier ->[\s\S]*LanDevicesPage\(/);
  const page = ui.slice(0, ui.indexOf("if (settingsPeer != null && !hasDialog)"));
  assert.doesNotMatch(page, /AlertDialog|Dialog\(/);
  assert.match(page, /status.trusted.isEmpty\(\)/);
  assert.match(page, /status.trusted.forEachIndexed[\s\S]*TrustedDeviceRow/);
  assert.match(ui, /private fun TrustedDeviceRow[\s\S]*peer.label[\s\S]*IconButton\(onClick = onSettings/);
  assert.match(ui, /settingsPeer != null && !hasDialog[\s\S]*AlertDialog[\s\S]*deviceSettings\(settingsPeer\)/);
  assert.match(ui, /settingsPeer == null\) settingsRef = null/);
  const sync = read('apps/android/app/src/main/java/com/vaultmesh/app/LanSyncUi.kt');
  assert.doesNotMatch(sync.slice(sync.indexOf('internal fun LanSyncPanel'), sync.indexOf('internal fun LanSyncPeerSettings')), /Switch\(/);
  const assist = read('apps/android/app/src/main/java/com/vaultmesh/app/DeviceAssistUi.kt');
  assert.match(assist, /if \(settingsPeer != null\)[\s\S]*val peer = settingsPeer[\s\S]*assistGrant\(peer.pairingRef/);
  assert.doesNotMatch(assist, /peers.forEach/);
  assert.match(ui, /onClick = onReload[\s\S]*重新加载/);
  assert.match(ui, /panel.pairingRef != null[\s\S]*AlertDialog[\s\S]*panel.canBeginPairing/);
  assert.match(ui, /panel.renameRef != null[\s\S]*AlertDialog[\s\S]*重命名设备/);
  assert.match(ui, /panel.revokeRef != null[\s\S]*AlertDialog[\s\S]*撤销与此设备的配对/);
  assert.match(activity, /lanPanel = panel.copy\(codeInput = "", pairingPending = true\)/);
  assert.match(activity, /lanPanel\?\.withStatus\(next\)/);
  const open = activity.slice(activity.indexOf('private fun openLanPanel()'), activity.indexOf('private fun lanError('));
  assert.match(open, /VaultNativeBridge.lanOpen\(key\)/);
  assert.doesNotMatch(open, /lanStart\(|startLanDiscovery\(/);
});

test('CT-ANDROID-LAN-PAIRING-001: Android shares protocol and closes discovery with foreground authorization', () => {
  const pairing = read('crates/vault-android-runtime/src/lan_pairing.rs');
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const shared = read('crates/vault-lan-pairing/src/lib.rs');
  const credentials = read('crates/vault-android-runtime/src/lan_credentials.rs');
  assert.match(pairing, /LanPairingService::new_with_credentials/);
  assert.match(pairing, /sync_authorize_peer\(&peer, &fingerprint, true\)/);
  assert.match(shared, /const PROTOCOL_TXT: &str = "2\.0"/);
  assert.match(shared, /spake2_conflux/);
  assert.match(credentials, /XChaCha20Poly1305/);
  assert.match(activity, /override fun onPause\(\)[\s\S]*lockForLeavingForeground\(\)/);
  assert.match(activity, /lockForLeavingForeground\(\)[\s\S]*closeLanPanel\(\)/);
  assert.match(activity, /ACCESS_LOCAL_NETWORK/);
  assert.match(activity, /releaseLanMulticast\(\)/);
});

test('CT-ANDROID-JNI-018: PIN uses Keystore sealed device secret, core wrapping and persistent failure limit', () => {
  const native = read('crates/vault-android-runtime/src/pin_unlock.rs');
  assert.match(native, /session\.quick_unlock_key\(\)/);
  assert.match(native, /scrypt\(/);
  assert.match(native, /FAILURE_LIMIT: u8 = 5/);
  assert.match(native, /self\.save_pin_record\(&record\)\?/);
  assert.match(native, /VaultSession::unlock_with_vault_key/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/PinUnlockService.kt');
  assert.match(service, /AndroidKeyStore/);
  assert.match(service, /AES\/GCM\/NoPadding/);
  assert.match(service, /ATOMIC_MOVE/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /pinDraft = ""[\s\S]*viewModel\.lock\(\)/);
  assert.match(activity, /pinUnlock\.readDeviceSecret\(\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /VaultNativeBridge\.unlockWithPin\(pin, deviceSecret\)/);
});

test('CT-ANDROID-JNI-017: biometric quick unlock keeps Vault Key in Rust and binds Keystore crypto to a prompt', () => {
  const native = read('crates/vault-android-runtime/src/quick_unlock.rs');
  assert.match(native, /session\.quick_unlock_key\(\)/);
  assert.match(native, /XChaCha20Poly1305/);
  assert.match(native, /VaultSession::unlock_with_vault_key/);
  assert.match(native, /MAX_RECORD_BYTES: u64 = 4096/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/BiometricUnlockService.kt');
  assert.match(service, /setUserAuthenticationRequired\(true\)/);
  assert.match(service, /setInvalidatedByBiometricEnrollment\(true\)/);
  assert.match(service, /AUTH_BIOMETRIC_STRONG/);
  assert.match(service, /AES\/GCM\/NoPadding/);
  assert.match(service, /ATOMIC_MOVE/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /BiometricPrompt\.CryptoObject\(cipher\)/);
  assert.match(activity, /private fun lockForLeavingForeground\(\)[\s\S]*biometricPrompt\?\.cancelAuthentication\(\)[\s\S]*viewModel\.lock\(\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun prepareBiometricUnlock\([\s\S]*VaultNativeBridge::prepareBiometricUnlock/);
  assert.match(viewModel, /fun unlockWithBiometricSecret\([\s\S]*VaultNativeBridge\.unlockWithBiometricSecret\(secret\)/);
});

test('CT-ANDROID-JNI-017/018: locked UI presents one method and auto-prompts only once per foreground visit', () => {
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const locked = activity.slice(activity.indexOf('private fun LockedVaultScreen('),
    activity.indexOf('private fun RestoreBackupDialog('));
  assert.match(activity, /override fun onResume\(\)[\s\S]*unlockForegroundReady = true/);
  const resumed = activity.slice(activity.indexOf('override fun onResume()'), activity.indexOf('private val requestLocalNetworkPermission'));
  assert.match(resumed, /if \(!pinStatusReady\) refreshPinStatus\(\)/);
  assert.match(activity, /override fun onStart\(\)[\s\S]*foregroundVisit \+= 1/);
  assert.doesNotMatch(resumed, /foregroundVisit \+= 1/);
  assert.match(activity, /autoBiometricVisit == foregroundVisit[\s\S]*biometricFlow == null\) showUnlockFallback\(\)/);
  assert.match(activity, /autoBiometricVisit = foregroundVisit[\s\S]*unlockWithBiometric\(\)/);
  assert.match(activity, /onAuthenticationSucceeded\(result: BiometricPrompt.AuthenticationResult\) \{\s*if \(generation != foregroundGeneration\) return/);
  assert.match(activity, /onAuthenticationError\(errorCode: Int, errString: CharSequence\) \{\s*if \(generation != foregroundGeneration\) return/);
  assert.match(activity, /onAuthenticationError\([\s\S]*showUnlockFallback\(\)/);
  assert.match(activity, /lockForLeavingForeground\(\)[\s\S]*unlockForegroundReady = false/);
  assert.match(locked, /if \(state\.status == "locked" && unlockMethod == UnlockMethod\.BiometricPending\) return/);
  assert.match(locked, /if \(pinActive\) \{[\s\S]*repeat\(6\)[\s\S]*onPinDigit\(key\)/);
  assert.match(activity, /private fun enterPinDigit\([\s\S]*pinDraft \+= digit[\s\S]*if \(pinDraft\.length == 6\) unlockWithPin\(\)/);
  assert.match(locked, /\} else \{[\s\S]*OutlinedTextField\([\s\S]*label = \{ Text\(if \(state\.status == "missing"\) "设置主密码" else "主密码"\)/);
  assert.match(locked, /Text\("其他解锁方式"\)[\s\S]*Text\("选择解锁方式"\)/);
});

test('CT-ANDROID-JNI-016: Login regular fields use explicit editor and preserve protected values', () => {
  const runtime = read('crates/vault-android-runtime/src/login_fields.rs');
  const editor = runtime.match(/pub struct AndroidLoginExtras \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(editor, /additional_urls: Vec<String>/);
  assert.match(editor, /custom_fields: Vec<AndroidLoginCustomField>/);
  assert.doesNotMatch(editor, /pub (?:password|totp_secret|recovery_codes):/);
  assert.match(runtime, /parse_login_extras_json[\s\S]*512 \* 1024/);
  assert.match(runtime, /pub fn login_editor_detail\([\s\S]*session\.item_detail\(id\)/);
  assert.match(runtime, /pub fn update_login_complete\([\s\S]*totp_secret: None[\s\S]*recovery_codes: None/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun beginEditLogin\([\s\S]*VaultNativeBridge\.loginEditorDetail\(item\.id\)/);
  assert.match(viewModel, /VaultNativeBridge\.addLoginComplete/);
  assert.match(viewModel, /VaultNativeBridge\.updateLoginComplete/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /Text\("附加网址"/);
  assert.match(activity, /Text\("自定义字段"/);
});

test('CT-ANDROID-JNI-015: complete Identity editing keeps child IDs and validates bounded structured input', () => {
  const runtime = read('crates/vault-android-runtime/src/items.rs');
  assert.match(runtime, /pub struct AndroidIdentityInput \{[\s\S]*emails: Vec<AndroidIdentityContact>[\s\S]*addresses: Vec<AndroidIdentityAddress>/);
  assert.match(runtime, /pub struct AndroidIdentityContact \{[\s\S]*pub id: Uuid/);
  assert.match(runtime, /pub struct AndroidIdentityAddress \{[\s\S]*pub id: Uuid/);
  assert.match(runtime, /parse_identity_input_json[\s\S]*256 \* 1024/);
  assert.match(runtime, /pub fn identity_editor_detail\([\s\S]*session\.identity_detail\(id\)/);
  assert.match(runtime, /pub fn add_identity_complete\([\s\S]*self\.mutate_and_commit/);
  assert.match(runtime, /pub fn update_identity_complete\([\s\S]*self\.mutate_and_commit/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun beginIdentity\([\s\S]*VaultNativeBridge\.identityEditorDetail\(item\.id\)/);
  assert.match(viewModel, /VaultNativeBridge\.addIdentityComplete/);
  assert.match(viewModel, /VaultNativeBridge\.updateIdentityComplete/);
  const ui = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  assert.match(ui, /IdentityContactsEditor\("电子邮件"/);
  assert.match(ui, /IdentityAddressesEditor\(draft\.addresses\)/);
});

test('CT-ANDROID-JNI-014: SSH extras stay in explicit editor and managed aliases remain read-only', () => {
  const runtime = read('crates/vault-android-runtime/src/items.rs');
  const editor = runtime.match(/pub struct AndroidSshExtras \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(editor, /notes: Option<String>/);
  assert.match(editor, /master_password_reprompt: bool/);
  assert.doesNotMatch(editor, /pub (?:password|public_key|private_key|key_passphrase):/);
  assert.match(runtime, /pub fn ssh_editor_detail\([\s\S]*managed_ssh_alias\.is_some\(\)/);
  assert.match(runtime, /pub fn update_ssh_complete\([\s\S]*managed_ssh_alias\.is_some\(\)/);
  assert.match(runtime, /parse_ssh_extras_json[\s\S]*128 \* 1024/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun beginSsh\([\s\S]*VaultNativeBridge\.sshEditorDetail\(item\.id\)/);
  assert.match(viewModel, /VaultNativeBridge\.addSshComplete/);
  assert.match(viewModel, /VaultNativeBridge\.updateSshComplete/);
  const ui = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  assert.match(ui, /EditorField\(draft\.notes, "备注"/);
  assert.match(ui, /EditorField\(draft\.folder, "文件夹"/);
});

test('CT-ANDROID-JNI-013: Secret extras are explicit and Passkeys stay excluded', () => {
  const runtime = read('crates/vault-android-runtime/src/items.rs');
  const editor = runtime.match(/pub struct AndroidSecretExtras \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(editor, /scopes: Vec<String>/);
  assert.match(editor, /master_password_reprompt: bool/);
  assert.doesNotMatch(editor, /secret: String|value: String/);
  assert.match(runtime, /pub fn secret_editor_detail\([\s\S]*current\.is_passkey/);
  assert.match(runtime, /pub fn add_secret_complete\([\s\S]*self\.mutate_and_commit/);
  assert.match(runtime, /pub fn update_secret_complete\([\s\S]*current\.is_passkey[\s\S]*session\.update_secret/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun beginSecret\([\s\S]*VaultNativeBridge\.secretEditorDetail\(item\.id\)/);
  assert.match(viewModel, /VaultNativeBridge\.addSecretComplete/);
  assert.match(viewModel, /VaultNativeBridge\.updateSecretComplete/);
  const ui = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  assert.match(ui, /EditorField\(draft\.scopes, "Scopes（每行一个）"/);
  assert.match(ui, /EditorField\(draft\.notes, "备注"/);
});

test('CT-ANDROID-JNI-012: card extras stay in explicit editor and commit atomically', () => {
  const runtime = read('crates/vault-android-runtime/src/items.rs');
  const editor = runtime.match(/pub struct AndroidCardExtras \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(editor, /billing_address: Option<String>/);
  assert.match(editor, /master_password_reprompt: bool/);
  assert.doesNotMatch(editor, /card_number|security_code|pin:/);
  assert.match(runtime, /pub fn card_editor_detail\([\s\S]*session\.card_detail\(id\)/);
  assert.match(runtime, /pub fn add_card_complete\([\s\S]*self\.mutate_and_commit/);
  assert.match(runtime, /pub fn update_card_complete\([\s\S]*self\.mutate_and_commit/);
  assert.match(runtime, /deny_unknown_fields/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun beginCard\([\s\S]*VaultNativeBridge\.cardEditorDetail\(item\.id\)/);
  assert.match(viewModel, /request != editorRequestGeneration/);
  assert.match(viewModel, /VaultNativeBridge\.addCardComplete/);
  assert.match(viewModel, /VaultNativeBridge\.updateCardComplete/);
  const ui = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  assert.match(ui, /EditorField\(draft\.billingAddress, "账单地址"/);
  assert.match(ui, /EditorField\(draft\.notes, "备注"/);
});

test('CT-ANDROID-JNI-011: recovery codes require fresh password and document cleanup follows save', () => {
  const runtime = read('crates/vault-android-runtime/src/recovery.rs');
  assert.match(runtime, /recovery_codes_for_access\(id, Some\(master_password\)\)/);
  assert.match(runtime, /self\.mutate_and_commit/);
  assert.match(runtime, /MAX_INPUT_BYTES: usize = 32 \* 1024/);
  const summary = read('crates/vault-android-runtime/src/lib.rs');
  assert.match(summary, /has_recovery_codes: item\.has_recovery_codes/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/RecoveryDocumentService.kt');
  assert.match(service, /uri\.scheme != "content"/);
  assert.match(service, /CodingErrorAction\.REPORT/);
  assert.match(service, /digest\.contentEquals\(expectedDigest\)/);
  assert.match(service, /FLAG_SUPPORTS_DELETE/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /recoveryPickerTarget[\s\S]*viewModel\.cancelRecovery\(\)/);
  assert.match(activity, /inputDigest\.contentEquals\(source\.digest\)/);
  assert.match(activity, /title = \{ Text\("删除导入的源文件？"\) \}/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun submitRecoveryView\([\s\S]*viewPassword = "", codes = emptyList\(\)/);
  assert.match(viewModel, /fun submitRecoveryCopy\([\s\S]*copyPassword = ""/);
  assert.match(viewModel, /fun showSection\([\s\S]*recovery = null/);
});

test('CT-ANDROID-JNI-010: health projection never returns passwords', () => {
  const health = read('crates/vault-android-runtime/src/health.rs');
  const summary = health.match(/pub struct AndroidPasswordHealth \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(summary, /score: u32/);
  assert.match(summary, /weak_item_ids: Vec<String>/);
  assert.doesNotMatch(summary, /password|hash|length|secret/i);
  assert.match(health, /session\.password_health\(now\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun requestPasswordHealth\(\)[\s\S]*runCurrentOperation\(generation, VaultNativeBridge::passwordHealth\)/);
  assert.match(viewModel, /generation != lifecycleGeneration \|\| mutableState\.value\.health\?\.requestId != requestId/);
  assert.match(viewModel, /fun showSection\([\s\S]*health = null/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /LazyColumn\(modifier = Modifier\.heightIn\(max = 400\.dp\)/);
});

test('CT-ANDROID-GENERATOR-001: generated values remain transient and use secure random', () => {
  const generator = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidCredentialGenerator.kt');
  assert.match(generator, /SecureRandom\(\)/);
  assert.match(generator, /for \(index in characters\.lastIndex downTo 1\)/);
  assert.match(generator, /random\.nextInt\(index \+ 1\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun copyGeneratedCredential\(\)[\s\S]*protectedClipboard\.writeResponse/);
  assert.match(viewModel, /fun applyGeneratedCredential\(\)[\s\S]*editor\.copy\(password = draft\.result\)/);
  assert.match(viewModel, /fun showSection\([\s\S]*generator = null/);
  assert.match(viewModel, /private fun markLocked\(\)[\s\S]*VaultUiState\(status = "locked"/);
});

test('CT-ANDROID-JNI-009: backup uses fixed encrypted staging and validates before replacement', () => {
  const runtime = read('crates/vault-android-runtime/src/lib.rs');
  const restore = runtime.match(/pub fn restore_staged_backup\([\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(restore, /read_vault\([\s\S]*BACKUP_IMPORT_STAGE_FILE_NAME/);
  assert.match(restore, /VaultSession::unlock\(master_password, &encrypted\)/);
  assert.match(restore, /sync_reset_after_restore\(\)/);
  assert.match(restore, /sync_checkpoint\(0\)/);
  assert.match(restore, /write_vault\(&self\.vault_path, &replacement\)\?;[\s\S]*replace_session\(candidate\)/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/BackupDocumentService.kt');
  assert.match(service, /uri\.scheme != "content"/);
  assert.match(service, /MAX_VAULT_BYTES/);
  assert.match(service, /openOutputStream\(uri, "wt"\)/);
  assert.match(service, /MessageDigest\.isEqual\(expected, actual\)/);
  assert.match(service, /StandardCopyOption\.ATOMIC_MOVE/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /ActivityResultContracts\.CreateDocument/);
  assert.match(activity, /ActivityResultContracts\.OpenDocument/);
  assert.match(activity, /title = \{ Text\("替换本机保险库？"\) \}/);
});

test('CT-ANDROID-JNI-008: TOTP seed stays in core and code copy requires fresh password', () => {
  const runtime = read('crates/vault-android-runtime/src/lib.rs');
  assert.match(runtime, /has_totp_secret: item\.has_totp_secret/);
  assert.match(runtime, /pub fn set_login_totp\([\s\S]*self\.mutate_and_commit/);
  assert.match(runtime, /totp_secret: std::mem::take\(&mut \*secret\)/);
  const protectedAccess = read('crates/vault-android-runtime/src/protected.rs');
  assert.match(protectedAccess, /pub fn copy_login_totp_code\([\s\S]*session\.verify_master_password\(master_password\)/);
  assert.match(protectedAccess, /totp_code_for_access\(id, unix_time, Some\(master_password\)\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /copy\(totp = null, busy = true/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /VaultRowAction\("验证码"\)[\s\S]*ProtectedCopyField\.LoginTotpCode/);
  assert.match(activity, /移除现有 TOTP 密钥/);
});

test('CT-ANDROID-JNI-007: history stays redacted and destructive actions require confirmation', () => {
  const history = read('crates/vault-android-runtime/src/history.rs');
  assert.match(history, /pub struct AndroidRevisionSummary/);
  assert.doesNotMatch(history.slice(history.indexOf('pub struct AndroidRevisionSummary'), history.indexOf('fn parse_id')), /password|secret|private_key|card_number/i);
  assert.match(history, /session\.restore_ssh_revision\(id, revision_id\)/);
  assert.match(history, /managed_ssh_alias\s*\.is_some\(\)/);
  assert.match(history, /self\.mutate_and_commit/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /if \(generation != lifecycleGeneration \|\| mutableState\.value\.history\?\.target != target\) return@launch/);
  assert.match(viewModel, /fun confirmRestoreRevision\(\)[\s\S]*restoreLoginRevision/);
  assert.match(viewModel, /fun confirmClearHistory\(\)[\s\S]*clearLoginHistory/);
  assert.match(viewModel, /fun showSection\([\s\S]*history = null/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /title = \{ Text\("恢复历史版本？"\) \}/);
  assert.match(activity, /title = \{ Text\("清空历史？"\) \}/);
});

test('CT-ANDROID-JNI-006: protected copy reauthenticates and keeps values out of UI state', () => {
  const runtime = read('crates/vault-android-runtime/src/protected.rs');
  assert.match(runtime, /session\.verify_master_password\(master_password\)/);
  assert.match(runtime, /session\.secret_detail\(id\)\?\.is_passkey/);
  assert.match(runtime, /MAX_COPY_BYTES/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/ProtectedClipboardService.kt');
  assert.match(service, /ClipDescription\.EXTRA_IS_SENSITIVE/);
  assert.match(service, /fun currentLabel\(\): String\?/);
  assert.match(service, /currentLabel\(\) == label/);
  assert.match(service, /handler\.postDelayed\(clear, 30_000\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /copy\(protectedCopy = null, busy = true/);
  assert.match(viewModel, /if \(generation != lifecycleGeneration\) \{[\s\S]*return@launch[\s\S]*\}[\s\S]*protectedClipboard\.writeResponse/);
  assert.doesNotMatch(viewModel, /val .*Value: String/);
});

test('CT-ANDROID-REVEAL-001: explicit reveal uses field access and expires from transient UI', () => {
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /fun requestProtectedReveal\([\s\S]*LoginTotpCode\) return/);
  assert.match(viewModel, /fun submitProtectedReveal\([\s\S]*masterPassword = ""[\s\S]*protectedClipboard\.readValue/);
  assert.match(viewModel, /delay\(30_000\)[\s\S]*closeProtectedReveal\(\)/);
  assert.match(viewModel, /generation != lifecycleGeneration \|\|[\s\S]*protectedReveal\?\.requestId != requestId/);
  assert.match(viewModel, /fun showSection\([\s\S]*protectedReveal = null/);
  assert.match(viewModel, /private fun markLocked\([\s\S]*VaultUiState\(status = "locked"/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /WindowManager\.LayoutParams\.FLAG_SECURE/);
  assert.match(activity, /private fun ProtectedRevealDialog\(/);
  assert.match(activity, /30 秒后自动关闭/);
  const items = read('apps/android/app/src/main/java/com/vaultmesh/app/AndroidItemsUi.kt');
  assert.match(items, /onReveal = \{ field -> viewModel\.requestProtectedReveal/);
});

test('CT-ANDROID-JNI-005: password rotation uses a candidate session and clears UI input', () => {
  const runtime = read('crates/vault-android-runtime/src/lib.rs');
  const rotation = runtime.match(/pub fn change_master_password\([\s\S]*?\n    \}/)?.[0] ?? '';
  assert.match(rotation, /VaultSession::unlock\(current_password, &encrypted\)/);
  assert.match(rotation, /candidate\.change_master_password\(current_password, new_password\)/);
  assert.match(rotation, /write_vault\(&self\.vault_path, &replacement\)\?;[\s\S]*self\.replace_session\(candidate\)/);
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /copy\(passwordRotation = null, busy = true/);
  assert.match(viewModel, /runCurrentOperation\(generation\)[\s\S]*VaultNativeBridge\.changeMasterPassword/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /两次输入的新主密码不一致/);
});

test('CT-ANDROID-JNI-003: search stays local and trash destruction is confirmed', () => {
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /val query: String = ""/);
  assert.doesNotMatch(viewModel, /external fun search|VaultNativeBridge\.search/);
  assert.match(viewModel, /restoreLogin[\s\S]*performMutation/);

  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const home = read('apps/android/app/src/main/java/com/vaultmesh/app/UnlockedHomeUi.kt');
  assert.match(home, /overviewEntries\(state\)[\s\S]*contains\(state\.query, true\)/);
  assert.match(home, /state\.logins\.filter[\s\S]*contains\(state\.query, true\)/);
  assert.match(activity, /永久删除？/);
  assert.match(activity, /清空回收站？/);

  const runtime = read('crates/vault-android-runtime/src/lib.rs');
  const summary = runtime.match(/pub struct AndroidTrashSummary \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(summary, /trash_id: String/);
  assert.doesNotMatch(summary, /password|notes|totp|recovery|custom/);
  assert.match(runtime, /restore_login[\s\S]*mutate_and_commit/);
  assert.match(runtime, /purge_login[\s\S]*mutate_and_commit/);
});

test('CT-ANDROID-JNI-002: Login list is redacted and mutations are atomically persisted', () => {
  const runtime = read('crates/vault-android-runtime/src/lib.rs');
  const summary = runtime.match(/pub struct AndroidLoginSummary \{([\s\S]*?)\n\}/)?.[1] ?? '';
  assert.match(summary, /id: String/);
  assert.match(summary, /title: String/);
  assert.match(summary, /has_password: bool/);
  assert.match(summary, /has_totp_secret: bool/);
  assert.match(summary, /has_recovery_codes: bool/);
  assert.doesNotMatch(summary, /password: String|notes|totp_secret: String|recovery_codes: (Vec|String)|custom/);
  assert.match(runtime, /fn mutate_and_commit<[\s\S]*payload_snapshot\(\)[\s\S]*write_vault[\s\S]*restore_payload_snapshot/);

  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /删除登录项？/);
  assert.match(activity, /新密码（留空则保留）/);
});

test('CT-ANDROID-JNI-004: other item summaries are redacted and use the shared atomic commit', () => {
  const runtime = read('crates/vault-android-runtime/src/items.rs');
  for (const name of ['AndroidCardSummary', 'AndroidSshSummary', 'AndroidIdentitySummary', 'AndroidSecretSummary', 'AndroidOtherTrashSummary']) {
    const fields = runtime.match(new RegExp(`pub struct ${name} \\{([\\s\\S]*?)\\n\\}`))?.[1] ?? '';
    assert.ok(fields.length > 0, name);
    assert.doesNotMatch(fields, /card_number|security_code: Option<String>|pin: Option<String>|password: Option<String>|private_key: Option<String>|key_passphrase: Option<String>|secret: String|scopes|notes/);
  }
  assert.match(runtime, /list_secrets[\s\S]*filter\(\|item\| !item\.is_passkey\)/);
  assert.match(runtime, /update_secret[\s\S]*current\.is_passkey/);
  assert.match(runtime, /delete_secret[\s\S]*is_passkey/);
  assert.match(runtime, /update_identity[\s\S]*emails: current\.emails[\s\S]*addresses: current\.addresses/);
  assert.match(runtime, /add_card[\s\S]*mutate_and_commit/);
  assert.match(runtime, /add_ssh[\s\S]*mutate_and_commit/);
  assert.match(runtime, /add_identity[\s\S]*mutate_and_commit/);
  assert.match(runtime, /add_secret[\s\S]*mutate_and_commit/);

  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /runCurrentOperation[\s\S]*generation != lifecycleGeneration[\s\S]*VaultNativeBridge\.lock\(\)/);
  assert.doesNotMatch(viewModel, /SavedStateHandle|rememberSaveable|println|Log\./);
});

test('CT-ANDROID-JNI-001: password is cleared before the asynchronous native operation', () => {
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  const clear = viewModel.indexOf('copy(password = "", busy = true');
  const dispatch = viewModel.indexOf('withContext(Dispatchers.IO)', clear);
  assert.ok(clear >= 0 && dispatch > clear);
  const clearEditor = viewModel.indexOf('copy(editor = null, generator = null, busy = true');
  const editorDispatch = viewModel.indexOf('withContext(Dispatchers.IO)', clearEditor);
  assert.ok(clearEditor >= 0 && editorDispatch > clearEditor);
  assert.match(viewModel, /lifecycleGeneration[\s\S]*generation != lifecycleGeneration[\s\S]*VaultNativeBridge\.lock\(\)/);
  assert.doesNotMatch(viewModel, /SavedStateHandle|rememberSaveable|println|Log\./);
});


test('CT-ANDROID-LAN-SYNC-001: fixed sync operations and independent platform lifecycle', () => {
  const jni = read('crates/vault-android-runtime/src/jni_sync.rs');
  assert.deepEqual([...jni.matchAll(/Java_com_vaultmesh_app_VaultNativeBridge_([A-Za-z]+)/g)].map(m => m[1]),
    ['syncOpen', 'syncTick', 'syncClose', 'syncRetry', 'syncStatus', 'syncSetEnabled', 'syncConflicts', 'syncRestoreConflict', 'syncClearConflicts', 'syncNeeded']);
  assert.doesNotMatch(jni, /Box::into_raw|from_raw|method_name|operation_name/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/LanSyncService.kt');
  assert.match(service, /FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE/);
  assert.match(service, /START_NOT_STICKY/);
  assert.match(service, /override fun onDestroy[\s\S]*syncClose\(\)[\s\S]*releaseMulticast\(\)/);
  assert.match(service, /current != network[\s\S]*syncTick\(false\)/);
  assert.doesNotMatch(service, /lanStart|lanStop|lanClose|VaultNativeBridge\.unlock/);
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /<service android:name=".LanSyncService" android:exported="false"/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  const closePanel = activity.slice(activity.indexOf('private fun closeLanPanel'), activity.indexOf('private fun openLanPanel'));
  assert.doesNotMatch(closePanel, /syncClose|stopService/);
  const rust = read('crates/vault-android-runtime/src/lib.rs');
  assert.match(rust, /sync_checkpoint\(lan_sync::now\(\)\)/);
  assert.match(rust, /write_vault\(&self.vault_path, &bytes\)[\s\S]*publish_sync\(\)/);
});

test('CT-ANDROID-AUTOFILL-001/002: system service and request-scoped JNI constrain credential delivery', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android:name="\.VaultAutofillService"[\s\S]*?android:permission="android\.permission\.BIND_AUTOFILL_SERVICE"/);
  assert.match(manifest, /android:name="\.AutofillAuthActivity" android:exported="false"/);
  assert.match(manifest, /android:name="\.AutofillAuthActivity"[^>]*android:theme="@style\/Theme\.VaultMesh\.AutofillSheet"/);
  const themes = read('apps/android/app/src/main/res/values/themes.xml');
  assert.match(themes, /Theme\.VaultMesh\.AutofillSheet[\s\S]*windowIsTranslucent[\s\S]*backgroundDimEnabled/);
  const bridge = read('crates/vault-android-runtime/src/jni_autofill.rs');
  assert.deepEqual([...bridge.matchAll(/Java_com_vaultmesh_app_VaultNativeBridge_([A-Za-z]+)/g)].map(m => m[1]),
    ['autofillPreviewFingerprint', 'autofillBegin', 'autofillBeginBiometric', 'autofillBeginPin', 'autofillCandidates', 'autofillFill', 'autofillSave', 'autofillCancel']);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultAutofillService.kt');
  assert.match(service, /credentialPresentation[\s\S]*android\.R\.id\.text1, username\.ifBlank \{ title \}/);
  const fill = service.slice(service.indexOf('override fun onFillRequest'), service.indexOf('override fun onSaveRequest'));
  assert.doesNotMatch(fill, /autofillValue|textValue|autofillFill|copyLoginPassword/);
  assert.match(service, /PendingIntent\.FLAG_ONE_SHOT or PendingIntent\.FLAG_MUTABLE/);
  assert.doesNotMatch(service, /putExtra\([^\n]*(password|username)/i);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/AutofillAuthActivity.kt');
  assert.match(activity, /FLAG_SECURE/);
  assert.match(activity, /IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS/);
  assert.match(activity, /override fun onPause\(\)[\s\S]*autofillCancel/);
  assert.match(activity, /BiometricPrompt\.CryptoObject\(cipher\)/);
  assert.match(activity, /RoundedCornerShape\(topStart = 28\.dp, topEnd = 28\.dp\)/);
  assert.match(activity, /Box\(Modifier\.fillMaxSize\(\)\.pointerInput\(confirming\)[\s\S]*detectTapGestures \{ if \(!confirming\) cancelRequest\(\) \}/);
  assert.match(activity, /Surface\(Modifier\.fillMaxWidth\(\)\.fillMaxHeight\(sheetHeight\)\.pointerInput\(Unit\)/);
  assert.match(activity, /Text\("VaultMesh · \$appLabel"/);
  assert.doesNotMatch(activity, /"为 \$appLabel 填充|"仅填充密码，保留当前用户名"|"验证身份后选择账号"/);
  assert.match(activity, /AutofillCandidateRow\(item, recent = true/);
  assert.match(activity, /Text\("输入六位 PIN"/);
  assert.match(activity, /Text\("其他解锁方式"\)/);
  assert.match(activity, /Text\("主密码", maxLines = 1\)/);
  assert.match(activity, /OutlinedTextField\(query, ::updateQuery/);
  assert.doesNotMatch(activity, /TextButton\(onClick = ::search, enabled = !busy\) \{ Text\("搜索"\) \}/);
  assert.match(activity, /if \(debounce\) delay\(450\)[\s\S]*fetchCandidates\(key, revision\)/);
  assert.match(activity, /600 - \(SystemClock\.elapsedRealtime\(\) - lastSearchStartedAt\)/);
  assert.match(activity, /revision != searchRevision/);
  assert.match(activity, /if \(query == next\) return/);
  assert.match(activity, /requestedSearchKey == key[\s\S]*appliedSearchKey == key/);
  assert.match(activity, /searchCache\[key\]\?\.let \{ snapshot/);
  assert.match(activity, /searchCache\.size > 4/);
  assert.match(activity, /override fun onPause\(\)[\s\S]*searchCache\.clear\(\)/);
  assert.match(activity, /autofillBeginBiometric/);
  assert.match(activity, /autofillBeginPin/);
  assert.match(activity, /request\.fillScope == AutofillRequests\.FillScope\.Pair/);
  assert.match(activity, /Dataset\.Builder\(VaultAutofillService\.credentialPresentation\(/);
  assert.match(activity, /createFillResponse\(this, request\.form\)[\s\S]*EXTRA_AUTHENTICATION_RESULT/);
  assert.match(service, /FillScope\.PasswordOnly[\s\S]*passwordActionPresentation\(context, "使用 VaultMesh 填充"\)[\s\S]*setValue\(form.password, null\)/);
  assert.match(activity, /pinRemaining == 0\) fallbackMethod\(\)/);
  assert.match(bridge, /runtime\.autofill_begin_biometric/);
  assert.match(bridge, /runtime\.autofill_begin_pin/);
  assert.doesNotMatch(activity, /rememberSaveable|SavedStateHandle|Log\./);
  assert.match(read('apps/android/app/src/main/java/com/vaultmesh/app/UnlockedHomeUi.kt'), /AutofillSettingsCard\(\)/);
});

test('CT-ANDROID-AUTOFILL-003: local phone suggestion uses only the username field and optional phone permission', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android:name="android\.permission\.READ_PHONE_NUMBERS"/);
  assert.doesNotMatch(manifest, /android:name="android\.permission\.READ_PHONE_STATE"|android:name="android\.permission\.READ_SMS"/);
  const source = read('apps/android/app/src/main/java/com/vaultmesh/app/LocalPhoneNumber.kt');
  assert.match(source, /checkSelfPermission\(Manifest\.permission\.READ_PHONE_NUMBERS\)/);
  assert.match(source, /getPhoneNumber\(SubscriptionManager\.DEFAULT_SUBSCRIPTION_ID\)/);
  assert.match(source, /PhoneNumberUtils\.formatNumber\(international/);
  assert.match(source, /international\.drop\(countryCode\.length \+ 1\)/);
  assert.match(source, /noBackupFilesDir[\s\S]*AndroidKeyStore/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultAutofillService.kt');
  assert.match(service, /response\.addDataset\(Dataset\.Builder[\s\S]*response\.addDataset\(phoneDataset/);
  const phoneDataset = service.slice(service.indexOf('internal fun phoneDataset'), service.indexOf('internal fun saveInfo'));
  assert.match(phoneDataset, /setValue\(usernameId, AutofillValue\.forText\(number\)\)/);
  assert.doesNotMatch(phoneDataset, /password|setAuthentication|putExtra/);
  assert.match(read('apps/android/app/src/main/java/com/vaultmesh/app/UnlockedHomeUi.kt'), /PhoneNumberSettingsCard\(\)/);
});

 test('CT-DEVICE-ASSIST-001: fixed JNI and receive-only SMS surface', () => {
  const bridge = read('crates/vault-android-runtime/src/jni_assist.rs');
  assert.deepEqual([...bridge.matchAll(/Java_com_vaultmesh_app_VaultNativeBridge_([A-Za-z]+)/g)].map(m => m[1]), ['assistOpen', 'assistStatus', 'assistGrant', 'assistTick', 'assistStop', 'assistCode']);
  assert.doesNotMatch(bridge, /Box::into_raw|from_raw|method_name|operation_name/);
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android.permission.RECEIVE_SMS/);
  assert.doesNotMatch(manifest, /android.permission.(READ_SMS|SEND_SMS|BIND_NOTIFICATION_LISTENER_SERVICE)/);
  const service = read('apps/android/app/src/main/java/com/vaultmesh/app/DeviceAssistService.kt');
  assert.match(service, /BROADCAST_SMS/);
  assert.match(service, /if \(!enabled\(this\)\) \{ stopSelf\(\); return START_NOT_STICKY/);
  assert.match(service, /return START_STICKY/);
  assert.match(service, /intent\?\.action == STOP[\s\S]*setEnabled\(this, false\)/);
  assert.match(service, /putBoolean\("enabled", value\)\.commit\(\)/);
  assert.match(service, /if \(!enabled\(context\) \|\| running\) return/);
  assert.match(manifest, /DeviceAssistService[^>]*stopWithTask="false"/);
  assert.match(manifest, /RECEIVE_BOOT_COMPLETED/);
  assert.doesNotMatch(manifest, /BIND_ACCESSIBILITY_SERVICE|LOCKED_BOOT_COMPLETED/);
  assert.match(bridge, /r.open_assist_binding\(credentials.clone\(\)\)/);
  const ui = read('apps/android/app/src/main/java/com/vaultmesh/app/DeviceAssistUi.kt');
  assert.match(ui, /DeviceAssistSwitch\(serviceEnabled/);
  assert.doesNotMatch(ui, /Text\("启动互通"\)|Text\("停止互通"\)/);
  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /DeviceAssistService.startIfEnabled\(this@MainActivity\)\s*if \(viewModel.state.value.status == "unlocked"\)/);
});
