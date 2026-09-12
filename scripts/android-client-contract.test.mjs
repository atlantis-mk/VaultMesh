import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const read = (path) => fs.readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('CT-ANDROID-JNI-001: manifest keeps the first slice private and offline', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  assert.match(manifest, /android:allowBackup="false"/);
  assert.match(manifest, /android:fullBackupContent="false"/);
  assert.match(manifest, /android:usesCleartextTraffic="false"/);
  assert.doesNotMatch(manifest, /android\.permission\.(INTERNET|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|USE_BIOMETRIC)/);

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
  assert.match(activity, /override fun onStop\(\)[\s\S]*markLocked\(\)[\s\S]*VaultNativeBridge\.lock\(\)[\s\S]*super\.onStop\(\)/);
  assert.match(activity, /VaultNativeBridge\.initialize\(filesDir\.absolutePath\)/);
});

test('CT-ANDROID-JNI-001: JNI exposes only fixed lifecycle and Login CRUD operations', () => {
  const bridge = read('crates/vault-android-runtime/src/jni_bridge.rs');
  const exports = [...bridge.matchAll(/Java_com_vaultmesh_app_VaultNativeBridge_([A-Za-z]+)/g)].map((match) => match[1]);
  assert.deepEqual(exports, [
    'initialize', 'status', 'create', 'unlock', 'lock',
    'listLogins', 'addLogin', 'updateLogin', 'deleteLogin',
    'listTrash', 'restoreLogin', 'purgeLogin', 'emptyTrash',
  ]);
  assert.doesNotMatch(bridge, /Box::into_raw|from_raw|method_name|operation_name/);

  const kotlin = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultNativeBridge.kt');
  const nativeApi = kotlin.slice(kotlin.indexOf('@JvmStatic external'), kotlin.indexOf('fun decodeLogins'));
  assert.doesNotMatch(nativeApi, /Long\s*[),:]|ByteArray/);
  assert.match(kotlin, /System\.loadLibrary\("vaultmesh_android_runtime"\)/);
});

test('CT-ANDROID-JNI-003: search stays local and trash destruction is confirmed', () => {
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  assert.match(viewModel, /val query: String = ""/);
  assert.doesNotMatch(viewModel, /external fun search|VaultNativeBridge\.search/);
  assert.match(viewModel, /restoreLogin[\s\S]*performMutation/);

  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /contains\(state\.query, ignoreCase = true\)/);
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
  assert.doesNotMatch(summary, /password: String|notes|totp|recovery|custom/);
  assert.match(runtime, /fn mutate_and_commit<[\s\S]*payload_snapshot\(\)[\s\S]*write_vault[\s\S]*restore_payload_snapshot/);

  const activity = read('apps/android/app/src/main/java/com/vaultmesh/app/MainActivity.kt');
  assert.match(activity, /删除登录项？/);
  assert.match(activity, /新密码（留空则保留）/);
});

test('CT-ANDROID-JNI-001: password is cleared before the asynchronous native operation', () => {
  const viewModel = read('apps/android/app/src/main/java/com/vaultmesh/app/VaultViewModel.kt');
  const clear = viewModel.indexOf('copy(password = "", busy = true');
  const dispatch = viewModel.indexOf('withContext(Dispatchers.IO)', clear);
  assert.ok(clear >= 0 && dispatch > clear);
  const clearEditor = viewModel.indexOf('copy(editor = null, busy = true');
  const editorDispatch = viewModel.indexOf('withContext(Dispatchers.IO)', clearEditor);
  assert.ok(clearEditor >= 0 && editorDispatch > clearEditor);
  assert.match(viewModel, /lifecycleGeneration[\s\S]*generation != lifecycleGeneration[\s\S]*VaultNativeBridge\.lock\(\)/);
  assert.doesNotMatch(viewModel, /SavedStateHandle|rememberSaveable|println|Log\./);
});
