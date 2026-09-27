package com.vaultmesh.app

import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.view.WindowManager
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.service.autofill.Dataset
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.activity.OnBackPressedCallback
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.Alignment
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.Lifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

internal data class FillCandidate(val id: String, val title: String, val username: String, val matched: Boolean, val suggested: Boolean, val relatedHint: Boolean)
private data class CandidateSnapshot(val items: List<FillCandidate>, val recentIds: List<String>)
private enum class AutofillUnlockMethod { Biometric, Pin, MasterPassword }

@Composable
private fun AutofillCandidateRow(item: FillCandidate, recent: Boolean, enabled: Boolean, onClick: () -> Unit) {
    val association = when {
        item.matched -> "已关联此目标"
        item.suggested -> "网站匹配 · 需确认"
        item.relatedHint -> "可能相关 · 需确认"
        else -> "未关联此目标"
    }
    Card(onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(18.dp),
        colors = CardDefaults.cardColors(containerColor = if (recent) MaterialTheme.colorScheme.primaryContainer
            else MaterialTheme.colorScheme.surfaceVariant)) {
        Row(Modifier.fillMaxWidth().padding(14.dp), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Surface(shape = CircleShape, color = if (recent) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.outlineVariant) {
                Icon(painterResource(R.drawable.ic_lock), contentDescription = null,
                    tint = if (recent) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(9.dp).size(22.dp))
            }
            Column(Modifier.weight(1f)) {
                Text(item.username.ifBlank { item.title }, style = MaterialTheme.typography.titleMedium,
                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                    if (item.username.isNotBlank() && item.title != item.username) {
                        Text(item.title, modifier = Modifier.weight(1f, fill = false),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text(association, style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
            }
            Text("›", style = MaterialTheme.typography.headlineSmall,
                color = MaterialTheme.colorScheme.primary)
        }
    }
}

/** Only this platform owner receives the protected JNI response. Compose receives summaries. */
class AutofillAuthActivity : FragmentActivity() {
    private var pending: AutofillRequests.Request? = null
    private var token: String? = null
    private var masterPassword by mutableStateOf("")
    private var pinDraft by mutableStateOf("")
    private var unlockMethod by mutableStateOf(AutofillUnlockMethod.MasterPassword)
    private var biometricEnabled by mutableStateOf(false)
    private var pinRemaining by mutableIntStateOf(0)
    private var methodPicker by mutableStateOf(false)
    private val biometricUnlock by lazy { BiometricUnlockService(application) }
    private val pinUnlock by lazy { PinUnlockService(application) }
    private var biometricCiphertext: ByteArray? = null
    private var biometricPrompt: BiometricPrompt? = null
    private var authorizationMethod = AutofillUnlockMethod.MasterPassword
    private var autoPromptPending = false
    private var busy by mutableStateOf(false)
    private var searching by mutableStateOf(false)
    private var unlocked by mutableStateOf(false)
    private var error by mutableStateOf<String?>(null)
    private var candidates by mutableStateOf<List<FillCandidate>>(emptyList())
    private var recentIds by mutableStateOf<List<String>>(emptyList())
    private var query by mutableStateOf("")
    private var searchFocused by mutableStateOf(false)
    private var searchJob: Job? = null
    @Volatile private var searchRevision = 0L
    private var lastSearchStartedAt = 0L
    private var requestedSearchKey: String? = null
    private var appliedSearchKey: String? = null
    private val searchCache = LinkedHashMap<String, CandidateSnapshot>()
    private var title by mutableStateOf("")
    private var appLabel = ""
    private var username by mutableStateOf("")
    private var selected by mutableStateOf<FillCandidate?>(null)
    private var confirming by mutableStateOf(false)
    private var completedFill = false
    private var selectedAutoHandled = false
    @Volatile private var generation = 0L
    private val nativeGate = Any()

    @Suppress("DEPRECATION")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        setResult(RESULT_CANCELED)
        // Request ownership cannot be restored from saved state or replayed.
        if (savedInstanceState != null) { finish(); return }
        val id = intent.getStringExtra(AutofillRequests.EXTRA_REQUEST)
        if (intent.data?.lastPathSegment != id) { finish(); return }
        val request = AutofillRequests.claim(id) ?: run { finish(); return }
        pending = request
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() { cancelRequest() }
        })
        if (!request.form.target.stillInstalled(this)) { finish(); return }
        if (request.capture == null) {
            val structure = intent.getParcelableExtra<AssistStructure>(AutofillManager.EXTRA_ASSIST_STRUCTURE)
            val fresh = structure?.let { AutofillStructure.parse(this, it) }
            val state = intent.getBundleExtra(AutofillManager.EXTRA_CLIENT_STATE)
            if (fresh == null || fresh.target != request.form.target || fresh.activity != request.form.activity || fresh.fillIds != request.form.fillIds || state?.getString(AutofillRequests.EXTRA_REQUEST) != request.clientStateId) {
                finish(); return
            }
        }
        appLabel = runCatching { packageManager.getApplicationLabel(packageManager.getApplicationInfo(request.form.target.packageName, 0)).toString().take(64) }.getOrDefault(request.form.target.packageName.take(64))
        title = appLabel
        username = request.capture?.username?.concatToString() ?: ""
        lifecycleScope.launch {
            delay((request.expires - SystemClock.elapsedRealtime()).coerceAtLeast(0))
            Toast.makeText(this@AutofillAuthActivity, "请求已过期，请重新触发", Toast.LENGTH_SHORT).show()
            finish()
        }
        setContent {
            VaultMeshTheme {
                val imeVisible = WindowInsets.ime.getBottom(LocalDensity.current) > 0
                val sheetHeight = when {
                    imeVisible || searchFocused -> 0.98f
                    !unlocked && methodPicker -> 0.82f
                    !unlocked && unlockMethod == AutofillUnlockMethod.Pin -> 0.82f
                    !unlocked && unlockMethod == AutofillUnlockMethod.MasterPassword -> 0.60f
                    !unlocked -> 0.50f
                    request.capture != null -> 0.82f
                    else -> 0.72f
                }
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.BottomCenter) {
                    Box(Modifier.fillMaxSize().pointerInput(confirming) {
                        detectTapGestures { if (!confirming) cancelRequest() }
                    })
                    Surface(Modifier.fillMaxWidth().fillMaxHeight(sheetHeight).pointerInput(Unit) {
                        awaitPointerEventScope { while (true) awaitPointerEvent() }
                    },
                        shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp),
                        color = MaterialTheme.colorScheme.surface, shadowElevation = 16.dp) {
                    Column(Modifier.fillMaxSize().navigationBarsPadding().padding(horizontal = 22.dp, vertical = 14.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        Box(Modifier.align(Alignment.CenterHorizontally).size(width = 38.dp, height = 5.dp)
                            .background(MaterialTheme.colorScheme.outlineVariant, CircleShape))
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                            Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer) {
                                Icon(painterResource(R.drawable.ic_lock), contentDescription = null,
                                    tint = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(9.dp).size(22.dp))
                            }
                            Column(Modifier.weight(1f)) {
                                Text("VaultMesh · $appLabel", style = MaterialTheme.typography.titleLarge,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                Text(request.form.target.packageName, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis)
                                request.form.target.webOrigin?.let {
                                    Text(it, style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                        }
                        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                        if (!unlocked) {
                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                if (unlockMethod == AutofillUnlockMethod.Biometric) {
                                    Text("系统生物识别", style = MaterialTheme.typography.titleLarge)
                                    Text("请在系统弹窗完成指纹或面容验证。", color = MaterialTheme.colorScheme.onSurfaceVariant)
                                    TextButton(onClick = ::startBiometric, enabled = !busy) { Text("重新验证") }
                                } else if (unlockMethod == AutofillUnlockMethod.Pin) {
                                    Text("输入六位 PIN", style = MaterialTheme.typography.titleLarge)
                                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                                        repeat(6) { index ->
                                            Box(Modifier.padding(horizontal = 8.dp).size(14.dp).background(
                                                if (index < pinDraft.length) MaterialTheme.colorScheme.primary
                                                else MaterialTheme.colorScheme.primaryContainer, CircleShape))
                                        }
                                    }
                                    listOf(listOf("1", "2", "3"), listOf("4", "5", "6"),
                                        listOf("7", "8", "9"), listOf("", "0", "⌫")).forEach { keys ->
                                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                            keys.forEach { key ->
                                                Box(Modifier.weight(1f), contentAlignment = Alignment.Center) {
                                                    if (key.isNotEmpty()) FilledTonalButton(
                                                        onClick = { if (key == "⌫") pinDraft = pinDraft.dropLast(1)
                                                            else if (pinDraft.length < 6) {
                                                                pinDraft += key
                                                                if (pinDraft.length == 6) authenticatePin()
                                                            } },
                                                        enabled = !busy, modifier = Modifier.size(58.dp),
                                                        contentPadding = PaddingValues(0.dp), shape = CircleShape,
                                                    ) { Text(key, style = MaterialTheme.typography.headlineSmall) }
                                                }
                                            }
                                        }
                                    }
                                    Text("剩余 $pinRemaining 次尝试", style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                                } else {
                                    Text("输入主密码", style = MaterialTheme.typography.titleLarge)
                                    OutlinedTextField(masterPassword, { masterPassword = it.take(4096) }, label = { Text("主密码") },
                                        visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                                        singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
                                    Button(onClick = ::authenticate, enabled = !busy && masterPassword.isNotEmpty(),
                                        modifier = Modifier.fillMaxWidth().height(52.dp)) {
                                        if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                                        else Text("解锁本次请求")
                                    }
                                }
                                Spacer(Modifier.weight(1f))
                                if (biometricEnabled || pinRemaining > 0) {
                                    TextButton(onClick = { methodPicker = !methodPicker }, enabled = !busy,
                                        modifier = Modifier.fillMaxWidth()) { Text("其他解锁方式") }
                                }
                                if (methodPicker) {
                                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                                        if (biometricEnabled) TextButton(onClick = { methodPicker = false; selectMethod(AutofillUnlockMethod.Biometric) },
                                            enabled = !busy && unlockMethod != AutofillUnlockMethod.Biometric,
                                            modifier = Modifier.weight(1f)) { Text("生物识别", maxLines = 1) }
                                        if (pinRemaining > 0) TextButton(onClick = { methodPicker = false; selectMethod(AutofillUnlockMethod.Pin) },
                                            enabled = !busy && unlockMethod != AutofillUnlockMethod.Pin,
                                            modifier = Modifier.weight(1f)) { Text("六位 PIN", maxLines = 1) }
                                        TextButton(onClick = { methodPicker = false; selectMethod(AutofillUnlockMethod.MasterPassword) },
                                            enabled = !busy && unlockMethod != AutofillUnlockMethod.MasterPassword,
                                            modifier = Modifier.weight(1f)) { Text("主密码", maxLines = 1) }
                                    }
                                }
                            }
                        } else if (request.capture != null) {
                            OutlinedTextField(title, { title = it.take(256) }, label = { Text("标题") }, singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
                            OutlinedTextField(username, { username = it.take(256); selected = null }, label = { Text("用户名") }, singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
                            Text("已识别密码，将加密保存。")
                            TextButton(onClick = ::search, enabled = !busy && !searching) { Text("查找可更新账号") }
                            Text("选择保存方式", style = MaterialTheme.typography.titleMedium)
                            TextButton(onClick = { selected = null }, enabled = !busy && !searching) { Text(if (selected == null) "✓ 新建登录项" else "新建登录项") }
                            LazyColumn(Modifier.weight(1f)) {
                                items(candidates.filter { (it.matched || it.suggested || it.relatedHint) && (username.isEmpty() || it.username == username) }, key = { it.id }) { item ->
                                    TextButton(onClick = { selected = item }, enabled = !busy && !searching, modifier = Modifier.fillMaxWidth()) {
                                        Text((if (selected?.id == item.id) "✓ " else "") + "更新 ${item.username.ifBlank { item.title }}" +
                                            if (item.username.isNotBlank() && item.title != item.username) " · ${item.title}" else "")
                                    }
                                }
                            }
                            Button(onClick = { confirming = true }, enabled = !busy && !searching && title.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text(if (busy) "正在保存…" else "继续保存") }
                        } else {
                            val candidateListState = rememberLazyListState()
                            LaunchedEffect(query) { candidateListState.scrollToItem(0) }
                            OutlinedTextField(query, ::updateQuery, label = { Text("搜索登录项") },
                                singleLine = true, enabled = !busy,
                                modifier = Modifier.fillMaxWidth().onFocusChanged { searchFocused = it.hasFocus },
                                trailingIcon = { if (searching) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) })
                            if (!searching && candidates.isEmpty()) Text("没有找到登录项。可先登录，再按系统提示保存。")
                            val visibleCandidates = if (searching) candidates.filter {
                                query.isBlank() || it.username.contains(query, ignoreCase = true) || it.title.contains(query, ignoreCase = true)
                            } else candidates
                            val recent = visibleCandidates.filter { it.id in recentIds }
                            val others = visibleCandidates.filter { it.id !in recentIds }
                            LazyColumn(Modifier.weight(1f), state = candidateListState,
                                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                if (recent.isNotEmpty()) {
                                    item { Text("最近使用", style = MaterialTheme.typography.titleSmall) }
                                    items(recent, key = { it.id }) { item ->
                                        AutofillCandidateRow(item, recent = true, enabled = !busy && !searching) {
                                            selected = item
                                            if (item.matched) fill(item, false, false) else confirming = true
                                        }
                                    }
                                }
                                if (others.isNotEmpty()) {
                                    item { Text("其他账号", style = MaterialTheme.typography.titleSmall) }
                                    items(others, key = { it.id }) { item ->
                                        AutofillCandidateRow(item, recent = false, enabled = !busy && !searching) {
                                            selected = item
                                            if (item.matched) fill(item, false, false) else confirming = true
                                        }
                                    }
                                }
                            }
                        }
                        TextButton(onClick = ::cancelRequest, modifier = Modifier.fillMaxWidth()) { Text("取消") }
                    }
                    if (confirming) AlertDialog(
                        onDismissRequest = { if (!busy) confirming = false },
                        title = { Text(if (request.capture == null) "确认向此应用填充" else if (selected == null) "确认新建登录项" else "确认更新密码") },
                        text = { Text(if (request.capture == null) {
                            "将 ${selected?.title} 的${if (request.fillScope == AutofillRequests.FillScope.PasswordOnly) "密码" else "登录信息"}交给 ${request.form.target.packageName}。${if (request.fillScope == AutofillRequests.FillScope.PasswordOnly) "当前用户名保持不变。" else ""}${request.form.target.webOrigin?.let { "该应用声明网站为 $it，尚未验证两者关联。" } ?: "此账号尚未关联该应用。"}确认并记住会保存当前应用签名的关联；也可以只填充本次。"
                        } else "${if (selected == null) "新建 $title" else "更新 ${selected?.title} 的密码"}，并关联当前应用${request.form.target.webOrigin?.let { "及网站 $it" } ?: ""}。") },
                        confirmButton = { TextButton(onClick = { confirming = false; if (request.capture == null) selected?.let { fill(it, true, true) } else save() }, enabled = !busy) { Text(if (request.capture == null) "确认并记住" else "确认") } },
                        dismissButton = { TextButton(onClick = { if (request.capture == null) { confirming = false; selected?.let { fill(it, true, false) } } else confirming = false }, enabled = !busy) { Text(if (request.capture == null) "仅本次填充" else "返回") } },
                    )
                }
            }
            }
        }
        prepareQuickMethods()
    }

    private fun valid(epoch: Long): Boolean = generation == epoch && !isFinishing && pending?.let {
        AutofillRequests.get(it.id) === it && it.form.target.stillInstalled(this)
    } == true

    private fun cancelRequest() {
        if (isFinishing) return
        val request = pending
        if (request?.capture == null && request != null && request.form.target.stillInstalled(this)) {
            runCatching { VaultAutofillService.createFillResponse(this, request.form).first }.getOrNull()?.let { response ->
                setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response))
            }
        }
        finish()
    }

    private fun prepareQuickMethods() {
        lifecycleScope.launch {
            val availability = withContext(Dispatchers.IO) {
                if (VaultNativeBridge.status() == "not_initialized") VaultNativeBridge.initialize(filesDir.absolutePath)
                val bio = biometricUnlock.available() && biometricUnlock.enabled()
                val pin = if (pinUnlock.enabled()) runCatching {
                    val status = JSONObject(VaultNativeBridge.pinStatus())
                    if (status.getBoolean("enabled")) status.getInt("remainingAttempts") else 0
                }.getOrDefault(0) else 0
                bio to pin
            }
            if (isFinishing || pending == null) return@launch
            biometricEnabled = availability.first
            pinRemaining = availability.second
            if (biometricEnabled && masterPassword.isEmpty() && !busy) {
                unlockMethod = AutofillUnlockMethod.Biometric
                autoPromptPending = true
                if (lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) startBiometric()
            } else if (pinRemaining > 0 && masterPassword.isEmpty() && !busy) unlockMethod = AutofillUnlockMethod.Pin
        }
    }

    override fun onResume() {
        super.onResume()
        if (autoPromptPending) startBiometric()
    }

    private fun selectMethod(method: AutofillUnlockMethod) {
        if (busy || unlocked) return
        masterPassword = ""
        pinDraft = ""
        error = null
        unlockMethod = method
        if (method == AutofillUnlockMethod.Biometric) startBiometric()
    }

    private fun fallbackMethod() {
        unlockMethod = if (pinRemaining > 0) AutofillUnlockMethod.Pin else AutofillUnlockMethod.MasterPassword
    }

    private fun startBiometric() {
        if (!biometricEnabled || busy || unlocked ||
            !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        autoPromptPending = false
        val prepared = biometricUnlock.unlockCipher()
        if (prepared == null) { biometricEnabled = false; fallbackMethod(); return }
        val (cipher, ciphertext) = prepared
        biometricCiphertext = ciphertext
        val epoch = generation
        val prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val sealed = biometricCiphertext
                biometricCiphertext = null
                biometricPrompt = null
                val authorizedCipher = result.cryptoObject?.cipher
                if (sealed == null || authorizedCipher == null || !valid(epoch)) {
                    sealed?.fill(0)
                    fallbackMethod()
                    return
                }
                lifecycleScope.launch {
                    val secret = withContext(Dispatchers.IO) { biometricUnlock.releaseSecret(authorizedCipher, sealed) }
                    if (!valid(epoch)) return@launch
                    if (secret == null) { fallbackMethod(); error = "生物识别授权失败，请使用其他方式。" }
                    else beginAuthorization(AutofillUnlockMethod.Biometric, secret, "")
                }
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                biometricCiphertext?.fill(0)
                biometricCiphertext = null
                biometricPrompt = null
                if (valid(epoch)) {
                    fallbackMethod()
                    if (errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON &&
                        errorCode != BiometricPrompt.ERROR_USER_CANCELED &&
                        errorCode != BiometricPrompt.ERROR_CANCELED) error = "生物识别授权失败，请使用其他方式。"
                }
            }
        })
        biometricPrompt = prompt
        prompt.authenticate(BiometricPrompt.PromptInfo.Builder().setTitle(if (pending?.capture == null) "使用 VaultMesh 填充" else "保存到 VaultMesh")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("取消").build(), BiometricPrompt.CryptoObject(cipher))
    }

    private fun authenticatePin() {
        if (busy || pinRemaining <= 0 || pinDraft.length != 6) return
        val input = pinDraft
        pinDraft = ""
        val epoch = generation
        busy = true
        lifecycleScope.launch {
            val secret = withContext(Dispatchers.IO) { pinUnlock.readDeviceSecret() }
            if (!valid(epoch)) return@launch
            busy = false
            if (secret == null) { pinRemaining = 0; fallbackMethod(); error = "PIN 已不可用，请使用主密码。" }
            else beginAuthorization(AutofillUnlockMethod.Pin, secret, input)
        }
    }

    private fun authenticate() {
        val input = masterPassword
        masterPassword = ""
        beginAuthorization(AutofillUnlockMethod.MasterPassword, input, "")
    }

    private fun beginAuthorization(method: AutofillUnlockMethod, credential: String, pin: String) {
        if (busy) return
        val request = pending ?: return
        busy = true
        error = null
        val epoch = generation
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                synchronized(nativeGate) {
                    if (!valid(epoch)) return@synchronized "stale"
                    if (VaultNativeBridge.status() == "not_initialized") VaultNativeBridge.initialize(filesDir.absolutePath)
                    val result = when (method) {
                        AutofillUnlockMethod.MasterPassword -> VaultNativeBridge.autofillBegin(request.id, request.form.target.json(), credential)
                        AutofillUnlockMethod.Biometric -> VaultNativeBridge.autofillBeginBiometric(request.id, request.form.target.json(), credential)
                        AutofillUnlockMethod.Pin -> VaultNativeBridge.autofillBeginPin(request.id, request.form.target.json(), pin, credential)
                    }
                    if (result.startsWith("token:")) {
                        val next = result.removePrefix("token:")
                        if (valid(epoch)) token = next else VaultNativeBridge.autofillCancel(next)
                    }
                    result
                }
            }
            busy = false
            if (!valid(epoch)) return@launch
            if (!result.startsWith("token:")) {
                if (method == AutofillUnlockMethod.Pin) {
                    pinRemaining = withContext(Dispatchers.IO) { runCatching {
                        JSONObject(VaultNativeBridge.pinStatus()).getInt("remainingAttempts")
                    }.getOrDefault(0) }
                    if (pinRemaining == 0) fallbackMethod()
                } else if (method == AutofillUnlockMethod.Biometric) fallbackMethod()
                error = when (result) {
                    "missing" -> "请先打开 VaultMesh 创建或导入保险库。"
                    "pin_locked" -> "PIN 已锁定，请使用主密码。"
                    "pin_failed" -> "PIN 不正确，请重试。"
                    else -> if (method == AutofillUnlockMethod.MasterPassword) "解锁失败，请检查主密码。" else "授权失败，请使用其他方式。"
                }
                return@launch
            }
            authorizationMethod = method
            unlocked = true
            selectedAutoHandled = false
            searchCache.clear()
            requestedSearchKey = null
            appliedSearchKey = null
            search()
        }
    }

    private fun updateQuery(value: String) {
        val next = value.take(128)
        if (query == next) return
        query = next
        if (!unlocked || pending?.capture != null) return
        queueSearch(next, debounce = true)
    }

    private fun search() {
        if (busy) return
        queueSearch(if (pending?.capture != null) username else query, debounce = false)
    }

    private fun queueSearch(searchQuery: String, debounce: Boolean) {
        val key = searchQuery.trim().lowercase()
        if ((searching && requestedSearchKey == key) || (!searching && appliedSearchKey == key)) return
        searchRevision++
        val revision = searchRevision
        searchJob?.cancel()
        requestedSearchKey = key
        searchCache[key]?.let { snapshot ->
            recentIds = snapshot.recentIds
            candidates = snapshot.items
            appliedSearchKey = key
            searching = false
            searchJob = null
            return
        }
        searching = true
        searchJob = lifecycleScope.launch {
            if (debounce) delay(450)
            fetchCandidates(key, revision)
        }
    }

    private suspend fun fetchCandidates(searchQuery: String, revision: Long) {
        val authority = token ?: return
        val target = pending?.form?.target ?: return
        val epoch = generation
        val wait = 600 - (SystemClock.elapsedRealtime() - lastSearchStartedAt)
        if (wait > 0) delay(wait)
        if (!valid(epoch) || revision != searchRevision || !unlocked) return
        lastSearchStartedAt = SystemClock.elapsedRealtime()
        val result = withContext(Dispatchers.IO) { synchronized(nativeGate) {
            if (valid(epoch) && revision == searchRevision) {
                val preview = AutofillPreviewCache(this@AutofillAuthActivity)
                val digest = preview.vaultDigest()
                val history = runCatching { AutofillSelectionHistory(this@AutofillAuthActivity).recentIds(target) }.getOrDefault(emptyList())
                Triple(VaultNativeBridge.autofillCandidates(authority, searchQuery, appLabel, JSONArray(history).toString()), history, digest)
            } else Triple("", emptyList(), null)
        } }
        if (!valid(epoch) || revision != searchRevision) return
        val parsed = runCatching {
            val array = JSONArray(result.first)
            List(array.length()) { i -> array.getJSONObject(i).let { FillCandidate(it.getString("id"), it.getString("title"), it.getString("username"), it.getBoolean("matched"), it.getBoolean("suggested"), it.getBoolean("relatedHint")) } }
        }.getOrNull()
        searching = false
        if (parsed == null) { error = "授权已失效，请重新解锁。"; unlocked = false; candidates = emptyList(); appliedSearchKey = null }
        else {
            val ordered = parsed.sortedWith(compareBy<FillCandidate> { item ->
                val index = result.second.indexOf(item.id)
                if (index >= 0) index else 100 + when {
                    item.matched -> 0; item.suggested -> 1; item.relatedHint -> 2; else -> 3
                }
            })
            val snapshot = CandidateSnapshot(ordered, result.second)
            if (searchQuery.isEmpty()) runCatching {
                AutofillPreviewCache(this@AutofillAuthActivity).refreshTarget(target, ordered, result.third)
            }
            searchCache[searchQuery] = snapshot
            if (searchCache.size > 4) searchCache.remove(searchCache.keys.first())
            recentIds = snapshot.recentIds
            candidates = snapshot.items
            appliedSearchKey = searchQuery
            val selectedRequest = pending?.takeIf { searchQuery.isEmpty() && !selectedAutoHandled && it.capture == null }
            val digestValid = selectedRequest?.selectedDigest?.let { expected ->
                AutofillPreviewCache(this@AutofillAuthActivity).vaultDigest() == expected
            } == true
            if (selectedRequest?.selectedId != null && !digestValid) {
                selectedAutoHandled = true
                error = "保险库已变化，请重新选择账号。"
            }
            val chosen = selectedRequest?.takeIf { digestValid }?.selectedId
                ?.let { id -> ordered.firstOrNull { it.id == id } }
            if (chosen != null) {
                selectedAutoHandled = true
                selected = chosen
                if (chosen.matched) fill(chosen, false, false) else confirming = true
            }
        }
    }

    private fun fill(item: FillCandidate, confirmed: Boolean, rememberAssociation: Boolean) {
        if (busy) return
        val request = pending ?: return
        val authority = token ?: return
        val epoch = generation
        busy = true
        lifecycleScope.launch {
            val outcome = withContext(Dispatchers.IO) { synchronized(nativeGate) {
                if (!valid(epoch)) return@synchronized null to "stale"
                val result = VaultNativeBridge.autofillFill(authority, request.id, item.id, confirmed, rememberAssociation, request.form.password != null)
                token = null
                if (!result.startsWith("value:") || !valid(epoch)) return@synchronized null to result
                val dataset = runCatching {
                    val values = JSONObject(result.removePrefix("value:"))
                    val builder = Dataset.Builder(VaultAutofillService.credentialPresentation(
                        this@AutofillAuthActivity, item.username,
                        VaultAutofillService.credentialSubtitle(item.title, request.form.target.packageName, appLabel)))
                    if (request.fillScope == AutofillRequests.FillScope.Pair) {
                        request.form.username?.let { builder.setValue(it, AutofillValue.forText(values.getString("username"))) }
                    }
                    request.form.password?.let { builder.setValue(it, AutofillValue.forText(values.getString("password"))) }
                    builder.build()
                }.getOrNull()
                if (dataset != null) runCatching { AutofillSelectionHistory(this@AutofillAuthActivity).record(request.form.target, item.id) }
                dataset to result
            } }
            if (!valid(epoch)) return@launch
            busy = false
            val dataset = outcome.first
            if (dataset == null) {
                error = when {
                    outcome.second == "unlock_failed" && authorizationMethod != AutofillUnlockMethod.MasterPassword -> "此条目要求主密码再次验证，请使用主密码授权。"
                    outcome.second == "io_error" -> "关联保存失败，未填充。请重新解锁后重试。"
                    else -> "填充授权失效，请重新解锁。"
                }
                unlocked = false; candidates = emptyList()
                if (outcome.second == "unlock_failed") unlockMethod = AutofillUnlockMethod.MasterPassword
                return@launch
            }
            completedFill = true
            setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset))
            finish()
        }
    }

    private fun save() {
        if (busy) return
        val request = pending ?: return
        if (request.capture == null) return
        val authority = token ?: return
        val updateId = selected?.id ?: ""
        val saveTitle = title
        val saveUsername = username
        val epoch = generation
        busy = true
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { synchronized(nativeGate) {
                if (!valid(epoch)) return@synchronized "stale"
                val captured = AutofillRequests.capturedPassword(request.id) ?: return@synchronized "stale"
                val result = VaultNativeBridge.autofillSave(authority, request.id, updateId, saveTitle, saveUsername, captured)
                token = null
                result
            } }
            if (!valid(epoch)) return@launch
            busy = false
            if (result == "ok") {
                Toast.makeText(this@AutofillAuthActivity, "已保存到 VaultMesh", Toast.LENGTH_SHORT).show()
                finish()
            } else {
                error = if (result == "unlock_failed" && authorizationMethod != AutofillUnlockMethod.MasterPassword)
                    "已有登录项要求主密码验证，请改用主密码授权保存。"
                else "保存失败，未确认写入。请重新解锁后检查并重试。"
                unlocked = false
                candidates = emptyList()
                if (authorizationMethod != AutofillUnlockMethod.MasterPassword) unlockMethod = AutofillUnlockMethod.MasterPassword
            }
        }
    }

    override fun onPause() {
        generation++
        searchRevision++
        searchJob?.cancel()
        searchJob = null
        searching = false
        searchCache.clear()
        requestedSearchKey = null
        appliedSearchKey = null
        biometricPrompt?.cancelAuthentication()
        biometricPrompt = null
        biometricCiphertext?.fill(0)
        biometricCiphertext = null
        masterPassword = ""
        pinDraft = ""
        candidates = emptyList()
        username = ""
        query = ""
        searchFocused = false
        selected = null
        synchronized(nativeGate) { token?.let(VaultNativeBridge::autofillCancel); token = null }
        if (!completedFill) AutofillRequests.remove(pending?.id)
        super.onPause()
        if (!isFinishing) finish()
    }

    override fun onDestroy() {
        synchronized(nativeGate) { token?.let(VaultNativeBridge::autofillCancel); token = null }
        if (!completedFill) AutofillRequests.remove(pending?.id)
        pending = null
        super.onDestroy()
    }
}
