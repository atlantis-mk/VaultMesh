package com.vaultmesh.app

import android.Manifest
import android.app.*
import android.content.*
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.provider.Telephony
import kotlinx.coroutines.*
import org.json.JSONObject
import java.security.MessageDigest

/** Separate from Vault sync; resumes only the user-persisted assist opt-in. */
class DeviceAssistService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var worker: Job? = null
    private var multicast: WifiManager.MulticastLock? = null
    private var receiver: BroadcastReceiver? = null
    private var network: android.net.Network? = null
    private val nativeGate = Any()
    @Volatile private var destroyed = false
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) { setEnabled(this, false); stopSelf(); return START_NOT_STICKY }
        if (!enabled(this)) { stopSelf(); return START_NOT_STICKY }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            state = "互通已开启，等待通知权限"
            stopSelf()
            return START_NOT_STICKY
        }
        if (worker != null) return START_STICKY
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "设备填充互通", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 21, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 22, Intent(this, DeviceAssistService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_nav_devices)
            .setContentTitle("VaultMesh 设备填充互通").setContentText("已授权电脑可获取号码与短时验证码")
            .setContentIntent(open).setOngoing(true).setVisibility(Notification.VISIBILITY_PRIVATE)
            .addAction(Notification.Action.Builder(null, "停止互通", stop).build()).build()
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(108, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            else startForeground(108, notification)
        } catch (_: RuntimeException) { state = "系统未允许启动互通服务"; stopSelf(); return START_NOT_STICKY }
        running = true
        worker = scope.launch {
            try {
                val initialized = if (VaultNativeBridge.status() == "not_initialized") VaultNativeBridge.initialize(filesDir.absolutePath) else "ok"
                val key = if (initialized == "ok") LanPairingKeyService(application).readOrCreate() else null
                val opened = if (key == null) "key_unavailable" else try { VaultNativeBridge.assistOpen(key) } finally { key.fill(0) }
                if (opened != "ok") {
                    state = "互通授权暂不可用，请打开应用解锁一次"
                    stopSelf()
                    return@launch
                }
                while (isActive && !destroyed) {
                    synchronized(nativeGate) {
                        if (destroyed || !enabled(this@DeviceAssistService)) {
                            VaultNativeBridge.assistStop()
                            stopSelf()
                            return@synchronized
                        }
                        val current = getSystemService(android.net.ConnectivityManager::class.java).activeNetwork
                        if (current != network) { VaultNativeBridge.assistStop(); network = current }
                        val allowed = LanSyncService.networkAllowed(this@DeviceAssistService)
                        val status = runCatching { JSONObject(VaultNativeBridge.assistStatus()) }.getOrNull()
                        val grants = status?.optJSONArray("grants")
                        val phoneEnabled = grants != null && (0 until grants.length()).any { grants.getJSONObject(it).optBoolean("phone") }
                        val smsEnabled = grants != null && (0 until grants.length()).any { grants.getJSONObject(it).optBoolean("sms") }
                        val smsAllowed = smsEnabled && checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED
                        if (allowed && multicast == null) multicast = getSystemService(WifiManager::class.java).createMulticastLock("vaultmesh-device-assist").apply { setReferenceCounted(false); acquire() }
                        if (!allowed) releaseMulticast()
                        val number = if (phoneEnabled) LocalPhoneNumber(this@DeviceAssistService).suggestedNumber().orEmpty() else ""
                        val result = VaultNativeBridge.assistTick(allowed, number, smsAllowed)
                        updateReceiver(allowed && smsAllowed)
                        state = when {
                            result != "ok" -> "互通授权暂不可用，请打开应用解锁一次"
                            !allowed -> "等待局域网连接或本地网络权限"
                            smsEnabled && Build.VERSION.SDK_INT >= 37 -> "号码互通运行中；系统可能限制自动验证码，请使用手动交付"
                            smsEnabled && (!smsAllowed || receiver == null) -> "号码互通运行中；短信权限不可用，可手动交付"
                            phoneEnabled && number.isEmpty() -> "未读取到号码，请检查手机号码权限或设置备用号码"
                            else -> "互通服务运行中"
                        }
                    }
                    delay(1000)
                }
            } catch (_: Exception) { state = "互通暂时中断，打开应用可恢复"; stopSelf() }
        }
        return START_STICKY
    }
    private fun updateReceiver(enabled: Boolean) {
        if (!enabled) { receiver?.let { runCatching { unregisterReceiver(it) } }; receiver = null; return }
        if (receiver != null) return
        val handler = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION || destroyed) return
                // System-authenticated broadcast only; never forward the Intent or the body.
                val messages = runCatching { Telephony.Sms.Intents.getMessagesFromIntent(intent) }.getOrNull() ?: return
                if (messages.isEmpty() || messages.size > 16) return
                val now = System.currentTimeMillis()
                if (messages.any { !DeviceAssistSms.fresh(it.timestampMillis, now) }) return
                val body = messages.joinToString("") { it.messageBody.orEmpty() }
                val code = DeviceAssistSms.extract(body) ?: return
                val source = messages.first().originatingAddress.orEmpty().filterNot(Char::isISOControl).take(64).ifEmpty { "短信" }
                val dedupBytes = MessageDigest.getInstance("SHA-256").digest((source + messages.first().timestampMillis + body).toByteArray())
                val dedup = dedupBytes.joinToString("") { "%02x".format(it) }
                synchronized(nativeGate) {
                    if (!destroyed && enabled(this@DeviceAssistService) && checkSelfPermission(Manifest.permission.RECEIVE_SMS) == PackageManager.PERMISSION_GRANTED)
                        VaultNativeBridge.assistCode(code, source, now - messages.minOf { it.timestampMillis }, dedup, "")
                }
            }
        }
        val filter = IntentFilter(Telephony.Sms.Intents.SMS_RECEIVED_ACTION)
        try {
            if (Build.VERSION.SDK_INT >= 33) registerReceiver(handler, filter, Manifest.permission.BROADCAST_SMS, null, Context.RECEIVER_EXPORTED)
            else registerReceiver(handler, filter, Manifest.permission.BROADCAST_SMS, null)
            receiver = handler
        } catch (_: RuntimeException) { state = "系统禁止自动接收短信，可手动交付" }
    }
    private fun releaseMulticast() { multicast?.let { runCatching { if (it.isHeld) it.release() } }; multicast = null }
    override fun onDestroy() {
        destroyed = true; scope.cancel()
        synchronized(nativeGate) { updateReceiver(false); VaultNativeBridge.assistStop(); releaseMulticast() }
        running = false
        if (!enabled(this)) state = "互通已关闭"
        else if (state == "互通服务运行中") state = "互通已开启，等待恢复"
        stopForeground(STOP_FOREGROUND_REMOVE); super.onDestroy()
    }
    companion object {
        private const val CHANNEL = "device-assist"
        private const val STOP = "com.vaultmesh.app.STOP_DEVICE_ASSIST"
        @Volatile var running = false; private set
        @Volatile var state = "互通已关闭"; private set
        private var lastStartAttempt = 0L
        private fun preferences(context: Context) = context.getSharedPreferences("device-assist", Context.MODE_PRIVATE)
        fun enabled(context: Context): Boolean = runCatching { preferences(context).getBoolean("enabled", false) }.getOrDefault(false)
        fun setEnabled(context: Context, value: Boolean): Boolean {
            val saved = preferences(context).edit().putBoolean("enabled", value).commit()
            lastStartAttempt = 0
            if (!value) {
                context.stopService(Intent(context, DeviceAssistService::class.java))
                // Close the transport even if no platform Service instance remains.
                VaultNativeBridge.assistStop()
                state = "互通已关闭"
            } else state = "互通已开启，等待连接"
            if (!saved) state = "无法保存互通开关，请重试"
            return saved
        }
        fun startIfEnabled(context: Context) {
            if (!enabled(context) || running) return
            if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                state = "互通已开启，等待通知权限"
                return
            }
            val now = android.os.SystemClock.elapsedRealtime()
            if (lastStartAttempt != 0L && now - lastStartAttempt < 10_000) return
            lastStartAttempt = now
            try {
                androidx.core.content.ContextCompat.startForegroundService(context, Intent(context, DeviceAssistService::class.java))
            } catch (_: RuntimeException) { state = "系统暂未允许互通运行，请打开应用恢复" }
        }
    }
}
