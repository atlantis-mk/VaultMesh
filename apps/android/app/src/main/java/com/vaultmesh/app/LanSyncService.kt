package com.vaultmesh.app

import android.Manifest
import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.content.ContextCompat
import kotlinx.coroutines.*

/** Platform owner of already-authorized connections; pairing discovery has a separate lifetime. */
class LanSyncService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var worker: Job? = null
    private var multicast: WifiManager.MulticastLock? = null
    private var network: Network? = null
    @Volatile private var destroyed = false
    private val nativeLock = Any()

    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == STOP) {
            pause(this)
            stopSelf()
            return START_NOT_STICKY
        }
        if (worker != null) return START_NOT_STICKY
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel(CHANNEL, "局域网同步", NotificationManager.IMPORTANCE_LOW))
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, LanSyncService::class.java).setAction(STOP), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val notification = Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_nav_devices)
            .setContentTitle("VaultMesh 局域网同步").setContentText("与已授权设备同步；锁定时仅收发密文")
            .setContentIntent(open).setOngoing(true).setVisibility(Notification.VISIBILITY_PRIVATE)
            .addAction(Notification.Action.Builder(null, "停止同步", stop).build()).build()
        try {
            if (Build.VERSION.SDK_INT >= 29) startForeground(107, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
            else startForeground(107, notification)
        } catch (_: RuntimeException) {
            state = "系统未允许启动同步服务，请重试。"
            stopSelf()
            return START_NOT_STICKY
        }
        running = true
        state = "正在连接已授权设备"
        worker = scope.launch {
            try {
                while (isActive && !destroyed) {
                    synchronized(nativeLock) {
                        if (!destroyed) {
                            val current = lanNetwork(this@LanSyncService)
                            val allowed = current != null
                            if (!allowed || current != network) {
                                VaultNativeBridge.syncTick(false)
                                releaseMulticast()
                                network = current
                            }
                            if (allowed && multicast == null) {
                                multicast = applicationContext.getSystemService(WifiManager::class.java)
                                    .createMulticastLock("vaultmesh-lan-sync").apply { setReferenceCounted(false); acquire() }
                            }
                            var result = VaultNativeBridge.syncTick(allowed)
                            if (result == "not_initialized") {
                                val key = LanPairingKeyService(application).readOrCreate()
                                val opened = if (key == null) "key_unavailable" else try {
                                    VaultNativeBridge.syncOpen(key)
                                } finally { key.fill(0) }
                                result = if (opened == "ok") VaultNativeBridge.syncTick(allowed) else opened
                            }
                            state = when {
                                result != "ok" -> "同步服务暂时不可用，请重试。"
                                !allowed -> "等待局域网连接或本地网络权限"
                                else -> "同步服务运行中"
                            }
                        }
                    }
                    delay(500)
                }
            } catch (_: Exception) {
                state = "同步服务已停止，请重试。"
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }
    private fun releaseMulticast() {
        multicast?.let { runCatching { if (it.isHeld) it.release() } }
        multicast = null
    }
    override fun onTaskRemoved(rootIntent: Intent?) { stopSelf() }
    override fun onDestroy() {
        destroyed = true
        scope.cancel()
        synchronized(nativeLock) { VaultNativeBridge.syncClose(); releaseMulticast() }
        running = false
        if (state == "同步服务运行中" || state == "正在连接已授权设备") state = "同步服务已停止"
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
    companion object {
        private const val CHANNEL = "lan-sync"
        private const val STOP = "com.vaultmesh.app.STOP_LAN_SYNC"
        @Volatile var running = false
            private set
        @Volatile var state = "同步服务未启动"
            private set
        fun paused(context: Context) = context.getSharedPreferences("lan-sync", Context.MODE_PRIVATE).getBoolean("paused", false)
        fun pause(context: Context) { context.getSharedPreferences("lan-sync", Context.MODE_PRIVATE).edit().putBoolean("paused", true).apply() }
        fun start(context: Context, explicit: Boolean = false) {
            if (explicit) context.getSharedPreferences("lan-sync", Context.MODE_PRIVATE).edit().putBoolean("paused", false).apply()
            if (paused(context) || running) return
            try { ContextCompat.startForegroundService(context, Intent(context, LanSyncService::class.java)) }
            catch (_: RuntimeException) { state = "系统未允许启动同步服务，请重试。" }
        }
        fun networkAllowed(context: Context): Boolean = lanNetwork(context) != null
        private fun lanNetwork(context: Context): Network? {
            if (Build.VERSION.SDK_INT >= 37 && ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_LOCAL_NETWORK) != PackageManager.PERMISSION_GRANTED) return null
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
            // A LAN does not need internet validation. Android can choose cellular
            // as its default even while a local Wi-Fi link is usable.
            return connectivity.allNetworks.firstOrNull { candidate ->
                val caps = connectivity.getNetworkCapabilities(candidate)
                caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET))
            }
        }
    }
}
