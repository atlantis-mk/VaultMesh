package com.vaultmesh.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import org.json.JSONObject

internal data class AndroidUpdateAsset(val variant: String, val url: String, val sha256: String, val size: Long)

internal data class AndroidUpdateManifest(
    val version: String,
    val versionCode: Long,
    val notes: String,
    val assets: Map<String, AndroidUpdateAsset>,
)

internal data class AndroidUpdateOffer(val version: String, val versionCode: Long, val notes: String, val asset: AndroidUpdateAsset)

// ADR-0049：只解析、比较并提示；下载与安装交给系统浏览器和安装器。
internal object AndroidUpdatePolicy {
    const val MAX_MANIFEST_BYTES = 64 * 1024
    const val AUTO_CHECK_INTERVAL_MS = 24L * 60 * 60 * 1000
    val RELEASE_VARIANTS = listOf("universal", "armeabi-v7a", "arm64-v8a", "x86_64")
    private val VERSION = Regex("""^\d+\.\d+\.\d+(?:-review(?:\.\d+)?)?$""")
    private val SHA256 = Regex("^[0-9a-f]{64}$")

    fun parse(json: String, endpoint: String): AndroidUpdateManifest {
        val endpointUri = URI(endpoint)
        require(endpointUri.scheme == "https" && !endpointUri.host.isNullOrEmpty()) { "invalid endpoint" }
        val root = JSONObject(json)
        require(root.getInt("schema") == 1) { "unsupported schema" }
        val version = root.getString("version")
        require(VERSION.matches(version)) { "invalid version" }
        val versionCode = root.getLong("versionCode")
        require(versionCode > 0 && versionCode % 10 == 0L) { "invalid versionCode" }
        val notes = root.optString("notes", "").take(4000)
        val assetsJson = root.getJSONObject("assets")
        val assets = RELEASE_VARIANTS.associateWith { variant ->
            val asset = assetsJson.getJSONObject(variant)
            val url = asset.getString("url")
            val uri = URI(url)
            val expectedPath = "/releases/v$version/VaultMesh_${version}_android-$variant.apk"
            require(uri.scheme == "https" && uri.host == endpointUri.host && uri.port == endpointUri.port
                && uri.rawQuery == null && uri.rawFragment == null && uri.rawUserInfo == null
                && uri.path.endsWith(expectedPath)) { "invalid asset url" }
            val sha256 = asset.getString("sha256")
            require(SHA256.matches(sha256)) { "invalid sha256" }
            val size = asset.getLong("size")
            require(size > 0) { "invalid size" }
            AndroidUpdateAsset(variant, url, sha256, size)
        }
        return AndroidUpdateManifest(version, versionCode, notes, assets)
    }

    // 已安装的 ABI APK 以个位区分，比较前去掉。
    fun isNewer(installedVersionCode: Long, manifestVersionCode: Long): Boolean =
        manifestVersionCode > installedVersionCode - installedVersionCode % 10

    fun selectAsset(manifest: AndroidUpdateManifest, supportedAbis: List<String>): AndroidUpdateAsset =
        supportedAbis.firstNotNullOfOrNull { abi -> manifest.assets[abi]?.takeIf { abi != "universal" } }
            ?: manifest.assets.getValue("universal")

    fun offer(manifest: AndroidUpdateManifest, installedVersionCode: Long, supportedAbis: List<String>, skippedVersionCode: Long): AndroidUpdateOffer? {
        if (!isNewer(installedVersionCode, manifest.versionCode)) return null
        if (manifest.versionCode == skippedVersionCode) return null
        return AndroidUpdateOffer(manifest.version, manifest.versionCode, manifest.notes, selectAsset(manifest, supportedAbis))
    }

    fun autoCheckDue(nowMs: Long, lastCheckMs: Long): Boolean =
        lastCheckMs <= 0 || nowMs < lastCheckMs || nowMs - lastCheckMs >= AUTO_CHECK_INTERVAL_MS
}

internal sealed interface AndroidUpdateResult {
    data class Available(val offer: AndroidUpdateOffer) : AndroidUpdateResult
    data object Current : AndroidUpdateResult
    data object Failed : AndroidUpdateResult
}

internal class AndroidUpdateChecker(private val context: Context) {
    private val prefs = context.getSharedPreferences("vaultmesh_update", Context.MODE_PRIVATE)
    val endpoint: String = BuildConfig.UPDATE_MANIFEST_URL
    val available: Boolean get() = endpoint.isNotEmpty()

    var autoCheckEnabled: Boolean
        get() = prefs.getBoolean("auto_check", true)
        set(value) { prefs.edit().putBoolean("auto_check", value).apply() }

    fun autoCheckDue(): Boolean =
        available && autoCheckEnabled && AndroidUpdatePolicy.autoCheckDue(System.currentTimeMillis(), prefs.getLong("last_check_ms", 0))

    fun skip(versionCode: Long) { prefs.edit().putLong("skipped_version_code", versionCode).apply() }

    /** 阻塞网络调用，必须在主线程之外执行。手动检查忽略已跳过的版本。 */
    fun check(manual: Boolean): AndroidUpdateResult {
        if (!available) return AndroidUpdateResult.Failed
        prefs.edit().putLong("last_check_ms", System.currentTimeMillis()).apply()
        val manifest = runCatching { AndroidUpdatePolicy.parse(fetch(), endpoint) }.getOrNull()
            ?: return AndroidUpdateResult.Failed
        val skipped = if (manual) -1 else prefs.getLong("skipped_version_code", -1)
        val offer = AndroidUpdatePolicy.offer(manifest, installedVersionCode(), Build.SUPPORTED_ABIS.toList(), skipped)
        return offer?.let { AndroidUpdateResult.Available(it) } ?: AndroidUpdateResult.Current
    }

    fun openDownload(offer: AndroidUpdateOffer): Boolean = runCatching {
        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(offer.asset.url))
            .addCategory(Intent.CATEGORY_BROWSABLE).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }.isSuccess

    private fun installedVersionCode(): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else @Suppress("DEPRECATION") info.versionCode.toLong()
    }

    private fun fetch(): String {
        val connection = URL(endpoint).openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = 10_000
            connection.readTimeout = 10_000
            connection.setRequestProperty("Accept", "application/json")
            check(connection.responseCode == 200) { "unexpected status" }
            val output = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(8 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    output.write(buffer, 0, read)
                    check(output.size() <= AndroidUpdatePolicy.MAX_MANIFEST_BYTES) { "manifest too large" }
                }
            }
            return output.toString(Charsets.UTF_8.name())
        } finally {
            connection.disconnect()
        }
    }
}
