package com.vaultmesh.app

import org.junit.Assert.*
import org.junit.Test

class AndroidUpdatePolicyTest {
    private val endpoint = "https://downloads.example.test/channels/review/android.json"
    private val sha = "a".repeat(64)

    private fun manifest(
        version: String = "0.1.1-review",
        versionCode: Long = 101000,
        host: String = "downloads.example.test",
        scheme: String = "https",
        schema: Int = 1,
        pathVersion: String = version,
    ): String {
        val assets = AndroidUpdatePolicy.RELEASE_VARIANTS.joinToString(",") { variant ->
            """"$variant":{"url":"$scheme://$host/releases/v$pathVersion/VaultMesh_${pathVersion}_android-$variant.apk","sha256":"$sha","size":1024}"""
        }
        return """{"schema":$schema,"version":"$version","versionCode":$versionCode,"notes":"n","assets":{$assets}}"""
    }

    @Test fun parsesValidManifest() {
        val parsed = AndroidUpdatePolicy.parse(manifest(), endpoint)
        assertEquals("0.1.1-review", parsed.version)
        assertEquals(101000L, parsed.versionCode)
        assertEquals(4, parsed.assets.size)
    }

    @Test fun rejectsUntrustedOrMalformedManifests() {
        listOf(
            manifest(schema = 2),
            manifest(host = "evil.example.test"),
            manifest(scheme = "http"),
            manifest(pathVersion = "0.1.0-review"),
            manifest(versionCode = 101002),
            manifest(version = "0.1.1-beta"),
            manifest().replace(sha, "xyz"),
            manifest().replace(""""size":1024""", """"size":0"""),
            manifest().replace(""""x86_64":""", """"x86":"""),
        ).forEach { json ->
            assertTrue(json, runCatching { AndroidUpdatePolicy.parse(json, endpoint) }.isFailure)
        }
        assertTrue(runCatching { AndroidUpdatePolicy.parse(manifest(), "http://downloads.example.test/android.json") }.isFailure)
    }

    @Test fun comparesVersionCodeBaseIgnoringAbiDigit() {
        assertTrue(AndroidUpdatePolicy.isNewer(100002, 101000))
        assertFalse(AndroidUpdatePolicy.isNewer(100003, 100000))
        assertFalse(AndroidUpdatePolicy.isNewer(101001, 100000))
        assertTrue(AndroidUpdatePolicy.isNewer(1, 10000))
    }

    @Test fun selectsFirstSupportedAbiAndFallsBackToUniversal() {
        val parsed = AndroidUpdatePolicy.parse(manifest(), endpoint)
        assertEquals("arm64-v8a", AndroidUpdatePolicy.selectAsset(parsed, listOf("arm64-v8a", "armeabi-v7a")).variant)
        assertEquals("armeabi-v7a", AndroidUpdatePolicy.selectAsset(parsed, listOf("armeabi-v7a", "armeabi")).variant)
        assertEquals("x86_64", AndroidUpdatePolicy.selectAsset(parsed, listOf("x86_64", "x86")).variant)
        assertEquals("universal", AndroidUpdatePolicy.selectAsset(parsed, listOf("x86", "mips")).variant)
    }

    @Test fun offerHonorsSkippedVersionAndCurrentInstall() {
        val parsed = AndroidUpdatePolicy.parse(manifest(), endpoint)
        assertNotNull(AndroidUpdatePolicy.offer(parsed, 100002, listOf("arm64-v8a"), -1))
        assertNull(AndroidUpdatePolicy.offer(parsed, 100002, listOf("arm64-v8a"), 101000))
        assertNull(AndroidUpdatePolicy.offer(parsed, 101002, listOf("arm64-v8a"), -1))
    }

    @Test fun autoCheckIsThrottledToOncePerDay() {
        val day = AndroidUpdatePolicy.AUTO_CHECK_INTERVAL_MS
        assertTrue(AndroidUpdatePolicy.autoCheckDue(1_000, 0))
        assertFalse(AndroidUpdatePolicy.autoCheckDue(10_000 + day - 1, 10_000))
        assertTrue(AndroidUpdatePolicy.autoCheckDue(10_000 + day, 10_000))
        assertTrue(AndroidUpdatePolicy.autoCheckDue(5_000, 10_000))
    }
}
