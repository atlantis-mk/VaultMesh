package com.vaultmesh.app

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import java.util.UUID

/** Transient platform-owned requests. Intents carry only an opaque ID. */
internal object AutofillRequests {
    enum class FillScope { Pair, PasswordOnly }
    const val TTL_MS = 120_000L
    const val EXTRA_REQUEST = "com.vaultmesh.app.AUTOFILL_REQUEST"
    private val handler = Handler(Looper.getMainLooper())
    private val requests = LinkedHashMap<String, Request>()
    internal class Request(val id: String, val form: AutofillForm, val capture: CapturedLogin?, val expires: Long,
        val fillScope: FillScope, val clientStateId: String, val selectedId: String?, val selectedDigest: String?) {
        var claimed = false
    }

    @Synchronized fun create(form: AutofillForm, capture: CapturedLogin? = null,
        fillScope: FillScope = FillScope.Pair, clientStateId: String? = null,
        selectedId: String? = null, selectedDigest: String? = null): Request {
        prune()
        while (requests.size >= 16) remove(requests.keys.first())
        val id = UUID.randomUUID().toString()
        val request = Request(id, form, capture, SystemClock.elapsedRealtime() + TTL_MS,
            fillScope, clientStateId ?: id, selectedId, selectedDigest)
        requests[request.id] = request
        handler.postDelayed({ remove(request.id) }, TTL_MS)
        return request
    }
    @Synchronized fun get(id: String?): Request? {
        prune()
        return requests[id]
    }
    @Synchronized fun claim(id: String?): Request? {
        val request = get(id) ?: return null
        if (request.claimed) return null
        request.claimed = true
        return request
    }
    @Synchronized fun remove(id: String?) { requests.remove(id)?.capture?.clear() }
    @Synchronized fun capturedPassword(id: String): String? = get(id)?.capture?.password?.concatToString()
    @Synchronized fun clear() { requests.keys.toList().forEach(::remove) }
    @Synchronized private fun prune() {
        requests.values.filter { it.expires <= SystemClock.elapsedRealtime() }.map { it.id }.forEach(::remove)
    }
}
