package com.vaultmesh.app

/** Pure bounded parser; SMS body is never retained or returned as metadata. */
internal object DeviceAssistSms {
    private const val SEMANTICS = "验证码|校验码|动态码|一次性密码|verification\\s+code|security\\s+code|one[- ]time(?:\\s+(?:password|code))?|\\botp\\b|\\bcode\\b"
    private val token = Regex("(?<![A-Za-z0-9])[A-Za-z0-9]{4,10}(?![A-Za-z0-9])")
    private val after = Regex("(?:$SEMANTICS)\\s*(?:(?:is|是|为)\\s*)?[:：=]?\\s*([A-Za-z0-9]{4,10})(?![A-Za-z0-9])", RegexOption.IGNORE_CASE)
    private val before = Regex("(?<![A-Za-z0-9])([A-Za-z0-9]{4,10})\\s+(?:is\\s+)?(?:your\\s+)?(?:$SEMANTICS)", RegexOption.IGNORE_CASE)
    private val ordinaryWords = setOf("code", "your", "will", "valid", "invalid", "expired", "please", "never", "share", "with", "this", "password", "security", "received")
    fun extract(body: String): String? {
        if (body.length !in 4..4096) return null
        val explicit = (after.findAll(body) + before.findAll(body)).mapNotNull { match ->
            val group = match.groups[1] ?: return@mapNotNull null
            val value = group.value
            if (value.lowercase() in ordinaryWords) return@mapNotNull null
            val end = group.range.last + 1
            // Decimal amounts and formatted telephone/transaction fragments are not codes.
            if (end + 1 < body.length && body[end] in ".,-" && body[end + 1].isDigit()) return@mapNotNull null
            value
        }.distinct().toList()
        val candidate = explicit.singleOrNull() ?: return null
        // Additional plausible numbers make a message ambiguous even when adjacent to a marker.
        val numeric = token.findAll(body).map { it.value }.filter { it.any(Char::isDigit) }.distinct().toList()
        if (numeric.any { it != candidate }) return null
        return candidate
    }
    fun fresh(sent: Long, now: Long): Boolean = sent > 0 && now - sent in 0 until 120_000L
}
