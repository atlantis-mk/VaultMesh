package com.vaultmesh.app

import java.security.SecureRandom

/** Local, short-lived credential generation using Android's secure random source. */
object AndroidCredentialGenerator {
    private const val LOWER = "abcdefghijkmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    private const val DIGITS = "23456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
    private val random = SecureRandom()
    private val domainPattern = Regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

    fun password(length: Int, lowercase: Boolean, uppercase: Boolean, digits: Boolean, symbols: Boolean): String {
        val pools = buildList {
            if (lowercase) add(LOWER)
            if (uppercase) add(UPPER)
            if (digits) add(DIGITS)
            if (symbols) add(SYMBOLS)
        }
        require(pools.isNotEmpty()) { "至少选择一种字符类型" }
        require(length in pools.size..128) { "密码长度须介于 ${pools.size} 与 128 之间" }
        val all = pools.joinToString("")
        val characters = pools.mapTo(mutableListOf()) { pool -> pool[random.nextInt(pool.length)] }
        while (characters.size < length) characters += all[random.nextInt(all.length)]
        for (index in characters.lastIndex downTo 1) {
            val swap = random.nextInt(index + 1)
            val current = characters[index]
            characters[index] = characters[swap]
            characters[swap] = current
        }
        return characters.joinToString("")
    }

    fun username(length: Int): String {
        require(length in 6..64) { "用户名长度须介于 6 与 64 之间" }
        val all = LOWER + DIGITS
        return buildString(length) {
            append(LOWER[random.nextInt(LOWER.length)])
            repeat(length - 1) { append(all[random.nextInt(all.length)]) }
        }
    }

    fun emailAlias(length: Int, domain: String): String {
        val normalized = domain.trim().lowercase()
        require(domainPattern.matches(normalized)) { "请输入有效的邮箱别名域名" }
        return "${username(length)}@$normalized"
    }
}
