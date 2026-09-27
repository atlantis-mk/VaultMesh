package com.vaultmesh.app

import java.net.IDN
import java.net.URI
import java.util.Locale

internal enum class LoginFieldRole { Username, Password, NewPassword, Confirmation }

/** Pure semantic classification: no existing field value is an input. */
internal object AutofillFields {
    /** 0 is a complete code field; 1..8 are positions in a split code widget. */
    fun smsOtpPosition(hints: List<String>, name: String?, hint: String?): Int? {
        val normalized = hints.map { it.lowercase(Locale.ROOT) }
        if (normalized.any { it != "smsotpcode" && !Regex("smsotpcode[1-8]").matches(it) }) return null
        val label = listOfNotNull(name, hint).joinToString(" ").lowercase(Locale.ROOT)
        if (Regex("password|密码|credit.?card|银行卡").containsMatchIn(label)) return null
        val fullCodeHints = normalized.count { it == "smsotpcode" }
        val positions = normalized.mapNotNull { Regex("smsotpcode([1-8])").matchEntire(it)?.groupValues?.get(1)?.toInt() }
        if (fullCodeHints > 0) return if (fullCodeHints == 1 && positions.isEmpty()) 0 else null
        if (positions.size == 1) return positions.single()
        if (positions.isNotEmpty()) return null
        return if (Regex("短信验证码|sms[ _-]*(otp|code|验证码)").containsMatchIn(label)) 0 else null
    }

    fun classify(hints: List<String>, autocomplete: String?, name: String?, hint: String?, htmlType: String?, inputType: Int): LoginFieldRole? {
        val tokens = (hints + (autocomplete?.split(' ') ?: emptyList())).map { it.lowercase(Locale.ROOT).replace("-", "") }
        if (tokens.any { it in setOf("onetimecode", "smsotpcode", "2faappotpcode", "emailotpcode",
                "creditcardnumber", "creditcardsecuritycode") || Regex("smsotpcode[1-8]").matches(it) }) return null
        val label = listOfNotNull(name, hint).joinToString(" ").lowercase(Locale.ROOT)
        if (Regex("短信验证码|sms[ _-]*(otp|code|验证码)").containsMatchIn(label)) return null
        if (Regex("confirm|repeat|retype|确认密码|重复密码").containsMatchIn(label)) return LoginFieldRole.Confirmation
        if (tokens.any { it == "newpassword" }) return LoginFieldRole.NewPassword
        if (Regex("new.?password|新密码").containsMatchIn(label)) return LoginFieldRole.NewPassword
        if (tokens.any { it in setOf("password", "currentpassword") }) return LoginFieldRole.Password
        if (tokens.any { it in setOf("username", "emailaddress", "email", "newusername") }) return LoginFieldRole.Username
        val variation = inputType and 0xff0
        if (htmlType == "password" || (inputType and 0xf == 1 && variation in setOf(0x80, 0x90, 0xe0))) return LoginFieldRole.Password
        if (Regex("password|passwd|(^|[_ ])pwd($|[_ ])|密码").containsMatchIn(label)) return LoginFieldRole.Password
        if (htmlType == "email" || (inputType and 0xf == 1 && variation in setOf(0x20, 0xd0)) || Regex("user.?name|email|login.?id|account|用户名|邮箱|账号|帐号").containsMatchIn(label)) return LoginFieldRole.Username
        return null
    }

    fun origin(domain: String, scheme: String?): String? = runCatching {
        if (domain.length > 253 || (scheme != null && scheme.lowercase(Locale.ROOT) != "https")) return null
        val parsed = URI("https://$domain")
        if (parsed.rawUserInfo != null || !parsed.rawPath.isNullOrEmpty() || parsed.rawQuery != null || parsed.rawFragment != null) return null
        val host = parsed.host ?: return null
        val ascii = IDN.toASCII(host).lowercase(Locale.ROOT)
        if (ascii.isEmpty() || ascii.endsWith('.') || parsed.port !in -1..65535) return null
        "https://$ascii" + if (parsed.port == -1 || parsed.port == 443) "" else ":${parsed.port}"
    }.getOrNull()
}
