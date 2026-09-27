package com.vaultmesh.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidCredentialGeneratorTest {
    @Test fun passwordRespectsLengthAndEverySelectedClass() {
        val values = (1..20).map { AndroidCredentialGenerator.password(24, true, true, true, true) }
        assertTrue(values.all { it.length == 24 })
        assertTrue(values.all { value -> value.any(Char::isLowerCase) && value.any(Char::isUpperCase) &&
            value.any(Char::isDigit) && value.any { !it.isLetterOrDigit() } })
        assertTrue(values.toSet().size > 1)
        assertFalse(values.any { it.contains('0') || it.contains('1') || it.contains('O') || it.contains('l') })
    }

    @Test fun invalidOptionsAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            AndroidCredentialGenerator.password(20, false, false, false, false)
        }
        assertThrows(IllegalArgumentException::class.java) {
            AndroidCredentialGenerator.password(2, true, true, true, false)
        }
        assertThrows(IllegalArgumentException::class.java) { AndroidCredentialGenerator.username(5) }
        assertThrows(IllegalArgumentException::class.java) { AndroidCredentialGenerator.emailAlias(12, "bad domain") }
    }

    @Test fun usernameAndEmailAliasUseSafeShape() {
        val username = AndroidCredentialGenerator.username(20)
        assertEquals(20, username.length)
        assertTrue(username.matches(Regex("[a-z][a-z2-9]{19}")))
        val alias = AndroidCredentialGenerator.emailAlias(12, " Example.COM ")
        assertTrue(alias.matches(Regex("[a-z][a-z2-9]{11}@example\\.com")))
        assertNotEquals(username, alias.substringBefore('@'))
    }
}
