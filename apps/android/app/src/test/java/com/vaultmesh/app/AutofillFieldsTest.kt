package com.vaultmesh.app

import org.junit.Assert.*
import org.junit.Test

class AutofillFieldsTest {
    private fun role(hints: List<String> = emptyList(), autocomplete: String? = null, name: String? = null, input: Int = 1) =
        AutofillFields.classify(hints, autocomplete, name, null, null, input)
    @Test fun loginRegistrationChangeAndOtpRemainDistinct() {
        assertEquals(LoginFieldRole.Username, role(listOf("username")))
        assertEquals(LoginFieldRole.Username, role(autocomplete = "section-login username"))
        assertEquals(LoginFieldRole.Password, role(autocomplete = "current-password"))
        assertEquals(LoginFieldRole.Password, role(input = 0x81))
        assertEquals(LoginFieldRole.NewPassword, role(autocomplete = "new-password"))
        assertEquals(LoginFieldRole.Confirmation, role(autocomplete = "new-password", name = "confirm_password"))
        assertEquals(LoginFieldRole.NewPassword, role(name = "新密码"))
        assertNull(role(autocomplete = "one-time-code", name = "password"))
        assertNull(role(listOf("smsOTPCode1"), name = "password"))
        assertNull(role(listOf("creditCardSecurityCode"), name = "password"))
        assertNull(role(name = "search"))
        assertNull(role(name = "pin", input = 0x12))
    }
    @Test fun originRejectsSpoofingAndUnencryptedTargets() {
        assertEquals("https://example.test", AutofillFields.origin("EXAMPLE.test:443", "https"))
        assertEquals("https://example.test:8443", AutofillFields.origin("example.test:8443", "https"))
        for (domain in listOf("good.test@evil.test", "good.test/evil", "good.test?x", "good.test#fragment", "example.test.", "", "a test")) {
            assertNull(domain, AutofillFields.origin(domain, "https"))
        }
        assertNull(AutofillFields.origin("example.test", "http"))
    }
    @Test fun smsOtpRequiresExplicitSmsSemantics() {
        assertEquals(0, AutofillFields.smsOtpPosition(listOf("smsOTPCode"), null, null))
        assertEquals(3, AutofillFields.smsOtpPosition(listOf("smsOTPCode3"), null, null))
        assertNull(AutofillFields.smsOtpPosition(listOf("smsOTPCode", "username"), null, null))
        assertEquals(0, AutofillFields.smsOtpPosition(emptyList(), "sms_code", null))
        assertNull(AutofillFields.smsOtpPosition(listOf("2faAppOTPCode"), "sms_code", null))
        assertNull(AutofillFields.smsOtpPosition(listOf("emailOTPCode"), null, "短信验证码"))
        assertNull(AutofillFields.smsOtpPosition(listOf("oneTimeCode"), null, null))
        assertNull(AutofillFields.smsOtpPosition(emptyList(), "pin", "验证码"))
        assertNull(AutofillFields.smsOtpPosition(emptyList(), null, null))
        assertTrue(SmsOtpRequests.validCode("123456", 1))
        assertTrue(SmsOtpRequests.validCode("123456", 6))
        assertFalse(SmsOtpRequests.validCode("123456", 4))
        assertFalse(SmsOtpRequests.validCode("12 456", 1))
        assertFalse(SmsOtpRequests.validCode("123", 1))
        assertTrue(SmsOtpEligibility.allowed(false, 0))
        assertTrue(SmsOtpEligibility.allowed(false, 1))
        assertFalse(SmsOtpEligibility.allowed(true, 1))
        assertFalse(SmsOtpEligibility.allowed(false, 2))
        assertFalse(SmsOtpEligibility.allowed(false, null))
        assertFalse(SmsOtpEligibility.allowed(null, 1))
    }
}
