package com.vaultmesh.app
import org.junit.Assert.*
import org.junit.Test
class DeviceAssistSmsTest {
    @Test fun extractsUnambiguousCodes() {
        assertEquals("428193", DeviceAssistSms.extract("【测试】验证码：428193，请勿泄露。"))
        assertEquals("A7b294", DeviceAssistSms.extract("Your verification code is A7b294."))
        assertEquals("AbCdEf", DeviceAssistSms.extract("Your verification code is AbCdEf."))
        assertEquals("123456", DeviceAssistSms.extract("123456 is your security code."))
    }
    @Test fun rejectsAmbiguityAndOrdinaryMessages() {
        assertNull(DeviceAssistSms.extract("Security code is invalid. Call 1234567890"))
        assertNull(DeviceAssistSms.extract("验证码付款金额 1234.00 元"))
        assertNull(DeviceAssistSms.extract("code: 1234.00"))
        assertNull(DeviceAssistSms.extract("您的订单 428193 已发货"))
        assertNull(DeviceAssistSms.extract("验证码 428193，订单 738492"))
        assertNull(DeviceAssistSms.extract("验证码为 1234567890123456"))
        assertNull(DeviceAssistSms.extract("code: "+"a".repeat(5000)))
    }
    @Test fun rejectsDelayedAndFutureSms() {
        assertTrue(DeviceAssistSms.fresh(1_000_000, 1_119_999))
        assertFalse(DeviceAssistSms.fresh(1_000_000, 1_120_000))
        assertFalse(DeviceAssistSms.fresh(1_000_000, 11_800_000))
        assertFalse(DeviceAssistSms.fresh(1_000_000, 999_999))
    }
}
