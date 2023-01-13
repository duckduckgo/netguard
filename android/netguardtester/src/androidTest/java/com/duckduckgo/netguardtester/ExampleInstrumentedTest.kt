package com.duckduckgo.netguardtester

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer

/**
 * Tests for netguard's util.c
 */
@RunWith(AndroidJUnit4::class)
class UtilTest {

    val netguard = NetguardInterface()

    @Test
    fun isValidUtf8() {
        val regularStrBytes = "regular string".encodeToByteArray()

        // Using a ByteBuffer as Kotlin does not allow non-UTF 8 Strings
        val buffer: ByteBuffer = ByteBuffer.allocateDirect(regularStrBytes.size)
        buffer.put(regularStrBytes)

        // 1) Valid UTF-8
        assertTrue(netguard.isValidUtf8(buffer))

        // 2) Invalid UTF-8
        val invalidBytes = byteArrayOf(0x41, 0x42, 0xfc.toByte(), 0x00)
        buffer.position(0)
        buffer.put(invalidBytes)
        assertFalse(netguard.isValidUtf8(buffer))
    }

    @Test
    fun isKotlinLoaded() {
        assertFalse(netguard.testPacket())
    }
}