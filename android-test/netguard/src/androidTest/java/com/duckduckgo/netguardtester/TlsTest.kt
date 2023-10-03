package com.duckduckgo.netguardtester

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.duckduckgo.netguard.test.NetguardInterface
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer

/**
 * Tests for netguard's tls.c
 */
@RunWith(AndroidJUnit4::class)
class TlsTest {
    val netguard = NetguardInterface()

    @Test
    fun getServerName() {
        val speedTestSni = "16030100af010000ab03032d804e0bff3f6d121e276ee9e6f8e1ca128ba8d9b37389207f2939c40d719011000018c02bc02ccca9c02fc030cca8c013c014009c009d002f00350100006aff010001000000001b0019000016757365722d6170692e7370656564746573742e6e65740017000000230000000d0016001406010603050105030401040303010303020102030010000e000c02683208687474702f312e31000b00020100000a00080006001700180019"
        val hexBytes = speedTestSni.decodeHex()
        val pktBuffer = ByteBuffer.allocateDirect(hexBytes.size)
            .put(hexBytes)

        val addrHex = "924b5edb".decodeHex()
        val addrBuffer = ByteBuffer.allocateDirect(addrHex.size)
            .put(addrHex)

        netguard.getServerName(pktBuffer, pktBuffer.position(), addrBuffer, 4)
    }

    fun String.decodeHex(): ByteArray {
        check(length % 2 == 0) { "Must have an even length" }

        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}