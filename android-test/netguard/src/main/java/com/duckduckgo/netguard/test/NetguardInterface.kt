package com.duckduckgo.netguard.test

import android.util.Log
import com.duckduckgo.vpn.network.impl.models.Packet
import java.nio.ByteBuffer

class NetguardInterface {
    external fun isValidUtf8(buffer: ByteBuffer): Boolean

    init {
        try {
            System.loadLibrary("netguard")
        } catch (ignored: Throwable) {
            Log.e("NetguardInterface", "Error loading lib")
        }
    }

    // Just a dummy function to ensure we can pull Kotlin classes from Netguard
    fun testPacket(): Boolean {
        val p = Packet()
        p.allowed = false
        return p.allowed
    }
}