package com.duckduckgo.netguardtester

import android.util.Log
import java.nio.ByteBuffer
import kotlin.system.exitProcess

class NetguardInterface {
    external fun isValidUtf8(buffer: ByteBuffer): Boolean

    init {
        try {
            System.loadLibrary("netguardtester")
        } catch (ignored: Throwable) {
            Log.e("NetguardInterface", "Error loading lib")
        }
    }
}