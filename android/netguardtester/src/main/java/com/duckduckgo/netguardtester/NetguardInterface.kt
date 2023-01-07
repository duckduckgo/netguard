package com.duckduckgo.netguardtester

import android.util.Log
import kotlin.system.exitProcess

class NetguardInterface {
    external fun testx(): Boolean

    init {
        try {
            System.loadLibrary("netguardtester")
        } catch (ignored: Throwable) {
            Log.e("NetguardInterface", "Error loading lib")
        }
    }
}