package com.duckduckgo.netguardtester

import android.util.Log
import kotlin.system.exitProcess

class NetguardInterface {
    external fun testx(): String

    fun testWrapper(): String {
        return testx()
    }

    init {
        try {
            System.loadLibrary("netguard")
        } catch (ignored: Throwable) {
            Log.e("NetguardInterface", "Error loading lib")
        }
    }
}