package com.blackom.tunnel.vpn

/**
 * Build marker for the tun2socks session. Packet forwarding itself runs in
 * [Tun2SocksBridge]; this symbol only identifies the native library that ships
 * with the process.
 */
internal class Tun2SocksNative private constructor() {
    companion object {
        val version: String by lazy { loadVersion() }

        @JvmStatic
        private external fun nativeVersion(): String

        private fun loadVersion(): String {
            return try {
                System.loadLibrary("blackom_native")
                nativeVersion()
            } catch (error: Throwable) {
                "blackom-tun2socks-unavailable"
            }
        }
    }
}
