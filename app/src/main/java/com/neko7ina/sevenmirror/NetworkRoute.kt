package com.neko7ina.sevenmirror

/**
 * Identity of the route a connection is bound to.
 *
 * Transports are part of the identity, not decoration. A VPN that owns the default network keeps
 * one network handle while the transport underneath it changes: the controlled Wi-Fi recovery
 * trace showed a single VPN handle across a Wi-Fi to cellular switch while its transports flipped
 * from `WIFI|VPN` to `CELLULAR|VPN`. A handle-only comparison therefore misses exactly the
 * transitions this application has to detect.
 *
 * Signal strength, bandwidth estimates, metering and validation are deliberately absent. They
 * change on an unchanged route, and treating them as route changes would retire a healthy
 * connection.
 */
internal data class NetworkRoute(val handle: Long, val transports: Int) {
    fun hasTransport(transport: Int): Boolean = transports and transport != 0
}

/** Transports carried by [NetworkRoute.transports]. Values are private to this application. */
internal const val TRANSPORT_WIFI = 1
internal const val TRANSPORT_CELLULAR = 2
internal const val TRANSPORT_ETHERNET = 4
internal const val TRANSPORT_BLUETOOTH = 8
internal const val TRANSPORT_VPN = 16
