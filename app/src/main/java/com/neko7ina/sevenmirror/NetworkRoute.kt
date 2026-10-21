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

/** Which networks the user lets this device synchronize over. Both are on for a new install. */
internal data class SyncNetworkSettings(val wifi: Boolean = true, val cellular: Boolean = true)

/**
 * The network a saved setting puts off-limits right now, or [NONE] when synchronization may run.
 *
 * The value names the network that is excluded, so the screen can say which setting is holding the
 * device offline instead of reporting a generic outage.
 */
internal enum class NetworkSyncBlock { NONE, WIFI, CELLULAR }

/**
 * Reads a route's transports against the saved network settings.
 *
 * A VPN keeps the transport underneath it in the same capabilities (the measured trace showed
 * `WIFI|VPN` and `CELLULAR|VPN`), so the underlying network decides and the tunnel does not make
 * mobile data look like an unmetered route. Ethernet and Bluetooth are always allowed: the setting
 * only speaks about the two networks a user chooses between. Failures and missing routes are not
 * a policy decision at all, so they read as [NetworkSyncBlock.NONE] and keep their ordinary
 * offline handling.
 */
internal fun networkSyncBlock(settings: SyncNetworkSettings, transports: Int?): NetworkSyncBlock {
    if (transports == null) return NetworkSyncBlock.NONE
    val wifi = transports and TRANSPORT_WIFI != 0
    val cellular = transports and TRANSPORT_CELLULAR != 0
    val ethernet = transports and TRANSPORT_ETHERNET != 0
    if (wifi && !settings.wifi) return NetworkSyncBlock.WIFI
    if (cellular && !wifi && !ethernet && !settings.cellular) return NetworkSyncBlock.CELLULAR
    return NetworkSyncBlock.NONE
}

/** Transports carried by [NetworkRoute.transports]. Values are private to this application. */
internal const val TRANSPORT_WIFI = 1
internal const val TRANSPORT_CELLULAR = 2
internal const val TRANSPORT_ETHERNET = 4
internal const val TRANSPORT_BLUETOOTH = 8
internal const val TRANSPORT_VPN = 16
