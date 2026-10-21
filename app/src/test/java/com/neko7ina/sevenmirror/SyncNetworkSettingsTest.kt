package com.neko7ina.sevenmirror

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The saved network settings decide whether a connection may exist at all, so the reading of a
 * route is pinned here rather than in a socket test: getting it wrong either sends over a network
 * the user switched off, or holds a healthy device offline on one they allowed.
 */
class SyncNetworkSettingsTest {
    @Test
    fun `a new install synchronizes over every network`() {
        val settings = SyncNetworkSettings()
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(settings, TRANSPORT_WIFI))
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(settings, TRANSPORT_CELLULAR))
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(settings, TRANSPORT_WIFI or TRANSPORT_VPN))
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(settings, TRANSPORT_CELLULAR or TRANSPORT_VPN))
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(settings, TRANSPORT_ETHERNET))
    }

    @Test
    fun `a switched off network holds sync only on that network`() {
        val withoutWifi = SyncNetworkSettings(wifi = false)
        assertEquals(NetworkSyncBlock.WIFI, networkSyncBlock(withoutWifi, TRANSPORT_WIFI))
        assertEquals(NetworkSyncBlock.WIFI, networkSyncBlock(withoutWifi, TRANSPORT_WIFI or TRANSPORT_VPN))
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(withoutWifi, TRANSPORT_CELLULAR or TRANSPORT_VPN))
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(withoutWifi, TRANSPORT_ETHERNET))

        val withoutCellular = SyncNetworkSettings(cellular = false)
        assertEquals(NetworkSyncBlock.CELLULAR, networkSyncBlock(withoutCellular, TRANSPORT_CELLULAR))
        assertEquals(
            NetworkSyncBlock.CELLULAR,
            networkSyncBlock(withoutCellular, TRANSPORT_CELLULAR or TRANSPORT_VPN),
        )
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(withoutCellular, TRANSPORT_WIFI or TRANSPORT_VPN))
    }

    @Test
    fun `having no default network stays an outage rather than a hold`() {
        val settings = SyncNetworkSettings(wifi = false, cellular = false)
        assertEquals(NetworkSyncBlock.NONE, networkSyncBlock(settings, null))
    }
}
