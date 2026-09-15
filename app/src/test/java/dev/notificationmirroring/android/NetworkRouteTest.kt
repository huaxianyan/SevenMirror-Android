package dev.notificationmirroring.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The coordinator retires a connection when the observed route differs from the route the
 * connection is bound to. These cases pin what "differs" means, because getting it wrong either
 * waits tens of seconds for a dead socket or retires a healthy connection.
 */
class NetworkRouteTest {
    @Test
    fun anUnchangedRouteIsNotARouteChange() {
        val bound = NetworkRoute(handle = 262L, transports = TRANSPORT_WIFI or TRANSPORT_VPN)
        val observed = NetworkRoute(handle = 262L, transports = TRANSPORT_WIFI or TRANSPORT_VPN)
        assertFalse(observed != bound)
    }

    @Test
    fun aVpnKeepsItsHandleWhileTheTransportUnderneathChanges() {
        // The measured trace: one Clash Meta handle on both sides of a Wi-Fi to cellular switch.
        val bound = NetworkRoute(handle = 1128687128589L, transports = TRANSPORT_WIFI or TRANSPORT_VPN)
        val observed =
            NetworkRoute(handle = 1128687128589L, transports = TRANSPORT_CELLULAR or TRANSPORT_VPN)
        assertTrue(observed != bound)
    }

    @Test
    fun aDifferentDefaultNetworkIsARouteChangeWithUnchangedTransports() {
        val bound = NetworkRoute(handle = 287L, transports = TRANSPORT_WIFI)
        val observed = NetworkRoute(handle = 288L, transports = TRANSPORT_WIFI)
        assertTrue(observed != bound)
    }

    @Test
    fun losingEveryRemainingRouteIsARouteChange() {
        val bound: NetworkRoute? = NetworkRoute(handle = 287L, transports = TRANSPORT_WIFI)
        val observed: NetworkRoute? = null
        assertTrue(observed != bound)
    }

    @Test
    fun transportsAreReadAsBits() {
        val route = NetworkRoute(handle = 1L, transports = TRANSPORT_WIFI or TRANSPORT_VPN)
        assertTrue(route.hasTransport(TRANSPORT_WIFI))
        assertTrue(route.hasTransport(TRANSPORT_VPN))
        assertFalse(route.hasTransport(TRANSPORT_CELLULAR))
        assertFalse(route.hasTransport(TRANSPORT_ETHERNET))
        assertFalse(route.hasTransport(TRANSPORT_BLUETOOTH))
    }

    @Test
    fun transportValuesStayDistinctBits() {
        val transports = listOf(
            TRANSPORT_WIFI, TRANSPORT_CELLULAR, TRANSPORT_ETHERNET,
            TRANSPORT_BLUETOOTH, TRANSPORT_VPN,
        )
        assertEquals(transports.size, transports.distinct().size)
        transports.forEach { assertEquals(1, Integer.bitCount(it)) }
    }
}
