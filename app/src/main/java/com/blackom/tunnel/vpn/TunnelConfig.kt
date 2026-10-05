package com.blackom.tunnel.vpn

import android.content.Context
import android.content.Intent

data class TunnelRoute(
    val address: String,
    val prefixLength: Int,
)

data class TunnelConfig(
    val sessionName: String = DEFAULT_SESSION,
    val address: String = DEFAULT_ADDRESS,
    val prefixLength: Int = DEFAULT_PREFIX,
    val mtu: Int = DEFAULT_MTU,
    val dns: List<String> = DEFAULT_DNS,
    val routes: List<TunnelRoute> = DEFAULT_ROUTES,
    val socksHost: String = DEFAULT_SOCKS_HOST,
    val socksPort: Int = DEFAULT_SOCKS_PORT,
    val allowedApplications: List<String> = emptyList(),
    val disallowedApplications: List<String> = emptyList(),
) {
    fun validate(): String? {
        if (sessionName.isBlank()) return "Session name is empty"
        if (prefixLength !in 0..32) return "IPv4 prefix must be between 0 and 32"
        if (mtu !in MIN_MTU..MAX_MTU) return "MTU must be between $MIN_MTU and $MAX_MTU"
        if (socksHost.isBlank() || socksPort !in 1..65535) return "SOCKS5 endpoint is invalid"
        if (!isIpv4(address)) return "Tunnel address is not a valid IPv4 address"
        if (dns.any { server -> !isIpv4(server) }) return "DNS server is not a valid IPv4 address"
        if (routes.isEmpty()) return "At least one route is required"
        if (routes.any { route -> route.prefixLength !in 0..32 || !isIpv4(route.address) }) {
            return "Route table contains an invalid IPv4 route"
        }
        if (allowedApplications.any { it.isNotBlank() } && disallowedApplications.any { it.isNotBlank() }) {
            return "Choose either an allow list or a disallow list"
        }
        return null
    }

    fun toStartIntent(context: Context): Intent {
        return Intent(context, TunnelVpnService::class.java)
            .setAction(TunnelVpnService.ACTION_START)
            .putExtra(EXTRA_SESSION, sessionName)
            .putExtra(EXTRA_ADDRESS, address)
            .putExtra(EXTRA_PREFIX, prefixLength)
            .putExtra(EXTRA_MTU, mtu)
            .putExtra(EXTRA_DNS, dns.toTypedArray())
            .putExtra(EXTRA_ROUTE_ADDRESSES, routes.map { it.address }.toTypedArray())
            .putExtra(EXTRA_ROUTE_PREFIXES, routes.map { it.prefixLength }.toIntArray())
            .putExtra(EXTRA_SOCKS_HOST, socksHost)
            .putExtra(EXTRA_SOCKS_PORT, socksPort)
            .putExtra(EXTRA_ALLOWED, allowedApplications.toTypedArray())
            .putExtra(EXTRA_DISALLOWED, disallowedApplications.toTypedArray())
    }

    companion object {
        const val DEFAULT_SESSION: String = "Blackom"
        const val DEFAULT_ADDRESS: String = "10.0.0.2"
        const val DEFAULT_PREFIX: Int = 24
        const val DEFAULT_MTU: Int = 1500
        const val DEFAULT_SOCKS_HOST: String = "127.0.0.1"
        const val DEFAULT_SOCKS_PORT: Int = 10808
        const val MIN_MTU: Int = 576
        const val MAX_MTU: Int = 9000
        val DEFAULT_DNS: List<String> = listOf("1.1.1.1", "8.8.8.8")
        val DEFAULT_ROUTES: List<TunnelRoute> = listOf(TunnelRoute("0.0.0.0", 0))

        const val EXTRA_SESSION: String = "com.blackom.tunnel.vpn.extra.SESSION"
        const val EXTRA_ADDRESS: String = "com.blackom.tunnel.vpn.extra.ADDRESS"
        const val EXTRA_PREFIX: String = "com.blackom.tunnel.vpn.extra.PREFIX"
        const val EXTRA_MTU: String = "com.blackom.tunnel.vpn.extra.MTU"
        const val EXTRA_DNS: String = "com.blackom.tunnel.vpn.extra.DNS"
        const val EXTRA_ROUTE_ADDRESSES: String = "com.blackom.tunnel.vpn.extra.ROUTE_ADDRESSES"
        const val EXTRA_ROUTE_PREFIXES: String = "com.blackom.tunnel.vpn.extra.ROUTE_PREFIXES"
        const val EXTRA_SOCKS_HOST: String = "com.blackom.tunnel.vpn.extra.SOCKS_HOST"
        const val EXTRA_SOCKS_PORT: String = "com.blackom.tunnel.vpn.extra.SOCKS_PORT"
        const val EXTRA_ALLOWED: String = "com.blackom.tunnel.vpn.extra.ALLOWED"
        const val EXTRA_DISALLOWED: String = "com.blackom.tunnel.vpn.extra.DISALLOWED"

        fun fromIntent(intent: Intent?): TunnelConfig {
            val defaults = TunnelConfig()
            if (intent == null) return defaults
            val routeAddresses = intent.getStringArrayExtra(EXTRA_ROUTE_ADDRESSES)
            val routePrefixes = intent.getIntArrayExtra(EXTRA_ROUTE_PREFIXES)
            val routes = if (routeAddresses != null && routePrefixes != null && routeAddresses.size == routePrefixes.size) {
                routeAddresses.mapIndexed { index, address -> TunnelRoute(address, routePrefixes[index]) }
            } else {
                defaults.routes
            }
            return TunnelConfig(
                sessionName = intent.getStringExtra(EXTRA_SESSION) ?: defaults.sessionName,
                address = intent.getStringExtra(EXTRA_ADDRESS) ?: defaults.address,
                prefixLength = intent.getIntExtra(EXTRA_PREFIX, defaults.prefixLength),
                mtu = intent.getIntExtra(EXTRA_MTU, defaults.mtu),
                dns = intent.getStringArrayExtra(EXTRA_DNS)?.toList() ?: defaults.dns,
                routes = routes,
                socksHost = intent.getStringExtra(EXTRA_SOCKS_HOST) ?: defaults.socksHost,
                socksPort = intent.getIntExtra(EXTRA_SOCKS_PORT, defaults.socksPort),
                allowedApplications = intent.getStringArrayExtra(EXTRA_ALLOWED)?.toList().orEmpty(),
                disallowedApplications = intent.getStringArrayExtra(EXTRA_DISALLOWED)?.toList().orEmpty(),
            )
        }

        private fun isIpv4(value: String): Boolean {
            return try {
                ipv4Bytes(value)
                true
            } catch (_: IllegalArgumentException) {
                false
            }
        }
    }
}
