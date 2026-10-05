package com.blackom.tunnel.netshare

import java.util.ArrayDeque
import java.util.Locale
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * In-memory per-client counters.
 *
 * [ClientSnapshot.bytesIn] is data delivered to the client (download).
 * [ClientSnapshot.bytesOut] is data received from the client (upload).
 * Speeds are kilobytes per second over a one-second sliding window (1024-byte KB).
 */
class ClientTrafficTracker(
    private val clock: () -> Long = System::currentTimeMillis,
    private val windowMillis: Long = 1_000,
    private val historyLimit: Int = 50,
) {
    private val lock = Any()
    private val states = LinkedHashMap<String, MutableClient>()
    private var lastTick: Long = clock()
    private val listeners = CopyOnWriteArrayList<() -> Unit>()
    private val _snapshots = MutableStateFlow<List<ClientSnapshot>>(emptyList())
    val snapshots: StateFlow<List<ClientSnapshot>> = _snapshots.asStateFlow()

    fun addListener(listener: () -> Unit) {
        listeners += listener
    }

    fun openClient(ip: String) {
        if (ip.isBlank()) return
        commit(clock()) {
            if (states.containsKey(ip)) return@commit false
            states[ip] = MutableClient(ip)
            true
        }
    }

    fun updateEndpoint(ip: String, mac: String?, networkInterface: String?, hostname: String?) {
        commit(lastTick) {
            val state = states[ip] ?: return@commit false
            var changed = false
            if (!mac.isNullOrBlank() && state.mac != mac) {
                state.mac = mac
                changed = true
            }
            if (!networkInterface.isNullOrBlank() && state.networkInterface != networkInterface) {
                state.networkInterface = networkInterface
                changed = true
            }
            if (!hostname.isNullOrBlank() && state.hostname != hostname) {
                state.hostname = hostname
                changed = true
            }
            changed
        }
    }

    fun recordDownload(ip: String, bytes: Int, atMillis: Long = clock()) {
        record(ip, bytes, atMillis, upload = false)
    }

    fun recordUpload(ip: String, bytes: Int, atMillis: Long = clock()) {
        record(ip, bytes, atMillis, upload = true)
    }

    fun recordDomain(ip: String, domain: String, atMillis: Long = clock()) {
        val normalized = normalizeNetworkHost(domain) ?: return
        if (ip.isBlank()) return
        commit(atMillis) {
            val state = states.getOrPut(ip) { MutableClient(ip) }
            state.activeDomain = normalized
            val latest = state.history.firstOrNull()
            if (latest?.domain == normalized) {
                state.history[0] = DomainVisit(normalized, atMillis)
            } else {
                state.history.add(0, DomainVisit(normalized, atMillis))
                while (state.history.size > historyLimit) {
                    state.history.removeAt(state.history.lastIndex)
                }
            }
            true
        }
    }

    fun refresh(atMillis: Long = clock()) {
        commit(atMillis) { true }
    }

    fun snapshot(ip: String): ClientSnapshot? = snapshots.value.firstOrNull { it.ip == ip }

    private fun record(ip: String, bytes: Int, atMillis: Long, upload: Boolean) {
        if (ip.isBlank() || bytes <= 0) return
        commit(atMillis) {
            val state = states.getOrPut(ip) { MutableClient(ip) }
            if (upload) {
                state.bytesOut += bytes
                state.upload.add(atMillis, bytes, windowMillis)
            } else {
                state.bytesIn += bytes
                state.download.add(atMillis, bytes, windowMillis)
            }
            true
        }
    }

    private fun commit(atMillis: Long, mutate: () -> Boolean) {
        val published = synchronized(lock) {
            lastTick = atMillis
            if (!mutate()) return
            states.values.map { it.freeze(atMillis, windowMillis) }.sortedBy { it.ip }
        }
        _snapshots.value = published
        for (listener in listeners) {
            listener()
        }
    }

    private class MutableClient(val ip: String) {
        var mac: String? = null
        var networkInterface: String? = null
        var hostname: String? = null
        var activeDomain: String? = null
        val history = ArrayList<DomainVisit>()
        var bytesIn: Long = 0
        var bytesOut: Long = 0
        val download = ByteWindow()
        val upload = ByteWindow()

        fun freeze(now: Long, windowMillis: Long): ClientSnapshot {
            return ClientSnapshot(
                ip = ip,
                mac = mac,
                networkInterface = networkInterface,
                hostname = hostname,
                activeDomain = activeDomain,
                history = history.toList(),
                bytesIn = bytesIn,
                bytesOut = bytesOut,
                downloadKilobytesPerSecond = download.kilobytesPerSecond(now, windowMillis),
                uploadKilobytesPerSecond = upload.kilobytesPerSecond(now, windowMillis),
            )
        }
    }
}

data class DomainVisit(
    val domain: String,
    val timestampMillis: Long,
)

data class ClientSnapshot(
    val ip: String,
    val mac: String?,
    val networkInterface: String?,
    val hostname: String?,
    val activeDomain: String?,
    val history: List<DomainVisit>,
    val bytesIn: Long,
    val bytesOut: Long,
    val downloadKilobytesPerSecond: Double,
    val uploadKilobytesPerSecond: Double,
)

private class ByteWindow {
    private val samples = ArrayDeque<Sample>()

    fun add(now: Long, bytes: Int, windowMillis: Long) {
        prune(now, windowMillis)
        val last = samples.lastOrNull()
        if (last != null && last.at == now) {
            samples.removeLast()
            samples.addLast(Sample(now, last.bytes + bytes))
        } else {
            samples.addLast(Sample(now, bytes.toLong()))
        }
    }

    fun kilobytesPerSecond(now: Long, windowMillis: Long): Double {
        if (windowMillis <= 0L) return 0.0
        val bytes = bytesWithin(now, windowMillis)
        val perSecond = bytes * 1_000.0 / windowMillis.toDouble()
        return perSecond / 1_024.0
    }

    private fun bytesWithin(now: Long, windowMillis: Long): Long {
        prune(now, windowMillis)
        var total = 0L
        for (sample in samples) total += sample.bytes
        return total
    }

    private fun prune(now: Long, windowMillis: Long) {
        val oldest = now - windowMillis
        while (samples.isNotEmpty() && samples.first().at < oldest) {
            samples.removeFirst()
        }
    }

    private data class Sample(val at: Long, val bytes: Long)
}

internal fun normalizeNetworkHost(raw: String): String? {
    var value = raw.trim()
    if (value.isEmpty()) return null
    if (value.any { it == '\r' || it == '\n' || it == '\u0000' || it.isWhitespace() }) return null
    if (value.startsWith("[")) {
        val end = value.indexOf(']')
        if (end <= 1) return null
        value = value.substring(1, end)
    } else if (value.count { it == ':' } == 1) {
        val colon = value.indexOf(':')
        val port = value.substring(colon + 1)
        if (port.isNotEmpty() && port.all { it.isDigit() }) {
            value = value.substring(0, colon)
        }
    }
    value = value.trimEnd('.').lowercase(Locale.US)
    if (value.isEmpty() || value.length > 253) return null
    return value
}
