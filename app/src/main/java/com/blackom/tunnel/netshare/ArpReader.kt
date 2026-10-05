package com.blackom.tunnel.netshare

import java.io.File
import java.io.IOException
import java.util.Locale
import java.util.concurrent.TimeUnit

/**
 * Reads the IPv4 ARP table from `/proc/net/arp`. When that file is missing or only
 * contains incomplete rows, falls back to the kernel IP neighbor cache (`ip neigh`),
 * which is what current Android releases expose for IPv4 and IPv6 neighbors.
 */
class ArpReader(
    private val procNetArp: () -> String? = { readProcNetArp() },
    private val neighborTable: () -> String? = { readNeighborTable() },
    private val cacheMillis: Long = 2_000,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private var cached: List<ArpEntry> = emptyList()
    private var cachedAt: Long = Long.MIN_VALUE

    fun read(): List<ArpEntry> {
        val now = clock()
        if (cacheMillis > 0 && cachedAt != Long.MIN_VALUE && now - cachedAt < cacheMillis) {
            return cached
        }
        val fresh = load()
        cached = fresh
        cachedAt = now
        return fresh
    }

    private fun load(): List<ArpEntry> {
        val fromProc = parseProcNetArp(procNetArp())
        if (fromProc.isNotEmpty()) return fromProc
        return parseNeighborTable(neighborTable())
    }

    private companion object {
        fun readProcNetArp(): String? {
            return try {
                val file = File("/proc/net/arp")
                if (!file.isFile || !file.canRead()) null else file.readText()
            } catch (_: IOException) {
                null
            }
        }

        fun readNeighborTable(): String? {
            val commands = listOf(
                listOf("ip", "neigh", "show"),
                listOf("/system/bin/ip", "neigh", "show"),
            )
            for (command in commands) {
                val text = runCommand(command)
                if (!text.isNullOrBlank()) return text
            }
            return null
        }

        fun runCommand(command: List<String>): String? {
            return try {
                val process = ProcessBuilder(command).redirectErrorStream(true).start()
                val text = process.inputStream.bufferedReader().use { it.readText() }
                if (!process.waitFor(1_500, TimeUnit.MILLISECONDS)) {
                    process.destroyForcibly()
                    null
                } else if (process.exitValue() == 0) {
                    text
                } else {
                    null
                }
            } catch (_: Exception) {
                null
            }
        }
    }
}

data class ArpEntry(
    val ip: String,
    val mac: String,
    val networkInterface: String,
)

internal fun parseProcNetArp(text: String?): List<ArpEntry> {
    if (text.isNullOrBlank()) return emptyList()
    val entries = LinkedHashMap<String, ArpEntry>()
    for (raw in text.lineSequence()) {
        val line = raw.trim()
        if (line.isEmpty()) continue
        val tokens = line.split(Regex("\\s+"))
        if (tokens.size < 6 || tokens[0].equals("IP", ignoreCase = true)) continue
        val flags = tokens[2].removePrefix("0x").removePrefix("0X").toIntOrNull(16) ?: 0
        if (flags == 0) continue
        val mac = normalizeMac(tokens[3]) ?: continue
        val iface = tokens[5]
        if (iface.isBlank() || iface == "*") continue
        entries[tokens[0]] = ArpEntry(tokens[0], mac, iface)
    }
    return entries.values.toList()
}

internal fun parseNeighborTable(text: String?): List<ArpEntry> {
    if (text.isNullOrBlank()) return emptyList()
    val entries = LinkedHashMap<String, ArpEntry>()
    for (raw in text.lineSequence()) {
        val line = raw.trim()
        if (line.isEmpty()) continue
        val tokens = line.split(Regex("\\s+"))
        if (tokens.size < 4) continue
        val state = tokens.last().uppercase(Locale.US)
        if (state in INCOMPLETE_NEIGHBOR_STATES) continue
        val dev = tokens.indexOf("dev")
        val lladdr = tokens.indexOf("lladdr")
        if (dev < 0 || lladdr < 0) continue
        val iface = tokens.getOrNull(dev + 1) ?: continue
        val mac = normalizeMac(tokens.getOrNull(lladdr + 1)) ?: continue
        entries[tokens[0]] = ArpEntry(tokens[0], mac, iface)
    }
    return entries.values.toList()
}

private val INCOMPLETE_NEIGHBOR_STATES = setOf("FAILED", "INCOMPLETE", "NONE")

private fun normalizeMac(raw: String?): String? {
    val mac = raw?.trim()?.lowercase(Locale.US) ?: return null
    if (!MAC_PATTERN.matches(mac) || mac == "00:00:00:00:00:00") return null
    return mac
}

private val MAC_PATTERN = Regex("""[0-9a-f]{2}(?::[0-9a-f]{2}){5}""")
