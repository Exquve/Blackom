package com.blackom.tunnel.core

import java.util.Locale

/**
 * Values substituted for payload tokens and used when standard HTTP headers are injected.
 *
 * [host] is the remote HTTP host. It may differ from the TCP connect address.
 * [onlineHost] becomes the `X-Online-Host` value; when null, [host] is used.
 * Websocket `Upgrade` / `Connection` headers are injected only when [websocketUpgrade] is set,
 * so a plain CONNECT payload is not rewritten into a websocket handshake.
 */
data class PayloadContext(
    val host: String,
    val port: Int,
    val protocol: String = "HTTP/1.1",
    val onlineHost: String? = null,
    val injectStandardHeaders: Boolean = true,
    val websocketUpgrade: Boolean = false,
)

enum class ChunkWriteMode {
    /** Leading bytes, written as their own flush with no extra delay. */
    NORMAL,

    /** Bytes that followed a `[split]` marker. The injector pauses, then writes. */
    SPLIT,

    /** Bytes that followed an `[instant_split]` marker. Written and flushed immediately. */
    INSTANT_SPLIT,
}

class PayloadChunk(
    val bytes: ByteArray,
    val writeMode: ChunkWriteMode,
) {
    fun text(): String = String(bytes, Charsets.ISO_8859_1)
}

class ParsedPayload(
    val chunks: List<PayloadChunk>,
    /** Token-substituted payload after header injection, with split markers removed. */
    val normalized: String,
) {
    val totalBytes: Int get() = chunks.sumOf { it.bytes.size }
}

class PayloadParseException(message: String) : IllegalArgumentException(message)

object PayloadParser {
    private val tokenPattern = Regex("\\[([A-Za-z0-9_]+)]")
    private val requestLinePattern = Regex(
        """^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|CONNECT|PATCH)\s+\S+\s+HTTP/1\.[01]$""",
        RegexOption.IGNORE_CASE,
    )
    private val knownTokens = setOf(
        "crlf",
        "lf",
        "cr",
        "protocol",
        "host",
        "port",
        "host_port",
        "split",
        "instant_split",
    )

    fun validate(template: String, context: PayloadContext): List<String> {
        val errors = ArrayList<String>()
        if (context.host.isBlank()) {
            errors += "Host is empty"
        } else if (containsControlCharacter(context.host)) {
            errors += "Host contains a control character"
        }
        if (context.port !in 1..65535) {
            errors += "Port ${context.port} is outside 1..65535"
        }
        if (context.protocol.isBlank()) {
            errors += "Protocol is empty"
        } else if (containsControlCharacter(context.protocol)) {
            errors += "Protocol contains a control character"
        }
        val onlineHost = context.onlineHost
        if (onlineHost != null && onlineHost.isNotBlank() && containsControlCharacter(onlineHost)) {
            errors += "X-Online-Host contains a control character"
        }
        val unknown = unknownTokens(template)
        if (unknown.isNotEmpty()) {
            errors += "Unknown payload tokens: ${unknown.joinToString(", ")}"
        }
        return errors
    }

    fun parse(template: String, context: PayloadContext): ParsedPayload {
        val errors = validate(template, context)
        if (errors.isNotEmpty()) {
            throw PayloadParseException(errors.joinToString("; "))
        }
        if (template.isBlank()) {
            return ParsedPayload(emptyList(), "")
        }
        val substituted = substitute(template, context)
        val (stripped, markers) = extractMarkers(substituted)
        val injection = injectHeaders(stripped, context)
        val shifted = shiftMarkers(markers, injection.inserts)
        val woven = weaveMarkers(injection.text, shifted)
        return ParsedPayload(
            chunks = splitChunks(woven),
            normalized = injection.text,
        )
    }

    private fun unknownTokens(template: String): List<String> {
        return tokenPattern.findAll(template)
            .filter { it.groupValues[1].lowercase(Locale.US) !in knownTokens }
            .map { it.value }
            .distinct()
            .toList()
    }

    private fun substitute(template: String, context: PayloadContext): String {
        val out = StringBuilder()
        var cursor = 0
        for (match in tokenPattern.findAll(template)) {
            out.append(template, cursor, match.range.first)
            when (match.groupValues[1].lowercase(Locale.US)) {
                "crlf" -> out.append("\r\n")
                "lf" -> out.append('\n')
                "cr" -> out.append('\r')
                "protocol" -> out.append(context.protocol)
                "host_port" -> out.append(formatHostPort(context.host, context.port))
                "host" -> out.append(formatHost(context.host))
                "port" -> out.append(context.port.toString())
                "split" -> out.append("[split]")
                "instant_split" -> out.append("[instant_split]")
                else -> out.append(match.value)
            }
            cursor = match.range.last + 1
        }
        out.append(template, cursor, template.length)
        return out.toString()
    }

    private fun extractMarkers(payload: String): Pair<String, List<Marker>> {
        val pattern = Regex("\\[(split|instant_split)]", RegexOption.IGNORE_CASE)
        val markers = ArrayList<Marker>()
        val stripped = StringBuilder()
        var cursor = 0
        for (match in pattern.findAll(payload)) {
            stripped.append(payload, cursor, match.range.first)
            val token = if (match.groupValues[1].equals("instant_split", ignoreCase = true)) {
                "[instant_split]"
            } else {
                "[split]"
            }
            markers += Marker(stripped.length, token)
            cursor = match.range.last + 1
        }
        stripped.append(payload, cursor, payload.length)
        return stripped.toString() to markers
    }

    private fun injectHeaders(payload: String, context: PayloadContext): HeaderInjection {
        if (!context.injectStandardHeaders || payload.isEmpty()) {
            return HeaderInjection(payload, emptyList())
        }
        val lineBreak = when {
            payload.contains("\r\n") -> "\r\n"
            payload.contains("\n") -> "\n"
            else -> "\r\n"
        }
        val blankAt = payload.indexOf(lineBreak + lineBreak)
        val headerBlock = if (blankAt >= 0) payload.substring(0, blankAt) else payload
        val lines = headerBlock.split(lineBreak)
        if (lines.isEmpty() || !requestLinePattern.matches(lines.first())) {
            return HeaderInjection(payload, emptyList())
        }

        val inserts = ArrayList<Pair<Int, String>>()
        val connectionEnd = connectionUpgradeIndex(lines, lineBreak)
        if (context.websocketUpgrade && connectionEnd != null) {
            inserts += connectionEnd to ", Upgrade"
        }

        val additions = ArrayList<String>()
        if (!hasHeader(lines, "Host")) {
            additions += "Host: ${hostHeaderValue(lines.first(), context)}"
        }
        if (!hasHeader(lines, "X-Online-Host")) {
            val online = context.onlineHost?.takeIf { it.isNotBlank() } ?: context.host
            additions += "X-Online-Host: ${formatHost(online)}"
        }
        if (context.websocketUpgrade && !hasHeader(lines, "Upgrade")) {
            additions += "Upgrade: websocket"
        }
        if (context.websocketUpgrade && !hasHeader(lines, "Connection")) {
            additions += "Connection: Upgrade"
        }
        if (additions.isNotEmpty()) {
            val at = if (blankAt >= 0) blankAt else payload.length
            val terminator = if (blankAt >= 0) "" else lineBreak
            val block = additions.joinToString(separator = lineBreak, prefix = lineBreak) + terminator
            inserts += at to block
        }
        if (inserts.isEmpty()) {
            return HeaderInjection(payload, emptyList())
        }
        return HeaderInjection(applyInserts(payload, inserts), inserts.map { it.first to it.second.length })
    }

    private fun connectionUpgradeIndex(
        lines: List<String>,
        lineBreak: String,
    ): Int? {
        var position = 0
        for ((index, line) in lines.withIndex()) {
            val lineEnd = position + line.length
            if (index > 0 && headerName(line).equals("Connection", ignoreCase = true)) {
                val value = line.substringAfter(':', "")
                if (!value.contains("Upgrade", ignoreCase = true)) {
                    return lineEnd
                }
                return null
            }
            position = lineEnd
            if (index < lines.lastIndex) {
                position += lineBreak.length
            }
        }
        return null
    }

    private fun applyInserts(text: String, inserts: List<Pair<Int, String>>): String {
        val builder = StringBuilder(text)
        val ordered = inserts.sortedWith(compareBy<Pair<Int, String>> { it.first }.thenBy { inserts.indexOf(it) })
        for ((at, value) in ordered.asReversed()) {
            builder.insert(at, value)
        }
        return builder.toString()
    }

    private fun shiftMarkers(markers: List<Marker>, inserts: List<Pair<Int, Int>>): List<Marker> {
        if (inserts.isEmpty()) return markers
        return markers.map { marker ->
            var delta = 0
            for ((at, length) in inserts) {
                if (marker.index >= at) delta += length
            }
            marker.copy(index = marker.index + delta)
        }
    }

    private fun weaveMarkers(text: String, markers: List<Marker>): String {
        val out = StringBuilder()
        var cursor = 0
        for (marker in markers.sortedBy { it.index }) {
            val at = marker.index.coerceIn(cursor, text.length)
            out.append(text, cursor, at)
            out.append(marker.token)
            cursor = at
        }
        out.append(text, cursor, text.length)
        return out.toString()
    }

    private fun splitChunks(payload: String): List<PayloadChunk> {
        val pattern = Regex("\\[(split|instant_split)]", RegexOption.IGNORE_CASE)
        val chunks = ArrayList<PayloadChunk>()
        var mode = ChunkWriteMode.NORMAL
        var cursor = 0
        for (match in pattern.findAll(payload)) {
            appendChunk(chunks, payload.substring(cursor, match.range.first), mode)
            mode = if (match.groupValues[1].equals("instant_split", ignoreCase = true)) {
                ChunkWriteMode.INSTANT_SPLIT
            } else {
                ChunkWriteMode.SPLIT
            }
            cursor = match.range.last + 1
        }
        appendChunk(chunks, payload.substring(cursor), mode)
        return chunks
    }

    private fun appendChunk(chunks: MutableList<PayloadChunk>, text: String, mode: ChunkWriteMode) {
        if (text.isEmpty()) return
        chunks += PayloadChunk(text.toByteArray(Charsets.ISO_8859_1), mode)
    }

    private fun hasHeader(lines: List<String>, name: String): Boolean {
        return lines.drop(1).any { headerName(it).equals(name, ignoreCase = true) }
    }

    private fun headerName(line: String): String = line.substringBefore(':').trim()

    private fun hostHeaderValue(requestLine: String, context: PayloadContext): String {
        val method = requestLine.substringBefore(' ').uppercase(Locale.US)
        val formatted = formatHost(context.host)
        return if (method == "CONNECT" || (context.port != 80 && context.port != 443)) {
            "$formatted:${context.port}"
        } else {
            formatted
        }
    }

    private fun containsControlCharacter(value: String): Boolean {
        return value.any { it == '\r' || it == '\n' || it == '\u0000' }
    }

    private data class Marker(val index: Int, val token: String)

    private data class HeaderInjection(
        val text: String,
        val inserts: List<Pair<Int, Int>>,
    )

    internal fun formatHost(host: String): String {
        val trimmed = host.trim()
        if (trimmed.startsWith('[') && trimmed.endsWith(']')) return trimmed
        return if (trimmed.contains(':')) "[$trimmed]" else trimmed
    }

    internal fun formatHostPort(host: String, port: Int): String = "${formatHost(host)}:$port"
}
