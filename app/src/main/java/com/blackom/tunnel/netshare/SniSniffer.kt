package com.blackom.tunnel.netshare

import java.io.InputStream
import java.util.Locale

/**
 * Reads a TLS ClientHello (record content type 0x16, handshake type 0x01)
 * and returns the first host_name in the server_name extension.
 */
object SniSniffer {
    const val MAX_RECORD_BYTES: Int = 16_384

    fun extractHost(bytes: ByteArray): String? = (parse(bytes) as? SniParseResult.Host)?.name

    fun extractHost(input: InputStream): String? = (parse(input) as? SniParseResult.Host)?.name

    fun parse(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): SniParseResult {
        if (offset < 0 || length < 0 || offset > bytes.size || offset + length > bytes.size) {
            return SniParseResult.NotFound
        }
        if (length < 5) {
            if (length > 0 && u8(bytes, offset) != HANDSHAKE_RECORD) return SniParseResult.NotFound
            return SniParseResult.Incomplete(5)
        }
        val contentType = u8(bytes, offset)
        val major = u8(bytes, offset + 1)
        val recordLength = u16(bytes, offset + 3)
        if (contentType != HANDSHAKE_RECORD || major != 3) return SniParseResult.NotFound
        if (recordLength <= 0 || recordLength > MAX_RECORD_BYTES) return SniParseResult.NotFound
        val total = 5 + recordLength
        if (length < total) return SniParseResult.Incomplete(total)

        val recordEnd = offset + total
        var cursor = offset + 5
        if (u8(bytes, cursor) != CLIENT_HELLO) return SniParseResult.NotFound
        val helloLength = u24(bytes, cursor + 1)
        cursor += 4
        val helloEnd = cursor + helloLength
        if (helloLength < 34 || helloEnd > recordEnd) return SniParseResult.NotFound

        cursor += 2 + 32
        if (cursor >= helloEnd) return SniParseResult.NotFound
        val sessionLength = u8(bytes, cursor)
        cursor += 1 + sessionLength
        if (cursor + 2 > helloEnd) return SniParseResult.NotFound
        val cipherLength = u16(bytes, cursor)
        cursor += 2 + cipherLength
        if (cursor + 1 > helloEnd) return SniParseResult.NotFound
        val compressionLength = u8(bytes, cursor)
        cursor += 1 + compressionLength
        if (cursor == helloEnd) return SniParseResult.NotFound
        if (cursor + 2 > helloEnd) return SniParseResult.NotFound
        val extensionsLength = u16(bytes, cursor)
        cursor += 2
        val extensionsEnd = cursor + extensionsLength
        if (extensionsEnd > helloEnd) return SniParseResult.NotFound

        while (cursor + 4 <= extensionsEnd) {
            val extensionType = u16(bytes, cursor)
            val extensionLength = u16(bytes, cursor + 2)
            cursor += 4
            if (cursor + extensionLength > extensionsEnd) return SniParseResult.NotFound
            if (extensionType == SERVER_NAME_EXTENSION) {
                val host = readServerName(bytes, cursor, cursor + extensionLength) ?: return SniParseResult.NotFound
                return SniParseResult.Host(host)
            }
            cursor += extensionLength
        }
        return SniParseResult.NotFound
    }

    /**
     * Reads one TLS record from [input]. Bytes after that record stay in the stream.
     * A short stream returns [SniParseResult.Incomplete].
     */
    fun parse(input: InputStream): SniParseResult {
        val header = ByteArray(5)
        val headerRead = readFully(input, header)
        if (headerRead < 5) return SniParseResult.Incomplete(5)
        val recordLength = u16(header, 3)
        if (u8(header, 0) != HANDSHAKE_RECORD || u8(header, 1) != 3) return SniParseResult.NotFound
        if (recordLength <= 0 || recordLength > MAX_RECORD_BYTES) return SniParseResult.NotFound
        val body = ByteArray(recordLength)
        val bodyRead = readFully(input, body)
        if (bodyRead < recordLength) return SniParseResult.Incomplete(5 + recordLength)
        return parse(header + body)
    }

    private fun readServerName(bytes: ByteArray, start: Int, end: Int): String? {
        if (end - start < 5) return null
        val listLength = u16(bytes, start)
        var cursor = start + 2
        val listEnd = cursor + listLength
        if (listEnd > end) return null
        while (cursor + 3 <= listEnd) {
            val nameType = u8(bytes, cursor)
            val nameLength = u16(bytes, cursor + 1)
            cursor += 3
            if (cursor + nameLength > listEnd) return null
            if (nameType == HOST_NAME_TYPE) {
                return normalizeSni(bytes.copyOfRange(cursor, cursor + nameLength))
            }
            cursor += nameLength
        }
        return null
    }

    private fun normalizeSni(raw: ByteArray): String? {
        val text = String(raw, Charsets.UTF_8).trim().trimEnd('.').lowercase(Locale.US)
        if (text.isEmpty() || text.length > 253) return null
        if (text.any { it.isISOControl() || it.isWhitespace() || it == '/' }) return null
        return text
    }

    private fun readFully(input: InputStream, dest: ByteArray): Int {
        var offset = 0
        while (offset < dest.size) {
            val read = input.read(dest, offset, dest.size - offset)
            if (read < 0) return offset
            offset += read
        }
        return offset
    }

    private fun u8(bytes: ByteArray, index: Int): Int = bytes[index].toInt() and 0xFF

    private fun u16(bytes: ByteArray, index: Int): Int = (u8(bytes, index) shl 8) or u8(bytes, index + 1)

    private fun u24(bytes: ByteArray, index: Int): Int {
        return (u8(bytes, index) shl 16) or (u8(bytes, index + 1) shl 8) or u8(bytes, index + 2)
    }

    private const val HANDSHAKE_RECORD: Int = 0x16
    private const val CLIENT_HELLO: Int = 0x01
    private const val SERVER_NAME_EXTENSION: Int = 0x0000
    private const val HOST_NAME_TYPE: Int = 0x00
}

sealed interface SniParseResult {
    data class Host(val name: String) : SniParseResult

    data class Incomplete(val neededBytes: Int) : SniParseResult

    data object NotFound : SniParseResult
}
