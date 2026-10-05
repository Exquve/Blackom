package com.blackom.tunnel.core

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/**
 * Opens a raw TCP connection and, when requested, a TLS session whose SNI
 * hostname can differ from the TCP destination. The parsed payload is then
 * written in separate flushes so `[split]` and `[instant_split]` stay on
 * distinct socket writes.
 */
class SocketInjector(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    suspend fun inject(request: InjectRequest): InjectedConnection = withContext(ioDispatcher) {
        validateRequest(request)
        val parsed = parsePayload(request)
        var tcp: Socket? = null
        var tls: SSLSocket? = null
        try {
            val connected = Socket().also { tcp = it }
            connected.tcpNoDelay = request.tcpNoDelay
            connected.connect(
                InetSocketAddress(request.connectHost, request.connectPort),
                request.connectTimeoutMillis,
            )
            request.onLog("TCP connected ${request.connectHost}:${request.connectPort}")

            val active = if (request.useTls) {
                val sni = resolveSniHost(request)
                wrapTls(connected, sni, request.connectPort).also { ssl ->
                    tls = ssl
                    request.onLog("TLS handshake complete, SNI=$sni")
                }
            } else {
                connected
            }

            coroutineContext[Job]?.invokeOnCompletion { cause ->
                if (cause != null) {
                    runCatching { active.close() }
                }
            }

            val written = writeChunks(active, parsed.chunks, request)
            active.soTimeout = request.readTimeoutMillis
            val response = readHandshakeResponse(active)
            ensureHttpSuccess(response)
            active.soTimeout = 0
            request.onLog("Handshake finished, wrote $written bytes, read ${response.size} bytes")
            InjectedConnection(
                socket = active,
                tls = active is SSLSocket,
                peerHost = request.connectHost,
                bytesWritten = written,
                response = response,
            )
        } catch (thrown: Throwable) {
            runCatching { (tls ?: tcp)?.close() }
            when (thrown) {
                is CancellationException -> throw thrown
                is PayloadParseException -> throw thrown
                is InjectException -> throw thrown
                else -> throw InjectException(thrown.message ?: "Tunnel handshake failed", thrown)
            }
        }
    }

    private fun parsePayload(request: InjectRequest): ParsedPayload {
        if (request.payloadTemplate.isBlank()) {
            return ParsedPayload(emptyList(), "")
        }
        return PayloadParser.parse(
            request.payloadTemplate,
            PayloadContext(
                host = request.serverHost,
                port = request.serverPort,
                protocol = request.protocol,
                onlineHost = request.onlineHost,
                injectStandardHeaders = request.injectStandardHeaders,
                websocketUpgrade = request.websocketUpgrade,
            ),
        )
    }

    private suspend fun writeChunks(
        socket: Socket,
        chunks: List<PayloadChunk>,
        request: InjectRequest,
    ): Int {
        val output = socket.getOutputStream()
        var total = 0
        for (chunk in chunks) {
            coroutineContext.ensureActive()
            when (chunk.writeMode) {
                ChunkWriteMode.SPLIT -> {
                    output.flush()
                    if (request.splitDelayMillis > 0) {
                        delay(request.splitDelayMillis)
                    }
                }
                ChunkWriteMode.INSTANT_SPLIT -> {
                    socket.tcpNoDelay = true
                    output.flush()
                }
                ChunkWriteMode.NORMAL -> Unit
            }
            output.write(chunk.bytes)
            output.flush()
            total += chunk.bytes.size
            request.onLog("Wrote ${chunk.bytes.size} bytes (${chunk.writeMode})")
        }
        return total
    }

    private fun wrapTls(tcp: Socket, sniHost: String, port: Int): SSLSocket {
        val context = SSLContext.getInstance("TLS")
        context.init(null, null, null)
        val ssl = context.socketFactory.createSocket(tcp, sniHost, port, true) as SSLSocket
        ssl.useClientMode = true
        val protocols = ssl.supportedProtocols.filter { it == "TLSv1.3" || it == "TLSv1.2" }
        if (protocols.isNotEmpty()) {
            ssl.enabledProtocols = protocols.toTypedArray()
        }
        if (!isNumericAddress(sniHost)) {
            val parameters = ssl.sslParameters
            parameters.serverNames = listOf(SNIHostName(sniHost))
            parameters.endpointIdentificationAlgorithm = "HTTPS"
            ssl.sslParameters = parameters
        }
        ssl.startHandshake()
        return ssl
    }

    private fun readHandshakeResponse(socket: Socket): ByteArray {
        val input = socket.getInputStream()
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(1024)
        try {
            while (output.size() < MAX_HANDSHAKE_RESPONSE) {
                val read = input.read(buffer)
                if (read < 0) break
                output.write(buffer, 0, read)
                if (containsHeaderTerminator(output)) break
            }
        } catch (_: SocketTimeoutException) {
            // The peer accepted the payload and has not replied yet.
        }
        return output.toByteArray()
    }

    private fun containsHeaderTerminator(output: ByteArrayOutputStream): Boolean {
        val text = output.toString(Charsets.ISO_8859_1.name())
        return text.contains("\r\n\r\n") || text.contains("\n\n")
    }

    private fun ensureHttpSuccess(response: ByteArray) {
        if (response.isEmpty()) return
        val text = String(response, Charsets.ISO_8859_1)
        val match = HTTP_STATUS.find(text) ?: return
        val status = match.groupValues[1].toInt()
        if (status >= 400) {
            val line = text.lineSequence().firstOrNull().orEmpty()
            throw InjectException("Remote handshake rejected: $line")
        }
    }

    private fun resolveSniHost(request: InjectRequest): String {
        val explicit = request.sniHost?.trim().orEmpty()
        if (explicit.isNotEmpty()) return explicit
        return request.serverHost
    }

    private fun validateRequest(request: InjectRequest) {
        if (request.connectHost.isBlank()) {
            throw InjectException("Connect host is empty")
        }
        if (request.connectPort !in 1..65535) {
            throw InjectException("Connect port ${request.connectPort} is outside 1..65535")
        }
        if (request.serverHost.isBlank()) {
            throw InjectException("Server host is empty")
        }
        if (request.serverPort !in 1..65535) {
            throw InjectException("Server port ${request.serverPort} is outside 1..65535")
        }
        val sni = request.sniHost
        if (sni != null && sni.isNotBlank() && containsControlCharacter(sni)) {
            throw InjectException("SNI host contains a control character")
        }
    }

    private fun containsControlCharacter(value: String): Boolean {
        return value.any { it == '\r' || it == '\n' || it == '\u0000' }
    }

    private fun isNumericAddress(host: String): Boolean {
        val bare = host.trim().removePrefix("[").removeSuffix("]")
        if (IPV4.matches(bare)) return true
        if (!bare.contains(':')) return false
        return bare.all { character ->
            character.isDigit() || character in 'a'..'f' || character in 'A'..'F' || character == ':' || character == '.'
        }
    }

    private companion object {
        const val MAX_HANDSHAKE_RESPONSE = 8192
        val HTTP_STATUS: Regex = Regex("""^HTTP/1\.[01]\s+(\d{3})""")
        val IPV4: Regex = Regex(
            """^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$""",
        )
    }
}

data class InjectRequest(
    val connectHost: String,
    val connectPort: Int,
    val serverHost: String = connectHost,
    val serverPort: Int = connectPort,
    val payloadTemplate: String = "",
    val useTls: Boolean = false,
    val sniHost: String? = null,
    val onlineHost: String? = null,
    val protocol: String = "HTTP/1.1",
    val websocketUpgrade: Boolean = false,
    val injectStandardHeaders: Boolean = true,
    val connectTimeoutMillis: Int = 15_000,
    val readTimeoutMillis: Int = 10_000,
    val splitDelayMillis: Long = 200,
    val tcpNoDelay: Boolean = true,
    val onLog: (String) -> Unit = {},
)

class InjectedConnection(
    val socket: Socket,
    val tls: Boolean,
    val peerHost: String,
    val bytesWritten: Int,
    val response: ByteArray,
) : java.io.Closeable {
    val responseText: String get() = String(response, Charsets.ISO_8859_1)

    val httpStatus: Int?
        get() {
            val match = Regex("""^HTTP/1\.[01]\s+(\d{3})""").find(responseText) ?: return null
            return match.groupValues[1].toInt()
        }

    override fun close() {
        socket.close()
    }
}

class InjectException(message: String, cause: Throwable? = null) : IOException(message, cause)
