package com.blackom.tunnel.netshare

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.io.PushbackInputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import java.nio.channels.ClosedSelectorException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Local HTTP and SOCKS5 proxy for tethered NetShare clients.
 *
 * The listen socket is a non-blocking [ServerSocketChannel]. Each accepted
 * session runs on a coroutine and is relayed in both directions while
 * [ClientTrafficTracker] counts the bytes.
 */
class NetShareServer(
    private val bindAddress: String = BIND_ADDRESS,
    port: Int = PORT,
    val tracker: ClientTrafficTracker = ClientTrafficTracker(),
    private val arpReader: ArpReader = ArpReader(),
    private val connector: UpstreamConnector = DefaultUpstreamConnector,
    private val hostnameResolver: ClientHostnameResolver = DefaultHostnameResolver,
    private val onLog: (String) -> Unit = {},
) {
    init {
        require(port in 0..65535) { "Port $port is outside 0..65535" }
        require(bindAddress.isNotBlank()) { "Bind address is empty" }
    }

    private val requestedPort = port
    private val activeCounts = ConcurrentHashMap<String, Int>()
    private val openSockets = ConcurrentHashMap.newKeySet<Socket>()
    private val selectorRef = AtomicReference<Selector?>(null)
    private val lifecycle = Any()
    private var session: kotlinx.coroutines.Job? = null
    private var sessionScope: CoroutineScope? = null
    private var serverChannel: ServerSocketChannel? = null
    private var listening: CountDownLatch? = null
    private var lookups = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "netshare-hostname").apply { isDaemon = true }
    }

    @Volatile
    var boundPort: Int = port
        private set

    @Volatile
    var isRunning: Boolean = false
        private set

    private val _devices = MutableStateFlow<List<ClientSnapshot>>(emptyList())
    val devices: StateFlow<List<ClientSnapshot>> = _devices.asStateFlow()

    init {
        tracker.addListener { publish() }
    }

    fun start() {
        synchronized(lifecycle) {
            if (isRunning) return
            if (lookups.isShutdown) {
                lookups = Executors.newCachedThreadPool { runnable ->
                    Thread(runnable, "netshare-hostname").apply { isDaemon = true }
                }
            }
            val channel = ServerSocketChannel.open()
            channel.setOption(java.net.StandardSocketOptions.SO_REUSEADDR, true)
            channel.bind(InetSocketAddress(bindAddress, requestedPort))
            channel.configureBlocking(false)
            serverChannel = channel
            boundPort = (channel.localAddress as InetSocketAddress).port
            val job = SupervisorJob()
            val scope = CoroutineScope(job + Dispatchers.IO)
            val ready = CountDownLatch(1)
            session = job
            sessionScope = scope
            listening = ready
            isRunning = true
            scope.launch { acceptLoop(ready) }
            scope.launch { maintenanceLoop() }
            onLog("NetShare listening on $bindAddress:$boundPort")
        }
    }

    fun awaitListening(timeoutMillis: Long = 3_000): Boolean {
        val latch = listening ?: return isRunning
        return latch.await(timeoutMillis, TimeUnit.MILLISECONDS)
    }

    fun stop() {
        synchronized(lifecycle) {
            if (!isRunning && serverChannel == null) return
            isRunning = false
            session?.cancel()
            selectorRef.get()?.wakeup()
            runCatching { serverChannel?.close() }
            runCatching { selectorRef.get()?.close() }
            serverChannel = null
            openSockets.forEach { socket -> runCatching { socket.close() } }
            openSockets.clear()
            activeCounts.clear()
            publish()
            lookups.shutdownNow()
            session = null
            sessionScope = null
            onLog("NetShare stopped")
        }
    }

    private fun CoroutineScope.acceptLoop(ready: CountDownLatch) {
        val selector = Selector.open()
        selectorRef.set(selector)
        try {
            val channel = serverChannel ?: return
            channel.register(selector, SelectionKey.OP_ACCEPT)
            ready.countDown()
            while (isActive && isRunning) {
                val selected = try {
                    selector.select(500)
                } catch (_: ClosedSelectorException) {
                    break
                }
                if (!isActive || !isRunning) break
                if (selected == 0) continue
                val keys = selector.selectedKeys().iterator()
                while (keys.hasNext()) {
                    val key = keys.next()
                    keys.remove()
                    if (!key.isValid || !key.isAcceptable) continue
                    acceptPending(channel)
                }
            }
        } catch (error: Exception) {
            if (isRunning) onLog("Accept loop stopped: ${error.message}")
        } finally {
            ready.countDown()
            selectorRef.compareAndSet(selector, null)
            runCatching { selector.close() }
        }
    }

    private fun CoroutineScope.acceptPending(channel: ServerSocketChannel) {
        while (true) {
            val client = channel.accept() ?: return
            client.configureBlocking(true)
            val socket = client.socket().apply { tcpNoDelay = true }
            openSockets += socket
            launch {
                val ip = socket.inetAddress?.hostAddress
                try {
                    if (ip != null) handle(socket, ip)
                } catch (_: IOException) {
                    // The client or upstream closed the session.
                } finally {
                    openSockets -= socket
                    runCatching { socket.close() }
                    if (ip != null) release(ip)
                }
            }
        }
    }

    private suspend fun handle(socket: Socket, ip: String) {
        acquire(ip)
        tracker.openClient(ip)
        applyArp(ip)
        tracker.updateEndpoint(ip, null, null, lookupHostname(ip))
        socket.soTimeout = HEADER_TIMEOUT_MILLIS
        val input = PushbackInputStream(socket.getInputStream(), 1)
        val first = input.read()
        if (first < 0) return
        input.unread(first)
        if (first == SOCKS_VERSION) {
            handleSocks(socket, input, ip)
        } else {
            handleHttp(socket, input, ip)
        }
    }

    private suspend fun handleHttp(socket: Socket, input: InputStream, ip: String) {
        val (head, leftover) = try {
            readHttpHead(input)
        } catch (error: IOException) {
            sendHttpStatus(socket, 400, "Bad Request")
            onLog("Bad HTTP head from $ip: ${error.message}")
            return
        }
        val plan = try {
            parseHttpHead(head)
        } catch (error: IllegalArgumentException) {
            sendHttpStatus(socket, 400, "Bad Request")
            onLog("Rejected HTTP request from $ip: ${error.message}")
            return
        }
        if (plan.tunnel) {
            openTunnel(socket, input, ip, plan.host, plan.port, leftover)
        } else {
            val prefix = plan.forwardedHead + leftover
            forwardHttp(socket, ip, plan.host, plan.port, prefix)
        }
    }

    private suspend fun handleSocks(socket: Socket, input: InputStream, ip: String) {
        val output = socket.getOutputStream()
        val methods = try {
            val version = readU8(input)
            if (version != SOCKS_VERSION) throw IOException("Not SOCKS5")
            val count = readU8(input)
            ByteArray(count).also { readFully(input, it) }
        } catch (error: IOException) {
            onLog("Bad SOCKS greeting from $ip: ${error.message}")
            return
        }
        if (methods.none { it == SOCKS_NO_AUTH }) {
            output.write(byteArrayOf(SOCKS_VERSION.toByte(), 0xFF.toByte()))
            output.flush()
            return
        }
        output.write(byteArrayOf(SOCKS_VERSION.toByte(), SOCKS_NO_AUTH))
        output.flush()

        val destination = try {
            val version = readU8(input)
            val command = readU8(input)
            val reserved = readU8(input)
            if (version != SOCKS_VERSION || reserved != 0) throw IOException("Bad SOCKS request")
            if (command != SOCKS_CONNECT) {
                output.write(socksReply(0x07))
                output.flush()
                return
            }
            readSocksDestination(input)
        } catch (error: IOException) {
            onLog("Bad SOCKS request from $ip: ${error.message}")
            runCatching {
                output.write(socksReply(0x01))
                output.flush()
            }
            return
        }
        openTunnel(socket, input, ip, destination.host, destination.port, ByteArray(0), socks = true)
    }

    private suspend fun forwardHttp(
        socket: Socket,
        ip: String,
        host: String,
        port: Int,
        prefix: ByteArray,
    ) {
        tracker.recordDomain(ip, host)
        val upstream = connectUpstream(socket, host, port, socks = false) ?: return
        try {
            relay(socket, upstream, ip, prefix)
        } finally {
            openSockets -= upstream
            runCatching { upstream.close() }
        }
    }

    private suspend fun openTunnel(
        socket: Socket,
        input: InputStream,
        ip: String,
        host: String,
        port: Int,
        alreadyRead: ByteArray,
        socks: Boolean = false,
    ) {
        tracker.recordDomain(ip, host)
        val upstream = connectUpstream(socket, host, port, socks) ?: return
        try {
            if (!socks) {
                sendRaw(socket, "HTTP/1.1 200 Connection Established\r\n\r\n")
            } else {
                val output = socket.getOutputStream()
                output.write(socksReply(0x00))
                output.flush()
            }
            socket.soTimeout = PREFACE_TIMEOUT_MILLIS
            val preface = readClientPreface(input, alreadyRead)
            socket.soTimeout = HEADER_TIMEOUT_MILLIS
            val sni = SniSniffer.extractHost(preface)
            if (sni != null) tracker.recordDomain(ip, sni)
            relay(socket, upstream, ip, preface)
        } finally {
            openSockets -= upstream
            runCatching { upstream.close() }
        }
    }

    private fun connectUpstream(client: Socket, host: String, port: Int, socks: Boolean): Socket? {
        return try {
            connector.connect(host, port, CONNECT_TIMEOUT_MILLIS).also { upstream ->
                upstream.tcpNoDelay = true
                openSockets += upstream
            }
        } catch (error: IOException) {
            onLog("Upstream $host:$port failed: ${error.message}")
            if (socks) {
                runCatching {
                    client.getOutputStream().write(socksReply(socksFailureCode(error)))
                    client.getOutputStream().flush()
                }
            } else {
                sendHttpStatus(client, 502, "Bad Gateway")
            }
            null
        }
    }

    private suspend fun relay(client: Socket, upstream: Socket, ip: String, prefix: ByteArray) {
        client.soTimeout = 0
        upstream.soTimeout = 0
        if (prefix.isNotEmpty()) {
            tracker.recordUpload(ip, prefix.size)
            val output = upstream.getOutputStream()
            output.write(prefix)
            output.flush()
        }
        coroutineScope {
            val upload = async(Dispatchers.IO) {
                pump(client.getInputStream(), upstream.getOutputStream()) { tracker.recordUpload(ip, it) }
                runCatching { upstream.shutdownOutput() }
            }
            val download = async(Dispatchers.IO) {
                pump(upstream.getInputStream(), client.getOutputStream()) { tracker.recordDownload(ip, it) }
                runCatching { client.shutdownOutput() }
            }
            upload.await()
            download.await()
        }
    }

    private fun pump(input: InputStream, output: OutputStream, onBytes: (Int) -> Unit) {
        val buffer = ByteArray(RELAY_BUFFER)
        try {
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                onBytes(read)
                output.write(buffer, 0, read)
                output.flush()
            }
        } catch (_: IOException) {
            // Peer closed, or stop() closed this socket.
        }
    }

    private fun readClientPreface(input: InputStream, prefix: ByteArray): ByteArray {
        val collected = ByteArrayOutputStream()
        if (prefix.isNotEmpty()) collected.write(prefix)
        val scratch = ByteArray(4 * 1024)
        while (collected.size() < MAX_PREFACE) {
            when (val parsed = SniSniffer.parse(collected.toByteArray())) {
                is SniParseResult.Host -> return collected.toByteArray()
                is SniParseResult.NotFound -> if (collected.size() > 0) return collected.toByteArray()
                is SniParseResult.Incomplete -> Unit
            }
            val read = try {
                input.read(scratch)
            } catch (_: SocketTimeoutException) {
                return collected.toByteArray()
            }
            if (read < 0) return collected.toByteArray()
            collected.write(scratch, 0, read)
        }
        return collected.toByteArray()
    }

    private suspend fun maintenanceLoop() {
        while (coroutineContext.isActive && isRunning) {
            delay(500)
            tracker.refresh()
            val known = tracker.snapshots.value.map { it.ip }.toSet()
            if (known.isEmpty()) continue
            val table = runCatching { arpReader.read() }.getOrDefault(emptyList())
            for (entry in table) {
                if (entry.ip in known) {
                    tracker.updateEndpoint(entry.ip, entry.mac, entry.networkInterface, null)
                }
            }
        }
    }

    private fun applyArp(ip: String) {
        val entry = runCatching { arpReader.read() }.getOrNull()?.firstOrNull { it.ip == ip } ?: return
        tracker.updateEndpoint(ip, entry.mac, entry.networkInterface, null)
    }

    private fun lookupHostname(ip: String): String? {
        val future = try {
            lookups.submit<String?> { runCatching { hostnameResolver.resolve(ip) }.getOrNull() }
        } catch (_: RejectedExecutionException) {
            return null
        }
        return try {
            future.get(HOSTNAME_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        } catch (_: Exception) {
            future.cancel(true)
            null
        }
    }

    private fun acquire(ip: String) {
        activeCounts.compute(ip) { _, current -> (current ?: 0) + 1 }
        publish()
    }

    private fun release(ip: String) {
        activeCounts.compute(ip) { _, current ->
            val next = (current ?: 0) - 1
            if (next <= 0) null else next
        }
        publish()
    }

    private fun publish() {
        val ips = activeCounts.keys
        _devices.value = tracker.snapshots.value.filter { it.ip in ips }.sortedBy { it.ip }
    }

    private fun sendHttpStatus(socket: Socket, status: Int, reason: String) {
        val body = reason
        val payload = "HTTP/1.1 $status $reason\r\nContent-Length: ${body.toByteArray(Charsets.ISO_8859_1).size}\r\nConnection: close\r\n\r\n$body"
        sendRaw(socket, payload)
    }

    private fun sendRaw(socket: Socket, payload: String) {
        runCatching {
            val output = socket.getOutputStream()
            output.write(payload.toByteArray(Charsets.ISO_8859_1))
            output.flush()
        }
    }

    companion object {
        const val BIND_ADDRESS: String = "0.0.0.0"
        const val PORT: Int = 8080
        private const val HEADER_TIMEOUT_MILLIS: Int = 15_000
        private const val PREFACE_TIMEOUT_MILLIS: Int = 1_500
        private const val CONNECT_TIMEOUT_MILLIS: Int = 10_000
        private const val HOSTNAME_TIMEOUT_MILLIS: Long = 800
        private const val RELAY_BUFFER: Int = 8 * 1024
        private const val MAX_PREFACE: Int = 16 * 1024
        private const val SOCKS_VERSION: Int = 5
        private const val SOCKS_NO_AUTH: Byte = 0
        private const val SOCKS_CONNECT: Int = 1
    }
}

fun interface UpstreamConnector {
    fun connect(host: String, port: Int, timeoutMillis: Int): Socket
}

fun interface ClientHostnameResolver {
    fun resolve(ip: String): String?
}

val DefaultUpstreamConnector: UpstreamConnector = UpstreamConnector { host, port, timeoutMillis ->
    Socket().apply {
        tcpNoDelay = true
        connect(InetSocketAddress(host, port), timeoutMillis)
    }
}

val DefaultHostnameResolver: ClientHostnameResolver = ClientHostnameResolver { ip ->
    runCatching {
        val address = java.net.InetAddress.getByName(ip)
        val name = address.hostName
        if (name.isNullOrBlank() || name.equals(ip, ignoreCase = true) || name.equals(address.hostAddress, ignoreCase = true)) {
            null
        } else {
            name
        }
    }.getOrNull()
}

internal class HttpProxyPlan(
    val host: String,
    val port: Int,
    val tunnel: Boolean,
    val forwardedHead: ByteArray,
)

internal fun readHttpHead(input: InputStream, maxBytes: Int = 16 * 1024): Pair<ByteArray, ByteArray> {
    val buffer = ByteArrayOutputStream()
    val scratch = ByteArray(512)
    while (buffer.size() < maxBytes) {
        val want = minOf(scratch.size, maxBytes - buffer.size())
        val read = input.read(scratch, 0, want)
        if (read < 0) throw IOException("Client closed before the HTTP headers")
        buffer.write(scratch, 0, read)
        val all = buffer.toByteArray()
        val end = indexOfHeaderEnd(all)
        if (end >= 0) return all.copyOf(end) to all.copyOfRange(end, all.size)
    }
    throw IOException("HTTP header is larger than $maxBytes bytes")
}

internal fun parseHttpHead(head: ByteArray): HttpProxyPlan {
    val text = String(head, Charsets.ISO_8859_1)
    val lines = text.split("\r\n")
    val request = lines.firstOrNull()?.takeIf { it.isNotBlank() }
        ?: throw IllegalArgumentException("Empty HTTP request")
    val parts = request.split(" ", limit = 3)
    if (parts.size != 3) throw IllegalArgumentException("Malformed request line")
    val method = parts[0].uppercase(Locale.US)
    val target = parts[1]
    val version = parts[2]
    if (!version.startsWith("HTTP/1.")) throw IllegalArgumentException("Unsupported HTTP version")
    if (method == "CONNECT") {
        val (host, explicitPort) = splitHostAndPort(target)
        val port = explicitPort ?: 443
        requirePort(port)
        return HttpProxyPlan(host, port, tunnel = true, forwardedHead = ByteArray(0))
    }
    if (method !in FORWARDED_METHODS) throw IllegalArgumentException("Unsupported method $method")
    val (host, port, path) = if (target.startsWith("http://") || target.startsWith("https://")) {
        val uri = try {
            URI(target)
        } catch (error: Exception) {
            throw IllegalArgumentException("Malformed URI")
        }
        val uriHost = uri.host ?: throw IllegalArgumentException("Missing host")
        val defaultPort = if (target.startsWith("https://")) 443 else 80
        val uriPort = if (uri.port == -1) defaultPort else uri.port
        val rawPath = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        val query = uri.rawQuery?.let { "?$it" }.orEmpty()
        Triple(uriHost, uriPort, rawPath + query)
    } else {
        val header = headerValue(lines, "Host") ?: throw IllegalArgumentException("Missing Host header")
        val (headerHost, headerPort) = splitHostAndPort(header)
        val resolved = headerPort ?: 80
        Triple(headerHost, resolved, if (target.isEmpty()) "/" else target)
    }
    requirePort(port)
    val forwarded = buildForwardedHead(method, path, version, lines)
    return HttpProxyPlan(host, port, tunnel = false, forwardedHead = forwarded)
}

private fun buildForwardedHead(method: String, path: String, version: String, lines: List<String>): ByteArray {
    val builder = StringBuilder()
    builder.append(method).append(' ').append(path).append(' ').append(version).append("\r\n")
    for (line in lines.drop(1)) {
        if (line.isEmpty()) continue
        val name = line.substringBefore(':').trim()
        if (name.equals("Proxy-Connection", ignoreCase = true) || name.equals("Proxy-Authorization", ignoreCase = true)) {
            continue
        }
        builder.append(line).append("\r\n")
    }
    builder.append("\r\n")
    return builder.toString().toByteArray(Charsets.ISO_8859_1)
}

private fun headerValue(lines: List<String>, name: String): String? {
    for (line in lines.drop(1)) {
        val separator = line.indexOf(':')
        if (separator <= 0) continue
        if (line.substring(0, separator).trim().equals(name, ignoreCase = true)) {
            return line.substring(separator + 1).trim()
        }
    }
    return null
}

internal fun splitHostAndPort(value: String): Pair<String, Int?> {
    val trimmed = value.trim()
    if (trimmed.startsWith("[")) {
        val end = trimmed.indexOf(']')
        if (end <= 1) throw IllegalArgumentException("Malformed IPv6 host")
        val host = trimmed.substring(1, end)
        if (end + 1 >= trimmed.length) return host to null
        if (trimmed[end + 1] != ':') throw IllegalArgumentException("Malformed IPv6 host")
        return host to trimmed.substring(end + 2).toIntOrNull().also { requirePort(it ?: -1) }
    }
    val colon = trimmed.lastIndexOf(':')
    if (colon > 0 && trimmed.substring(colon + 1).all { it.isDigit() } && trimmed.count { it == ':' } == 1) {
        val port = trimmed.substring(colon + 1).toIntOrNull() ?: throw IllegalArgumentException("Malformed port")
        requirePort(port)
        return trimmed.substring(0, colon) to port
    }
    if (trimmed.isBlank()) throw IllegalArgumentException("Missing host")
    return trimmed to null
}

private fun requirePort(port: Int) {
    if (port !in 1..65535) throw IllegalArgumentException("Port $port is outside 1..65535")
}

private fun indexOfHeaderEnd(data: ByteArray): Int {
    for (index in 0..data.size - 4) {
        if (data[index] == CR && data[index + 1] == LF && data[index + 2] == CR && data[index + 3] == LF) {
            return index + 4
        }
    }
    return -1
}

private fun readSocksDestination(input: InputStream): HostAndPort {
    val type = readU8(input)
    val host = when (type) {
        0x01 -> {
            val raw = ByteArray(4)
            readFully(input, raw)
            raw.joinToString(".") { (it.toInt() and 0xFF).toString() }
        }
        0x03 -> {
            val length = readU8(input)
            if (length == 0) throw IOException("Empty SOCKS domain")
            val raw = ByteArray(length)
            readFully(input, raw)
            String(raw, Charsets.UTF_8)
        }
        0x04 -> {
            val raw = ByteArray(16)
            readFully(input, raw)
            java.net.InetAddress.getByAddress(raw).hostAddress ?: throw IOException("Bad IPv6 address")
        }
        else -> throw IOException("Unsupported SOCKS address type")
    }
    val port = (readU8(input) shl 8) or readU8(input)
    if (port !in 1..65535) throw IOException("Bad SOCKS port")
    return HostAndPort(host, port)
}

private fun readU8(input: InputStream): Int {
    val value = input.read()
    if (value < 0) throw EOFException("Unexpected end of stream")
    return value
}

private fun readFully(input: InputStream, dest: ByteArray) {
    var offset = 0
    while (offset < dest.size) {
        val read = input.read(dest, offset, dest.size - offset)
        if (read < 0) throw EOFException("Unexpected end of stream")
        offset += read
    }
}

private fun socksReply(code: Int): ByteArray {
    return byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0)
}

private fun socksFailureCode(error: IOException): Int = when (error) {
    is ConnectException -> 0x05
    is UnknownHostException -> 0x04
    else -> 0x01
}

private data class HostAndPort(val host: String, val port: Int)

private const val CR: Byte = '\r'.code.toByte()
private const val LF: Byte = '\n'.code.toByte()

private val FORWARDED_METHODS = setOf("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE")
