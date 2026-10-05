package com.blackom.tunnel.netshare

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ArpReaderTest {
    @Test
    fun parsesCompleteProcEntriesAndSkipsTheNeighborCache() {
        var neighborReads = 0
        val reader = ArpReader(
            procNetArp = {
                """
                IP address       HW type     Flags       HW address            Mask     Device
                10.0.0.8         0x1         0x2         AA:BB:CC:DD:EE:FF     *        wlan0
                10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        wlan0
                """.trimIndent()
            },
            neighborTable = {
                neighborReads += 1
                "10.0.0.9 dev wlan0 lladdr 11:22:33:44:55:66 REACHABLE"
            },
            cacheMillis = 0,
        )
        val entries = reader.read()
        assertEquals(1, entries.size)
        assertEquals(ArpEntry("10.0.0.8", "aa:bb:cc:dd:ee:ff", "wlan0"), entries.single())
        assertEquals(0, neighborReads)
    }

    @Test
    fun fallsBackToIpNeighborCacheWhenProcIsIncomplete() {
        val reader = ArpReader(
            procNetArp = {
                """
                IP address       HW type     Flags       HW address            Mask     Device
                10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        wlan0
                """.trimIndent()
            },
            neighborTable = {
                """
                10.0.0.9 dev ap0 lladdr 11:22:33:44:55:66 REACHABLE
                10.0.0.10 dev ap0 FAILED
                fe80::abcd dev ap0 lladdr aa:aa:aa:aa:aa:aa STALE
                10.0.0.11 dev ap0 lladdr (incomplete) INCOMPLETE
                """.trimIndent()
            },
            cacheMillis = 0,
        )
        val byIp = reader.read().associateBy { it.ip }
        assertEquals(ArpEntry("10.0.0.9", "11:22:33:44:55:66", "ap0"), byIp["10.0.0.9"])
        assertEquals("aa:aa:aa:aa:aa:aa", byIp["fe80::abcd"]?.mac)
        assertEquals("ap0", byIp["fe80::abcd"]?.networkInterface)
        assertFalse(byIp.containsKey("10.0.0.10"))
        assertFalse(byIp.containsKey("10.0.0.11"))
    }
}

class SniSnifferTest {
    @Test
    fun extractsHostFromAHandcraftedClientHello() {
        val hello = clientHello("a.com")
        assertEquals(0x16, hello[0].toInt() and 0xFF)
        assertEquals(0x01, hello[5].toInt() and 0xFF)
        assertEquals("a.com", SniSniffer.extractHost(hello))
        assertEquals(SniParseResult.Host("a.com"), SniSniffer.parse(hello))
    }

    @Test
    fun extractsSniAfterAnotherExtensionAndNormalizesCase() {
        val hello = clientHello("YouTube.com", prefixExtension = true)
        assertEquals("youtube.com", SniSniffer.extractHost(hello))
    }

    @Test
    fun reportsIncompleteAndNonHandshakePayloads() {
        val hello = clientHello("instagram.com")
        assertEquals("instagram.com", SniSniffer.extractHost(hello))
        val short = SniSniffer.parse(hello.copyOf(4))
        assertTrue(short is SniParseResult.Incomplete)
        assertEquals(5, (short as SniParseResult.Incomplete).neededBytes)
        val partial = SniSniffer.parse(hello.copyOf(10))
        assertTrue(partial is SniParseResult.Incomplete)
        assertTrue((partial as SniParseResult.Incomplete).neededBytes > 10)
        assertEquals(SniParseResult.NotFound, SniSniffer.parse("GET / HTTP/1.1".toByteArray()))
        assertNull(SniSniffer.extractHost(ByteArray(0)))
    }

    @Test
    fun inputStreamParserStopsAtTheRecordBoundary() {
        val hello = clientHello("instagram.com")
        val stream = ByteArrayInputStream(hello + "EXTRA".toByteArray(Charsets.ISO_8859_1))
        assertEquals("instagram.com", SniSniffer.extractHost(stream))
        assertEquals("EXTRA", String(stream.readAllBytes(), Charsets.ISO_8859_1))
    }
}

class ClientTrafficTrackerTest {
    @Test
    fun slidingWindowKeepsTotalsAfterTheRateDrops() {
        val tracker = ClientTrafficTracker(clock = { 0L })
        tracker.recordDownload("10.0.0.8", 2048, atMillis = 1_000)
        tracker.recordUpload("10.0.0.8", 512, atMillis = 1_200)
        tracker.recordDownload("10.0.0.8", 1024, atMillis = 1_800)
        val live = tracker.snapshot("10.0.0.8")!!
        assertEquals(3072L, live.bytesIn)
        assertEquals(512L, live.bytesOut)
        assertEquals(3072 / 1024.0, live.downloadKilobytesPerSecond, 0.001)
        assertEquals(512 / 1024.0, live.uploadKilobytesPerSecond, 0.001)

        tracker.refresh(2_900)
        val aged = tracker.snapshot("10.0.0.8")!!
        assertEquals(0.0, aged.downloadKilobytesPerSecond, 0.001)
        assertEquals(0.0, aged.uploadKilobytesPerSecond, 0.001)
        assertEquals(3072L, aged.bytesIn)
        assertEquals(512L, aged.bytesOut)
    }

    @Test
    fun remembersDomainsWithTimestampsAndCapsHistory() {
        val tracker = ClientTrafficTracker(clock = { 0L }, historyLimit = 2)
        tracker.recordDomain("1.1.1.1", "Instagram.com.", atMillis = 10)
        tracker.recordDomain("1.1.1.1", "instagram.com", atMillis = 25)
        tracker.recordDomain("1.1.1.1", "youtube.com:443", atMillis = 40)
        tracker.recordDomain("1.1.1.1", "a.example", atMillis = 50)
        val snapshot = tracker.snapshot("1.1.1.1")!!
        assertEquals("a.example", snapshot.activeDomain)
        assertEquals(listOf("a.example", "youtube.com"), snapshot.history.map { it.domain })
        assertEquals(50L, snapshot.history[0].timestampMillis)
        assertEquals(40L, snapshot.history[1].timestampMillis)
        tracker.updateEndpoint("1.1.1.1", "aa:bb:cc:dd:ee:ff", "wlan0", "pixel")
        val identified = tracker.snapshot("1.1.1.1")!!
        assertEquals("aa:bb:cc:dd:ee:ff", identified.mac)
        assertEquals("wlan0", identified.networkInterface)
        assertEquals("pixel", identified.hostname)
    }
}

class HttpProxyHeadTest {
    @Test
    fun rewritesAbsoluteFormAndStripsProxyHeaders() {
        val head = (
            "GET http://example.com:8080/a?b=1 HTTP/1.1\r\n" +
                "Host: example.com:8080\r\n" +
                "Proxy-Connection: keep-alive\r\n" +
                "\r\n"
            ).toByteArray(Charsets.ISO_8859_1)
        val plan = parseHttpHead(head)
        assertFalse(plan.tunnel)
        assertEquals("example.com", plan.host)
        assertEquals(8080, plan.port)
        val forwarded = String(plan.forwardedHead, Charsets.ISO_8859_1)
        assertTrue(forwarded.startsWith("GET /a?b=1 HTTP/1.1\r\n"))
        assertTrue(forwarded.contains("Host: example.com:8080\r\n"))
        assertFalse(forwarded.contains("Proxy-Connection"))
        assertTrue(forwarded.endsWith("\r\n\r\n"))
    }

    @Test
    fun parsesConnectAndOriginForm() {
        val connect = parseHttpHead("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".toByteArray())
        assertTrue(connect.tunnel)
        assertEquals("example.com", connect.host)
        assertEquals(443, connect.port)
        val origin = parseHttpHead("GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray())
        assertEquals("example.com", origin.host)
        assertEquals(80, origin.port)
        assertTrue(String(origin.forwardedHead, Charsets.ISO_8859_1).startsWith("GET /x HTTP/1.1\r\n"))
        assertThrows(IllegalArgumentException::class.java) {
            parseHttpHead("GET /x HTTP/1.1\r\n\r\n".toByteArray())
        }
    }
}

class NetShareServerTest {
    @Test
    fun httpProxyForwardsTheRequestAndPublishesLiveCounters() {
        val release = CountDownLatch(1)
        val seen = AtomicReference<String>()
        ServerSocket(0).use { upstream ->
            upstream.soTimeout = 5_000
            val thread = Thread {
                try {
                    upstream.accept().use { socket ->
                        socket.soTimeout = 5_000
                        val head = readUntilHeader(socket.getInputStream())
                        seen.set(String(head, Charsets.ISO_8859_1))
                        val body = "OK"
                        val response = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n$body"
                        socket.getOutputStream().write(response.toByteArray(Charsets.ISO_8859_1))
                        socket.getOutputStream().flush()
                        release.await(5, TimeUnit.SECONDS)
                    }
                } catch (_: Exception) {
                    // Closed by the test finally block.
                }
            }
            thread.isDaemon = true
            thread.start()
            val server = proxy()
            var client: Socket? = null
            try {
                server.start()
                assertTrue(server.awaitListening())
                assertEquals(NetShareServer.BIND_ADDRESS, "0.0.0.0")
                assertEquals(8080, NetShareServer.PORT)
                client = connect(server.boundPort)
                val request = "GET http://127.0.0.1:${upstream.localPort}/hello HTTP/1.1\r\n" +
                    "Host: 127.0.0.1:${upstream.localPort}\r\n\r\n"
                client.getOutputStream().write(request.toByteArray(Charsets.ISO_8859_1))
                client.getOutputStream().flush()
                val response = readUntilHeader(client.getInputStream())
                val body = readExactly(client.getInputStream(), 2)
                assertTrue(String(response, Charsets.ISO_8859_1).contains("200"))
                assertEquals("OK", String(body, Charsets.ISO_8859_1))
                val requestText = seen.get()
                assertTrue(requestText.startsWith("GET /hello HTTP/1.1\r\n"))
                val device = server.devices.value.single()
                assertEquals("127.0.0.1", device.ip)
                assertEquals("aa:bb:cc:dd:ee:ff", device.mac)
                assertEquals("wlan0", device.networkInterface)
                assertEquals("pixel", device.hostname)
                assertEquals("127.0.0.1", device.activeDomain)
                assertTrue(device.bytesOut > 0)
                assertTrue(device.bytesIn >= 2)
            } finally {
                release.countDown()
                runCatching { client?.close() }
                server.stop()
                thread.join(2_000)
            }
        }
    }

    @Test
    fun connectTunnelCapturesSniAndRelaysBytes() {
        val hello = clientHello("instagram.com")
        val release = CountDownLatch(1)
        ServerSocket(0).use { upstream ->
            upstream.soTimeout = 5_000
            val thread = Thread {
                try {
                    upstream.accept().use { socket ->
                        socket.soTimeout = 5_000
                        val received = readExactly(socket.getInputStream(), hello.size)
                        assertArrayEquals(hello, received)
                        socket.getOutputStream().write("pong".toByteArray(Charsets.ISO_8859_1))
                        socket.getOutputStream().flush()
                        release.await(5, TimeUnit.SECONDS)
                    }
                } catch (_: Exception) {
                    // Closed by the test finally block.
                }
            }
            thread.isDaemon = true
            thread.start()
            val server = proxy()
            var client: Socket? = null
            try {
                server.start()
                assertTrue(server.awaitListening())
                client = connect(server.boundPort)
                val request = "CONNECT 127.0.0.1:${upstream.localPort} HTTP/1.1\r\n" +
                    "Host: 127.0.0.1:${upstream.localPort}\r\n\r\n"
                client.getOutputStream().write(request.toByteArray(Charsets.ISO_8859_1))
                client.getOutputStream().flush()
                val status = String(readUntilHeader(client.getInputStream()), Charsets.ISO_8859_1)
                assertTrue(status.contains("200"))
                client.getOutputStream().write(hello)
                client.getOutputStream().flush()
                assertEquals("pong", String(readExactly(client.getInputStream(), 4), Charsets.ISO_8859_1))
                val device = server.devices.value.single()
                assertEquals("instagram.com", device.activeDomain)
                assertTrue(device.history.any { it.domain == "instagram.com" && it.timestampMillis > 0 })
                assertTrue(device.bytesOut >= hello.size)
                assertTrue(device.bytesIn >= 4)
            } finally {
                release.countDown()
                runCatching { client?.close() }
                server.stop()
                thread.join(2_000)
            }
        }
    }

    @Test
    fun socks5ConnectRelaysAndTracksTheDestination() = runBlocking {
        val release = CountDownLatch(1)
        ServerSocket(0).use { upstream ->
            upstream.soTimeout = 5_000
            val thread = Thread {
                try {
                    upstream.accept().use { socket ->
                        socket.soTimeout = 5_000
                        assertEquals("ping", String(readExactly(socket.getInputStream(), 4), Charsets.ISO_8859_1))
                        socket.getOutputStream().write("pong".toByteArray(Charsets.ISO_8859_1))
                        socket.getOutputStream().flush()
                        release.await(5, TimeUnit.SECONDS)
                    }
                } catch (_: Exception) {
                    // Closed by the test finally block.
                }
            }
            thread.isDaemon = true
            thread.start()
            val server = proxy()
            var client: Socket? = null
            try {
                server.start()
                assertTrue(server.awaitListening())
                client = connect(server.boundPort)
                val output = client.getOutputStream()
                val input = client.getInputStream()
                output.write(byteArrayOf(5, 1, 0))
                output.flush()
                assertArrayEquals(byteArrayOf(5, 0), readExactly(input, 2))
                val port = upstream.localPort
                output.write(
                    byteArrayOf(
                        5,
                        1,
                        0,
                        1,
                        127,
                        0,
                        0,
                        1,
                        (port shr 8).toByte(),
                        port.toByte(),
                    ),
                )
                output.flush()
                val reply = readExactly(input, 10)
                assertEquals(5, reply[0].toInt() and 0xFF)
                assertEquals(0, reply[1].toInt() and 0xFF)
                output.write("ping".toByteArray(Charsets.ISO_8859_1))
                output.flush()
                assertEquals("pong", String(readExactly(input, 4), Charsets.ISO_8859_1))
                val device = server.devices.value.single()
                assertEquals("127.0.0.1", device.activeDomain)
                assertTrue(device.bytesOut >= 4)
                assertTrue(device.bytesIn >= 4)
                assertTrue(server.isRunning)
            } finally {
                release.countDown()
                runCatching { client?.close() }
                server.stop()
                assertTrue(server.devices.value.isEmpty())
                thread.join(2_000)
            }
        }
    }

    private fun proxy(): NetShareServer {
        return NetShareServer(
            bindAddress = "127.0.0.1",
            port = 0,
            arpReader = ArpReader(
                procNetArp = {
                    """
                    IP address       HW type     Flags       HW address            Mask     Device
                    127.0.0.1        0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
                    """.trimIndent()
                },
                neighborTable = { null },
                cacheMillis = 0,
            ),
            hostnameResolver = ClientHostnameResolver { "pixel" },
        )
    }

    private fun connect(port: Int): Socket {
        var last: Exception? = null
        repeat(20) {
            try {
                return Socket("127.0.0.1", port).apply { soTimeout = 5_000 }
            } catch (error: Exception) {
                last = error
                Thread.sleep(50)
            }
        }
        throw last ?: IllegalStateException("proxy did not accept")
    }
}

internal fun clientHello(host: String, prefixExtension: Boolean = false): ByteArray {
    val name = host.toByteArray(Charsets.US_ASCII)
    val serverName = ByteArrayOutputStream().apply {
        write16(name.size + 3)
        write(0)
        write16(name.size)
        write(name)
    }.toByteArray()
    val sni = ByteArrayOutputStream().apply {
        write16(0)
        write16(serverName.size)
        write(serverName)
    }.toByteArray()
    val extensions = if (prefixExtension) {
        byteArrayOf(0x00, 0x0b, 0x00, 0x01, 0x00) + sni
    } else {
        sni
    }
    val hello = ByteArrayOutputStream().apply {
        write16(0x0303)
        write(ByteArray(32))
        write(0)
        write16(2)
        write16(0x002f)
        write(1)
        write(0)
        write16(extensions.size)
        write(extensions)
    }.toByteArray()
    val handshake = ByteArrayOutputStream().apply {
        write(0x01)
        write24(hello.size)
        write(hello)
    }.toByteArray()
    return ByteArrayOutputStream().apply {
        write(0x16)
        write16(0x0303)
        write16(handshake.size)
        write(handshake)
    }.toByteArray()
}

private fun ByteArrayOutputStream.write16(value: Int) {
    write((value ushr 8) and 0xFF)
    write(value and 0xFF)
}

private fun ByteArrayOutputStream.write24(value: Int) {
    write((value ushr 16) and 0xFF)
    write((value ushr 8) and 0xFF)
    write(value and 0xFF)
}

private fun readUntilHeader(input: InputStream): ByteArray {
    val buffer = ByteArrayOutputStream()
    while (buffer.size() < 16 * 1024) {
        val value = input.read()
        if (value < 0) break
        buffer.write(value)
        val all = buffer.toByteArray()
        if (all.size >= 4 &&
            all[all.size - 4] == '\r'.code.toByte() &&
            all[all.size - 3] == '\n'.code.toByte() &&
            all[all.size - 2] == '\r'.code.toByte() &&
            all[all.size - 1] == '\n'.code.toByte()
        ) {
            return all
        }
    }
    error("header was not received: ${buffer.toString(Charsets.ISO_8859_1)}")
}

private fun readExactly(input: InputStream, size: Int): ByteArray {
    val out = ByteArray(size)
    var offset = 0
    while (offset < size) {
        val read = input.read(out, offset, size - offset)
        check(read >= 0) { "stream ended after $offset of $size bytes" }
        offset += read
    }
    return out
}
