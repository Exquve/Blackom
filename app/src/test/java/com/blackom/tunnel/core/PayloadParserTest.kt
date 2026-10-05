package com.blackom.tunnel.core

import java.io.ByteArrayOutputStream
import java.net.ServerSocket
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadParserTest {
    @Test
    fun replacesEveryTokenAndKeepsHostPortIntact() {
        val parsed = PayloadParser.parse(
            "[protocol] [host] [port] [host_port][cr][lf][crlf]",
            PayloadContext(host = "edge.example", port = 80),
        )
        assertEquals(
            "HTTP/1.1 edge.example 80 edge.example:80\r\n\r\n",
            parsed.normalized,
        )
        assertEquals(1, parsed.chunks.size)
        assertEquals(ChunkWriteMode.NORMAL, parsed.chunks.single().writeMode)
    }

    @Test
    fun tokensAreCaseInsensitive() {
        val parsed = PayloadParser.parse(
            "CONNECT [HoSt_PoRt] [PROTOCOL][CRLF]",
            PayloadContext(host = "edge.example", port = 443, injectStandardHeaders = false),
        )
        assertEquals("CONNECT edge.example:443 HTTP/1.1\r\n", parsed.normalized)
    }

    @Test
    fun bracketsIpv6Host() {
        val parsed = PayloadParser.parse(
            "[host_port]",
            PayloadContext(host = "2001:db8::1", port = 443, injectStandardHeaders = false),
        )
        assertEquals("[2001:db8::1]:443", parsed.normalized)
    }

    @Test
    fun splitAndInstantSplitBecomeSeparateWrites() {
        val parsed = PayloadParser.parse(
            "AAA[split]BBB[instant_split]CCC",
            PayloadContext(host = "edge.example", port = 443, injectStandardHeaders = false),
        )
        assertEquals(listOf("AAA", "BBB", "CCC"), parsed.chunks.map { it.text() })
        assertEquals(
            listOf(ChunkWriteMode.NORMAL, ChunkWriteMode.SPLIT, ChunkWriteMode.INSTANT_SPLIT),
            parsed.chunks.map { it.writeMode },
        )
        assertEquals("AAABBBCCC", parsed.normalized)
    }

    @Test
    fun injectsHostAndOnlineHostAroundSplitMarker() {
        val parsed = PayloadParser.parse(
            "CONNECT [host_port] [protocol][crlf][split][crlf]",
            PayloadContext(host = "example.com", port = 443, onlineHost = "bug.example"),
        )
        assertEquals(
            "CONNECT example.com:443 HTTP/1.1\r\n" +
                "Host: example.com:443\r\n" +
                "X-Online-Host: bug.example\r\n" +
                "\r\n",
            parsed.normalized,
        )
        assertEquals(
            listOf(
                "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nX-Online-Host: bug.example\r\n",
                "\r\n",
            ),
            parsed.chunks.map { it.text() },
        )
        assertEquals(ChunkWriteMode.SPLIT, parsed.chunks[1].writeMode)
    }

    @Test
    fun doesNotDuplicateExistingHeadersAndAddsWebsocketUpgrade() {
        val parsed = PayloadParser.parse(
            "GET / HTTP/1.1[crlf]Host: [host][crlf]Connection: keep-alive[crlf][crlf]",
            PayloadContext(host = "example.com", port = 80, websocketUpgrade = true),
        )
        assertEquals(
            "GET / HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "Connection: keep-alive, Upgrade\r\n" +
                "X-Online-Host: example.com\r\n" +
                "Upgrade: websocket\r\n" +
                "\r\n",
            parsed.normalized,
        )
    }

    @Test
    fun nonDefaultPortIsIncludedOnHostHeader() {
        val parsed = PayloadParser.parse(
            "GET / HTTP/1.1[crlf][crlf]",
            PayloadContext(host = "example.com", port = 8080),
        )
        assertTrue(parsed.normalized.contains("Host: example.com:8080\r\n"))
    }

    @Test
    fun rejectsUnknownTokensAndUnsafeHost() {
        val unknown = assertThrows(PayloadParseException::class.java) {
            PayloadParser.parse("GET / [nope]", PayloadContext("example.com", 80))
        }
        assertTrue(unknown.message!!.contains("[nope]"))
        assertTrue(
            PayloadParser.validate("ok", PayloadContext(host = "bad\r\nHost", port = 80)).isNotEmpty(),
        )
        assertTrue(PayloadParser.validate("ok", PayloadContext(host = "example.com", port = 0)).isNotEmpty())
    }
}

class SocketInjectorTest {
    @Test
    fun injectWritesPayloadAndCompletesHttpHandshake() = runBlocking {
        ServerSocket(0).use { server ->
            val template = "CONNECT [host_port] [protocol][crlf]Host: [host][crlf][split][crlf]"
            val expected = PayloadParser.parse(
                template,
                PayloadContext(host = "example.com", port = 443, injectStandardHeaders = false),
            ).chunks.joinToString(separator = "") { it.text() }
            val failure = arrayOfNulls<Throwable>(1)
            val serverThread = Thread {
                try {
                    server.accept().use { client ->
                        client.soTimeout = 3_000
                        val received = readExactly(client.getInputStream(), expected.length)
                        check(String(received, Charsets.ISO_8859_1) == expected)
                        val output = client.getOutputStream()
                        output.write(
                            "HTTP/1.1 200 Connection Established\r\n\r\n".toByteArray(Charsets.ISO_8859_1),
                        )
                        output.flush()
                        Thread.sleep(300)
                    }
                } catch (thrown: Throwable) {
                    failure[0] = thrown
                }
            }
            serverThread.isDaemon = true
            serverThread.start()

            val connection = SocketInjector().inject(
                InjectRequest(
                    connectHost = "127.0.0.1",
                    connectPort = server.localPort,
                    serverHost = "example.com",
                    serverPort = 443,
                    payloadTemplate = template,
                    injectStandardHeaders = false,
                    splitDelayMillis = 20,
                    readTimeoutMillis = 3_000,
                ),
            )
            try {
                assertEquals(expected.length, connection.bytesWritten)
                assertEquals(200, connection.httpStatus)
                assertFalse(connection.tls)
                assertFalse(connection.socket.isClosed)
            } finally {
                connection.close()
            }
            serverThread.join(5_000)
            failure[0]?.let { throw it }
            assertFalse(serverThread.isAlive)
        }
    }

    @Test
    fun httpErrorStatusFailsTheHandshake() = runBlocking {
        ServerSocket(0).use { server ->
            val serverThread = Thread {
                server.accept().use { client ->
                    client.soTimeout = 3_000
                    val buffer = ByteArray(128)
                    client.getInputStream().read(buffer)
                    client.getOutputStream().write(
                        "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.ISO_8859_1),
                    )
                    client.getOutputStream().flush()
                }
            }
            serverThread.isDaemon = true
            serverThread.start()

            val error = assertThrows(InjectException::class.java) {
                runBlocking {
                    SocketInjector().inject(
                        InjectRequest(
                            connectHost = "127.0.0.1",
                            connectPort = server.localPort,
                            payloadTemplate = "PING[crlf]",
                            injectStandardHeaders = false,
                            readTimeoutMillis = 3_000,
                        ),
                    )
                }
            }
            assertTrue(error.message!!.contains("403"))
            serverThread.join(5_000)
        }
    }

    private fun readExactly(input: java.io.InputStream, size: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(256)
        while (output.size() < size) {
            val read = input.read(buffer)
            check(read >= 0) { "socket closed before the payload arrived" }
            output.write(buffer, 0, read)
        }
        return output.toByteArray()
    }
}
