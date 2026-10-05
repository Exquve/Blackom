package com.blackom.tunnel.vpn

import java.io.IOException
import java.io.InputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelPacketTest {
    @Test
    fun tcpPacketRoundTripsAndVerifies() {
        val payload = "abc".toByteArray(Charsets.US_ASCII)
        val built = buildTcp(
            TcpSegment(
                source = ipv4Bytes("10.0.0.2"),
                destination = ipv4Bytes("1.1.1.1"),
                sourcePort = 40000,
                destinationPort = 443,
                sequence = 1000,
                acknowledgment = 50,
                flags = TCP_PSH or TCP_ACK,
                payload = payload,
            ),
            identification = 7,
        )
        assertTrue(checksumValid(built))
        val parsed = parseTcp(built)
        assertNotNull(parsed)
        parsed!!
        assertEquals(40000, parsed.sourcePort)
        assertEquals(443, parsed.destinationPort)
        assertEquals(1000L, parsed.sequence)
        assertEquals(50L, parsed.acknowledgment)
        assertEquals(TCP_PSH or TCP_ACK, parsed.flags)
        assertArrayEquals(payload, parsed.payload)
        assertArrayEquals(ipv4Bytes("10.0.0.2"), parsed.source)
    }

    @Test
    fun wrappedSequenceOrdersRetransmissions() {
        assertTrue(seqBefore(0xFFFF_FF00, 0x10))
        assertFalse(seqBefore(0x10, 0xFFFF_FF00))
        assertEquals(0L, seqAdd(0xFFFF_FFFF, 1))
    }
}

class Tun2SocksBridgeTest {
    @Test
    fun startFailsWhenSocksInboundIsClosed() {
        val endpoint = ServerSocket()
        endpoint.bind(InetSocketAddress("127.0.0.1", 0))
        val port = endpoint.localPort
        endpoint.close()
        val tun = QueueTun()
        val bridge = Tun2SocksBridge()
        try {
            assertFalse(bridge.startOn(tun, "127.0.0.1", port))
            assertEquals(BridgeRunState.IDLE, bridge.status.value.state)
            assertNotNull(bridge.status.value.lastError)
        } finally {
            bridge.stop()
        }
    }

    @Test(timeout = 20_000)
    fun tcpPayloadIsSplicedThroughSocks() {
        val echo = ServerSocket()
        echo.bind(InetSocketAddress("127.0.0.1", 0))
        val echoPort = echo.localPort
        val socks = ServerSocket()
        socks.bind(InetSocketAddress("127.0.0.1", 0))
        val socksPort = socks.localPort
        val protector = CountingProtector()
        val tun = QueueTun()
        val bridge = Tun2SocksBridge()
        bridge.protector = protector
        val echoThread = Thread {
            try {
                val socket = echo.accept()
                socket.soTimeout = 5_000
                val buffer = ByteArray(32)
                val read = socket.getInputStream().read(buffer)
                if (read > 0) {
                    socket.getOutputStream().write(buffer, 0, read)
                    socket.getOutputStream().flush()
                }
                socket.close()
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true }
        val socksThread = Thread {
            try {
                while (!socks.isClosed) {
                    val client = socks.accept()
                    Thread({ handleSocks(client) }, "test-socks").apply { isDaemon = true }.start()
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true }
        try {
            echoThread.start()
            socksThread.start()
            assertTrue(bridge.startOn(tun, "127.0.0.1", socksPort))
            assertEquals(BridgeRunState.RUNNING, bridge.status.value.state)
            assertTrue(protector.protectsBeforeConnect.get() >= 1)

            val clientIsn = 1000L
            tun.offer(
                buildTcp(
                    TcpSegment(
                        source = ipv4Bytes("10.0.0.2"),
                        destination = ipv4Bytes("127.0.0.1"),
                        sourcePort = 40000,
                        destinationPort = echoPort,
                        sequence = clientIsn,
                        acknowledgment = 0,
                        flags = TCP_SYN,
                        payload = ByteArray(0),
                    ),
                    identification = 1,
                ),
            )
            val handshake = nextTcp(tun)
            assertEquals(TCP_SYN or TCP_ACK, handshake.flags)
            assertEquals(seqAdd(clientIsn, 1), handshake.acknowledgment)
            assertTrue(checksumValid(tun.lastPacket))

            val payload = "ping".toByteArray(Charsets.US_ASCII)
            tun.offer(
                buildTcp(
                    TcpSegment(
                        source = ipv4Bytes("10.0.0.2"),
                        destination = ipv4Bytes("127.0.0.1"),
                        sourcePort = 40000,
                        destinationPort = echoPort,
                        sequence = seqAdd(clientIsn, 1),
                        acknowledgment = seqAdd(handshake.sequence, 1),
                        flags = TCP_PSH or TCP_ACK,
                        payload = payload,
                    ),
                    identification = 2,
                ),
            )
            val echoed = nextTcp(tun) { it.payload.isNotEmpty() }
            assertArrayEquals(payload, echoed.payload)
            assertEquals(seqAdd(clientIsn, 1 + payload.size), echoed.acknowledgment)
            assertTrue(protector.protectsBeforeConnect.get() >= 2)
            assertTrue(bridge.currentStatus().packetsFromTun >= 2)
            assertTrue(bridge.currentStatus().packetsToTun >= 2)
        } finally {
            bridge.stop()
            assertEquals(BridgeRunState.IDLE, bridge.status.value.state)
            runCatching { echo.close() }
            runCatching { socks.close() }
        }
    }

    @Test(timeout = 20_000)
    fun udpPayloadIsAssociatedThroughSocks() {
        val socks = ServerSocket()
        socks.bind(InetSocketAddress("127.0.0.1", 0))
        val relay = DatagramSocket(InetSocketAddress("127.0.0.1", 0))
        val tun = QueueTun()
        val bridge = Tun2SocksBridge()
        val relayThread = Thread {
            try {
                relay.soTimeout = 8_000
                val buffer = ByteArray(2048)
                val packet = DatagramPacket(buffer, buffer.size)
                relay.receive(packet)
                val reply = Socks5Client.encodeUdp(ipv4Bytes("1.1.1.1"), 53, "pong".toByteArray(Charsets.US_ASCII))
                relay.send(DatagramPacket(reply, reply.size, packet.socketAddress))
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true }
        val socksThread = Thread {
            try {
                while (!socks.isClosed) {
                    val client = socks.accept()
                    Thread({ handleUdpAssociate(client, relay.localPort) }, "test-socks-udp").apply { isDaemon = true }.start()
                }
            } catch (_: Exception) {
            }
        }.apply { isDaemon = true }
        try {
            relayThread.start()
            socksThread.start()
            assertTrue(bridge.startOn(tun, "127.0.0.1", socks.localPort))
            val payload = "dns".toByteArray(Charsets.US_ASCII)
            tun.offer(
                buildUdp(
                    UdpDatagram(
                        source = ipv4Bytes("10.0.0.2"),
                        destination = ipv4Bytes("1.1.1.1"),
                        sourcePort = 53000,
                        destinationPort = 53,
                        payload = payload,
                    ),
                    identification = 1,
                ),
            )
            val echoed = nextUdp(tun) { it.payload.isNotEmpty() }
            assertArrayEquals("pong".toByteArray(Charsets.US_ASCII), echoed.payload)
            assertEquals(53, echoed.sourcePort)
            assertEquals(53000, echoed.destinationPort)
            assertArrayEquals(ipv4Bytes("1.1.1.1"), echoed.source)
            assertArrayEquals(ipv4Bytes("10.0.0.2"), echoed.destination)
        } finally {
            bridge.stop()
            runCatching { relay.close() }
            runCatching { socks.close() }
        }
    }

    @Test
    fun defaultConfigMatchesTheTunnelProfile() {
        val config = TunnelConfig()
        assertEquals(null, config.validate())
        assertEquals("10.0.0.2", config.address)
        assertEquals(24, config.prefixLength)
        assertEquals(1500, config.mtu)
        assertEquals(listOf("1.1.1.1", "8.8.8.8"), config.dns)
        assertEquals("0.0.0.0", config.routes.single().address)
        assertEquals(0, config.routes.single().prefixLength)
        assertEquals("127.0.0.1", config.socksHost)
        assertEquals(10808, config.socksPort)
        val mixed = config.copy(allowedApplications = listOf("app.one"), disallowedApplications = listOf("app.two"))
        assertNotNull(mixed.validate())
    }

    private fun nextUdp(tun: QueueTun, predicate: (UdpDatagram) -> Boolean): UdpDatagram {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
        while (System.nanoTime() < deadline) {
            val packet = tun.take(500) ?: continue
            val parsed = parseUdp(packet) ?: continue
            if (predicate(parsed)) return parsed
        }
        throw AssertionError("Timed out waiting for a UDP packet from the bridge")
    }

    private fun handleUdpAssociate(client: Socket, relayPort: Int) {
        client.soTimeout = 5_000
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()
            val greeting = ByteArray(3)
            if (!readFully(input, greeting)) return
            output.write(byteArrayOf(5, 0))
            output.flush()
            val header = ByteArray(4)
            if (!readFully(input, header)) return
            if (!readFully(input, ByteArray(6))) return
            val reply = byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, 0, 0)
            reply[8] = ((relayPort ushr 8) and 0xFF).toByte()
            reply[9] = (relayPort and 0xFF).toByte()
            output.write(reply)
            output.flush()
            input.read()
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    private fun nextTcp(tun: QueueTun, predicate: (TcpSegment) -> Boolean = { true }): TcpSegment {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(8)
        while (System.nanoTime() < deadline) {
            val packet = tun.take(500) ?: continue
            val parsed = parseTcp(packet) ?: continue
            if (predicate(parsed)) return parsed
        }
        throw AssertionError("Timed out waiting for a TCP packet from the bridge")
    }

    private fun handleSocks(client: Socket) {
        client.soTimeout = 5_000
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()
            val greeting = ByteArray(3)
            if (!readFully(input, greeting)) return
            output.write(byteArrayOf(5, 0))
            output.flush()
            val header = ByteArray(4)
            if (!readFully(input, header)) return
            val address = ByteArray(4)
            val portBytes = ByteArray(2)
            if (!readFully(input, address) || !readFully(input, portBytes)) return
            val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
            val remote = Socket()
            remote.connect(InetSocketAddress(InetAddress.getByAddress(address), port), 3_000)
            output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0))
            output.flush()
            Thread({ copy(client, remote) }, "socks-up").apply { isDaemon = true }.start()
            copy(remote, client)
        } catch (_: Exception) {
        } finally {
            runCatching { client.close() }
        }
    }

    private fun copy(from: Socket, to: Socket) {
        try {
            val input = from.getInputStream()
            val output = to.getOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                output.write(buffer, 0, read)
                output.flush()
            }
        } catch (_: Exception) {
        }
    }

    private fun readFully(input: InputStream, dest: ByteArray): Boolean {
        var offset = 0
        while (offset < dest.size) {
            val read = input.read(dest, offset, dest.size - offset)
            if (read < 0) return false
            offset += read
        }
        return true
    }
}

private class CountingProtector : TunnelProtector {
    val protectsBeforeConnect = AtomicInteger()

    override fun protectTcp(socket: Socket): Boolean {
        if (!socket.isConnected) protectsBeforeConnect.incrementAndGet()
        return true
    }

    override fun protectUdp(socket: DatagramSocket): Boolean = true
}

private class QueueTun : TunDevice {
    private val incoming = ArrayBlockingQueue<ByteArray>(32)
    private val outgoing = ArrayBlockingQueue<ByteArray>(32)

    @Volatile private var closed = false
    var lastPacket: ByteArray = ByteArray(0)

    fun offer(packet: ByteArray) {
        if (!incoming.offer(packet, 2, TimeUnit.SECONDS)) {
            throw IOException("TUN inbound queue is full")
        }
    }

    fun take(timeoutMillis: Long): ByteArray? = outgoing.poll(timeoutMillis, TimeUnit.MILLISECONDS)

    override fun read(buffer: ByteArray): Int {
        while (!closed) {
            val packet = incoming.poll(200, TimeUnit.MILLISECONDS) ?: continue
            if (packet.isEmpty()) continue
            packet.copyInto(buffer)
            return packet.size
        }
        return -1
    }

    override fun write(packet: ByteArray) {
        if (closed) throw IOException("TUN is closed")
        lastPacket = packet
        if (!outgoing.offer(packet, 2, TimeUnit.SECONDS)) {
            throw IOException("TUN outbound queue is full")
        }
    }

    override fun close() {
        closed = true
        incoming.offer(ByteArray(0))
    }
}
