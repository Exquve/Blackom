package com.blackom.tunnel.vpn

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Owns the tun2socks session that splices `tun0` packets to a local SOCKS5 inbound.
 *
 * TCP connections are opened with SOCKS5 CONNECT. UDP datagrams, including DNS,
 * use SOCKS5 UDP ASSOCIATE. Outbound sockets are passed through [TunnelProtector]
 * so they do not re-enter the VPN.
 */
class Tun2SocksBridge(
    private val mtu: Int = DEFAULT_MTU,
) {
    var protector: TunnelProtector = TunnelProtector.ALLOW
    var onLog: (String) -> Unit = {}

    private val _status = MutableStateFlow(BridgeStatus())
    val status: StateFlow<BridgeStatus> = _status.asStateFlow()

    private val lifecycle = Any()
    private val tunLock = Any()
    private val tcpFlows = ConcurrentHashMap<FlowKey, TcpFlow>()
    private val udpFlows = ConcurrentHashMap<FlowKey, UdpFlow>()
    private val identification = AtomicInteger(1)
    private val packetsFromTun = AtomicLong()
    private val packetsToTun = AtomicLong()

    @Volatile private var running = false
    @Volatile private var device: TunDevice? = null
    @Volatile private var socksHost: String = DEFAULT_SOCKS_HOST
    @Volatile private var socksPort: Int = DEFAULT_SOCKS_PORT
    @Volatile private var probe: Socket? = null
    private var reader: Thread? = null
    private var workers: ExecutorService = newWorkers()

    fun startTun2Socks(fd: Int, socksHost: String, socksPort: Int): Boolean {
        val owned = ParcelFileTunDevice(ParcelFileDescriptor.adoptFd(fd))
        return startOn(owned, socksHost, socksPort, Tun2SocksNative.version)
    }

    fun stop() {
        val current: TunDevice?
        val thread: Thread?
        synchronized(lifecycle) {
            if (!running && device == null) {
                publish(BridgeRunState.IDLE, this.socksHost, this.socksPort, _status.value.lastError)
                return
            }
            running = false
            publish(BridgeRunState.STOPPING, socksHost, socksPort, null)
            current = device
            device = null
            thread = reader
            reader = null
            runCatching { probe?.close() }
        }
        runCatching { current?.close() }
        tcpFlows.values.forEach { flow -> flow.close() }
        tcpFlows.clear()
        udpFlows.values.forEach { flow -> flow.close() }
        udpFlows.clear()
        workers.shutdownNow()
        runCatching { thread?.join(2_000) }
        workers = newWorkers()
        publish(BridgeRunState.IDLE, socksHost, socksPort, null)
    }

    fun currentStatus(): BridgeStatus {
        val snapshot = _status.value
        return snapshot.copy(
            packetsFromTun = packetsFromTun.get(),
            packetsToTun = packetsToTun.get(),
        )
    }

    internal fun startOn(
        tun: TunDevice,
        socksHost: String,
        socksPort: Int,
        nativeVersion: String? = null,
    ): Boolean {
        synchronized(lifecycle) {
            if (running) {
                publish(BridgeRunState.RUNNING, this.socksHost, this.socksPort, "Bridge is already running")
                return false
            }
            if (socksHost.isBlank() || socksPort !in 1..65535) {
                publish(BridgeRunState.IDLE, socksHost, socksPort, "SOCKS5 endpoint is invalid")
                runCatching { tun.close() }
                return false
            }
            if (workers.isShutdown) workers = newWorkers()
            running = true
            device = tun
            this.socksHost = socksHost
            this.socksPort = socksPort
            packetsFromTun.set(0)
            packetsToTun.set(0)
            publish(BridgeRunState.STARTING, socksHost, socksPort, null, nativeVersion)
        }
        val probed = try {
            probeSocks(socksHost, socksPort)
        } catch (error: Exception) {
            failStart(error.message ?: "SOCKS5 handshake failed")
            return false
        }
        if (!probed || !running) {
            failStart(_status.value.lastError ?: "SOCKS5 inbound is not reachable")
            return false
        }
        val thread = Thread({ readLoop() }, "tun2socks").apply { isDaemon = true }
        reader = thread
        thread.start()
        publish(BridgeRunState.RUNNING, socksHost, socksPort, null, nativeVersion)
        onLog("tun2socks connected to $socksHost:$socksPort")
        return true
    }

    private fun failStart(message: String) {
        running = false
        val current = device
        device = null
        runCatching { current?.close() }
        publish(BridgeRunState.IDLE, socksHost, socksPort, message)
        onLog(message)
    }

    private fun probeSocks(host: String, port: Int): Boolean {
        if (!running) return false
        val socket = Socket()
        probe = socket
        return try {
            socket.tcpNoDelay = true
            if (!protector.protectTcp(socket)) throw IOException("Could not protect the SOCKS socket")
            socket.connect(InetSocketAddress(host, port), PROBE_TIMEOUT_MILLIS)
            if (!running) return false
            Socks5Client.greet(socket)
            true
        } finally {
            runCatching { socket.close() }
            if (probe === socket) probe = null
        }
    }

    private fun readLoop() {
        val buffer = ByteArray(MAX_PACKET)
        val current = device ?: return
        try {
            while (running) {
                val read = current.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                packetsFromTun.incrementAndGet()
                try {
                    dispatch(buffer.copyOf(read))
                } catch (error: Exception) {
                    onLog("Dropped a TUN packet: ${error.message}")
                }
            }
        } catch (_: IOException) {
            // The TUN device was closed.
        }
    }

    private fun dispatch(packet: ByteArray) {
        parseTcp(packet)?.let { segment ->
            onTcp(segment)
            return
        }
        parseUdp(packet)?.let { datagram ->
            onUdp(datagram)
        }
    }

    private fun onTcp(segment: TcpSegment) {
        val key = FlowKey(ipv4Text(segment.source), segment.sourcePort, ipv4Text(segment.destination), segment.destinationPort)
        val syn = segment.flags and TCP_SYN != 0 && segment.flags and TCP_ACK == 0
        if (syn) {
            if (tcpFlows.size >= MAX_TCP_FLOWS) return
            val ourIsn = java.util.concurrent.ThreadLocalRandom.current().nextInt().toLong() and 0xFFFF_FFFFL
            val flow = TcpFlow(
                key = key,
                source = segment.source,
                destination = segment.destination,
                sourcePort = segment.sourcePort,
                destinationPort = segment.destinationPort,
                clientIsn = segment.sequence,
                ourIsn = ourIsn,
            )
            val existing = tcpFlows.putIfAbsent(key, flow)
            if (existing != null) {
                resendSynAck(existing)
                return
            }
            synchronized(flow.lock) {
                writeTcp(synAck(flow))
                flow.ourSeq = seqAdd(ourIsn, 1)
            }
            workers.execute {
                try {
                    openTcp(flow)
                } catch (error: Exception) {
                    onLog("TCP ${key.destination}:${key.destinationPort} failed: ${error.message}")
                    sendRst(flow)
                    tcpFlows.remove(key, flow)
                    flow.close()
                }
            }
            return
        }
        val flow = tcpFlows[key] ?: return
        acceptFromClient(flow, segment)
    }

    private fun openTcp(flow: TcpFlow) {
        val socket = Socket()
        socket.tcpNoDelay = true
        if (!protector.protectTcp(socket)) throw IOException("Could not protect a TCP socket")
        socket.connect(InetSocketAddress(socksHost, socksPort), CONNECT_TIMEOUT_MILLIS)
        if (!running) {
            socket.close()
            tcpFlows.remove(flow.key, flow)
            flow.close()
            return
        }
        Socks5Client.greet(socket)
        Socks5Client.connectIpv4(socket, flow.destination, flow.destinationPort)
        synchronized(flow.lock) {
            if (flow.closed) {
                socket.close()
                return
            }
            flow.socket = socket
            val output = socket.getOutputStream()
            while (flow.pending.isNotEmpty()) {
                output.write(flow.pending.removeFirst())
            }
            output.flush()
        }
        pumpTcp(flow, socket)
    }

    private fun acceptFromClient(flow: TcpFlow, segment: TcpSegment) {
        synchronized(flow.lock) {
            if (flow.closed) return
            if (segment.flags and TCP_ACK != 0) flow.handshakeAcked = true
            if (segment.flags and TCP_RST != 0) {
                flow.close()
                tcpFlows.remove(flow.key, flow)
                return
            }
            var shouldAck = false
            if (segment.payload.isNotEmpty() && segment.sequence == flow.nextClientSeq) {
                deliverToSocks(flow, segment.payload)
                flow.nextClientSeq = seqAdd(flow.nextClientSeq, segment.payload.size)
                shouldAck = true
            } else if (segment.payload.isNotEmpty() && seqBefore(segment.sequence, flow.nextClientSeq)) {
                shouldAck = true
            }
            val finSequence = seqAdd(segment.sequence, segment.payload.size)
            if (segment.flags and TCP_FIN != 0 && !flow.clientFin && finSequence == flow.nextClientSeq) {
                flow.clientFin = true
                flow.nextClientSeq = seqAdd(flow.nextClientSeq, 1)
                runCatching { flow.socket?.shutdownOutput() }
                shouldAck = true
            }
            if (shouldAck) {
                writeTcp(controlSegment(flow, TCP_ACK))
            }
        }
    }

    private fun deliverToSocks(flow: TcpFlow, payload: ByteArray) {
        val socket = flow.socket
        if (socket == null) {
            flow.pending.addLast(payload.copyOf())
            return
        }
        val output = socket.getOutputStream()
        output.write(payload)
        output.flush()
    }

    private fun pumpTcp(flow: TcpFlow, socket: Socket) {
        val buffer = ByteArray(maxPayload())
        try {
            val input = socket.getInputStream()
            while (running && !flow.closed) {
                val read = input.read(buffer)
                if (read < 0) {
                    sendFin(flow)
                    break
                }
                if (read > 0) sendData(flow, buffer.copyOf(read))
            }
        } catch (_: IOException) {
            if (running && !flow.closed) sendRst(flow)
        } finally {
            tcpFlows.remove(flow.key, flow)
            flow.close()
        }
    }

    private fun sendData(flow: TcpFlow, payload: ByteArray) {
        var offset = 0
        while (offset < payload.size) {
            val size = minOf(maxPayload(), payload.size - offset)
            val chunk = payload.copyOfRange(offset, offset + size)
            synchronized(flow.lock) {
                if (flow.closed || flow.localFin) return
                writeTcp(controlSegment(flow, TCP_PSH or TCP_ACK, chunk))
                flow.ourSeq = seqAdd(flow.ourSeq, size)
            }
            offset += size
        }
    }

    private fun sendFin(flow: TcpFlow) {
        synchronized(flow.lock) {
            if (flow.closed || flow.localFin) return
            flow.localFin = true
            writeTcp(controlSegment(flow, TCP_FIN or TCP_ACK))
            flow.ourSeq = seqAdd(flow.ourSeq, 1)
        }
    }

    private fun sendRst(flow: TcpFlow) {
        synchronized(flow.lock) {
            if (flow.closed) return
            writeTcp(controlSegment(flow, TCP_RST or TCP_ACK))
        }
    }

    private fun resendSynAck(flow: TcpFlow) {
        synchronized(flow.lock) {
            if (flow.closed || flow.handshakeAcked) return
            writeTcp(synAck(flow))
        }
    }

    private fun synAck(flow: TcpFlow): TcpSegment {
        return TcpSegment(
            source = flow.destination,
            destination = flow.source,
            sourcePort = flow.destinationPort,
            destinationPort = flow.sourcePort,
            sequence = flow.initialSequence,
            acknowledgment = flow.nextClientSeq,
            flags = TCP_SYN or TCP_ACK,
            payload = ByteArray(0),
        )
    }

    private fun controlSegment(flow: TcpFlow, flags: Int, payload: ByteArray = ByteArray(0)): TcpSegment {
        return TcpSegment(
            source = flow.destination,
            destination = flow.source,
            sourcePort = flow.destinationPort,
            destinationPort = flow.sourcePort,
            sequence = flow.ourSeq,
            acknowledgment = flow.nextClientSeq,
            flags = flags,
            payload = payload,
        )
    }

    private fun onUdp(datagram: UdpDatagram) {
        val key = FlowKey(
            ipv4Text(datagram.source),
            datagram.sourcePort,
            ipv4Text(datagram.destination),
            datagram.destinationPort,
        )
        if (udpFlows.size >= MAX_UDP_FLOWS && !udpFlows.containsKey(key)) return
        val existing = udpFlows[key]
        if (existing != null) {
            existing.send(datagram.payload)
            return
        }
        val created = UdpFlow(
            key = key,
            source = datagram.source,
            destination = datagram.destination,
            sourcePort = datagram.sourcePort,
            destinationPort = datagram.destinationPort,
        )
        if (udpFlows.putIfAbsent(key, created) != null) {
            udpFlows[key]?.send(datagram.payload)
            return
        }
        created.send(datagram.payload)
        workers.execute {
            try {
                openUdp(created)
            } catch (error: Exception) {
                onLog("UDP ${key.destination}:${key.destinationPort} failed: ${error.message}")
                udpFlows.remove(key, created)
                created.close()
            }
        }
    }

    private fun openUdp(flow: UdpFlow) {
        val control = Socket()
        control.tcpNoDelay = true
        if (!protector.protectTcp(control)) throw IOException("Could not protect a UDP control socket")
        control.connect(InetSocketAddress(socksHost, socksPort), CONNECT_TIMEOUT_MILLIS)
        Socks5Client.greet(control)
        val relay = Socks5Client.udpAssociate(control)
        val udp = DatagramSocket()
        if (!protector.protectUdp(udp)) {
            udp.close()
            control.close()
            throw IOException("Could not protect a UDP socket")
        }
        flow.attach(control, udp, relay)
        workers.execute { receiveUdp(flow) }
    }

    private fun receiveUdp(flow: UdpFlow) {
        val socket = flow.udp ?: return
        val buffer = ByteArray(MAX_PACKET)
        val packet = DatagramPacket(buffer, buffer.size)
        try {
            while (running && !flow.closed) {
                socket.receive(packet)
                val payload = Socks5Client.decodeUdpPayload(packet.data, packet.length) ?: continue
                if (payload.isEmpty()) continue
                writeUdp(
                    UdpDatagram(
                        source = flow.destination,
                        destination = flow.source,
                        sourcePort = flow.destinationPort,
                        destinationPort = flow.sourcePort,
                        payload = payload,
                    ),
                )
            }
        } catch (_: IOException) {
            // The UDP association was closed.
        }
    }

    private fun writeTcp(segment: TcpSegment) {
        writePacket(buildTcp(segment, identification.getAndIncrement()))
    }

    private fun writeUdp(datagram: UdpDatagram) {
        writePacket(buildUdp(datagram, identification.getAndIncrement()))
    }

    private fun writePacket(packet: ByteArray) {
        val current = device ?: return
        try {
            synchronized(tunLock) {
                current.write(packet)
            }
        } catch (_: IOException) {
            return
        }
        packetsToTun.incrementAndGet()
    }

    private fun maxPayload(): Int = (mtu - 40).coerceAtLeast(200)

    private fun publish(
        state: BridgeRunState,
        host: String?,
        port: Int,
        error: String?,
        nativeVersion: String? = _status.value.nativeVersion,
    ) {
        _status.value = BridgeStatus(
            state = state,
            socksHost = host,
            socksPort = port,
            packetsFromTun = packetsFromTun.get(),
            packetsToTun = packetsToTun.get(),
            lastError = error,
            nativeVersion = nativeVersion,
        )
    }

    private fun newWorkers(): ExecutorService {
        return Executors.newCachedThreadPool { runnable ->
            Thread(runnable, "tun2socks-flow").apply { isDaemon = true }
        }
    }

    private class TcpFlow(
        val key: FlowKey,
        val source: ByteArray,
        val destination: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        clientIsn: Long,
        ourIsn: Long,
    ) {
        val lock = Any()
        val initialSequence: Long = ourIsn
        var nextClientSeq: Long = seqAdd(clientIsn, 1)
        var ourSeq: Long = ourIsn
        var handshakeAcked: Boolean = false
        var socket: Socket? = null
        var clientFin: Boolean = false
        var localFin: Boolean = false
        var closed: Boolean = false
        val pending = ArrayDeque<ByteArray>()

        fun close() {
            synchronized(lock) {
                if (closed) return
                closed = true
                pending.clear()
                runCatching { socket?.close() }
                socket = null
            }
        }
    }

    private class UdpFlow(
        val key: FlowKey,
        val source: ByteArray,
        val destination: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
    ) {
        private val lock = Any()
        private val pending = ArrayDeque<ByteArray>()
        var control: Socket? = null
        var udp: DatagramSocket? = null
        var relay: InetSocketAddress? = null
        var closed: Boolean = false

        fun send(payload: ByteArray) {
            synchronized(lock) {
                if (closed) return
                val socket = udp
                val target = relay
                if (socket == null || target == null) {
                    pending.addLast(payload.copyOf())
                    return
                }
                sendNow(socket, target, payload)
            }
        }

        fun attach(control: Socket, udp: DatagramSocket, relay: InetSocketAddress) {
            synchronized(lock) {
                if (closed) {
                    runCatching { control.close() }
                    runCatching { udp.close() }
                    return
                }
                this.control = control
                this.udp = udp
                this.relay = relay
                while (pending.isNotEmpty()) {
                    sendNow(udp, relay, pending.removeFirst())
                }
            }
        }

        fun close() {
            synchronized(lock) {
                if (closed) return
                closed = true
                pending.clear()
                runCatching { udp?.close() }
                runCatching { control?.close() }
                udp = null
                control = null
            }
        }

        private fun sendNow(socket: DatagramSocket, relay: InetSocketAddress, payload: ByteArray) {
            val encoded = Socks5Client.encodeUdp(destination, destinationPort, payload)
            val packet = DatagramPacket(encoded, encoded.size, relay)
            socket.send(packet)
        }
    }

    private data class FlowKey(
        val source: String,
        val sourcePort: Int,
        val destination: String,
        val destinationPort: Int,
    )

    companion object {
        const val DEFAULT_MTU: Int = 1500
        const val DEFAULT_SOCKS_HOST: String = "127.0.0.1"
        const val DEFAULT_SOCKS_PORT: Int = 10808
        private const val PROBE_TIMEOUT_MILLIS: Int = 3_000
        private const val CONNECT_TIMEOUT_MILLIS: Int = 10_000
        private const val MAX_PACKET: Int = 65535
        private const val MAX_TCP_FLOWS: Int = 128
        private const val MAX_UDP_FLOWS: Int = 256
    }
}

internal interface TunDevice : java.io.Closeable {
    fun read(buffer: ByteArray): Int
    fun write(packet: ByteArray)
}

internal class ParcelFileTunDevice(
    private val descriptor: ParcelFileDescriptor,
) : TunDevice {
    private val input = FileInputStream(descriptor.fileDescriptor)
    private val output = FileOutputStream(descriptor.fileDescriptor)

    override fun read(buffer: ByteArray): Int = input.read(buffer)

    override fun write(packet: ByteArray) {
        output.write(packet)
        output.flush()
    }

    override fun close() {
        runCatching { input.close() }
        runCatching { output.close() }
        runCatching { descriptor.close() }
    }
}

interface TunnelProtector {
    fun protectTcp(socket: Socket): Boolean
    fun protectUdp(socket: DatagramSocket): Boolean

    companion object {
        val ALLOW: TunnelProtector = object : TunnelProtector {
            override fun protectTcp(socket: Socket): Boolean = true
            override fun protectUdp(socket: DatagramSocket): Boolean = true
        }
    }
}

enum class BridgeRunState {
    IDLE,
    STARTING,
    RUNNING,
    STOPPING,
}

data class BridgeStatus(
    val state: BridgeRunState = BridgeRunState.IDLE,
    val socksHost: String? = null,
    val socksPort: Int = 0,
    val packetsFromTun: Long = 0,
    val packetsToTun: Long = 0,
    val lastError: String? = null,
    val nativeVersion: String? = null,
)
