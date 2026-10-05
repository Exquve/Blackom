package com.blackom.tunnel.vpn

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

internal class Socks5Exception(message: String) : IOException(message)

internal object Socks5Client {
    fun greet(socket: Socket) {
        val output = socket.getOutputStream()
        output.write(byteArrayOf(5, 1, 0))
        output.flush()
        val reply = ByteArray(2)
        readFully(socket.getInputStream(), reply)
        if (reply[0] != 5.toByte() || reply[1] != 0.toByte()) {
            throw Socks5Exception("SOCKS5 server rejected no-auth")
        }
    }

    fun connectIpv4(socket: Socket, address: ByteArray, port: Int) {
        require(address.size == 4)
        val request = ByteArray(10)
        request[0] = 5
        request[1] = 1
        request[3] = 1
        address.copyInto(request, 4)
        request[8] = ((port ushr 8) and 0xFF).toByte()
        request[9] = (port and 0xFF).toByte()
        val output = socket.getOutputStream()
        output.write(request)
        output.flush()
        val relay = readReply(socket.getInputStream())
        if (relay.port !in 0..65535) throw Socks5Exception("Bad SOCKS5 connect reply")
    }

    fun udpAssociate(socket: Socket): InetSocketAddress {
        val request = byteArrayOf(5, 3, 0, 1, 0, 0, 0, 0, 0, 0)
        val output = socket.getOutputStream()
        output.write(request)
        output.flush()
        val relay = readReply(socket.getInputStream())
        val bound = relay.address?.hostAddress
        if (bound == null || bound == "0.0.0.0" || bound == "::") {
            val remote = socket.remoteSocketAddress as? InetSocketAddress
                ?: throw Socks5Exception("SOCKS5 UDP relay address is missing")
            return InetSocketAddress(remote.address, relay.port)
        }
        return relay
    }

    fun encodeUdp(address: ByteArray, port: Int, payload: ByteArray): ByteArray {
        val packet = ByteArray(10 + payload.size)
        packet[3] = 1
        address.copyInto(packet, 4)
        packet[8] = ((port ushr 8) and 0xFF).toByte()
        packet[9] = (port and 0xFF).toByte()
        payload.copyInto(packet, 10)
        return packet
    }

    fun decodeUdpPayload(packet: ByteArray, length: Int): ByteArray? {
        if (length < 4 || packet[2] != 0.toByte()) return null
        val offset = when (val type = packet[3].toInt() and 0xFF) {
            1 -> 10
            4 -> 22
            3 -> {
                if (length < 5) return null
                7 + (packet[4].toInt() and 0xFF)
            }
            else -> return null
        }
        if (offset > length) return null
        return packet.copyOfRange(offset, length)
    }

    private fun readReply(input: InputStream): InetSocketAddress {
        val header = ByteArray(4)
        readFully(input, header)
        if (header[0] != 5.toByte()) throw Socks5Exception("Bad SOCKS5 reply version")
        if (header[1] != 0.toByte()) throw Socks5Exception("SOCKS5 request failed: ${header[1].toInt() and 0xFF}")
        val address = when (val type = header[3].toInt() and 0xFF) {
            1 -> {
                val raw = ByteArray(4)
                readFully(input, raw)
                InetAddress.getByAddress(raw)
            }
            3 -> {
                val size = input.read()
                if (size <= 0) throw EOFException("Empty SOCKS5 domain")
                val raw = ByteArray(size)
                readFully(input, raw)
                InetAddress.getByName(String(raw, Charsets.UTF_8))
            }
            4 -> {
                val raw = ByteArray(16)
                readFully(input, raw)
                InetAddress.getByAddress(raw)
            }
            else -> throw Socks5Exception("Unsupported SOCKS5 address type $type")
        }
        val portBytes = ByteArray(2)
        readFully(input, portBytes)
        val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)
        return InetSocketAddress(address, port)
    }

    private fun readFully(input: InputStream, dest: ByteArray) {
        var offset = 0
        while (offset < dest.size) {
            val read = input.read(dest, offset, dest.size - offset)
            if (read < 0) throw EOFException("SOCKS5 stream closed")
            offset += read
        }
    }
}
