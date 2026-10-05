package com.blackom.tunnel.vpn

internal data class TcpSegment(
    val source: ByteArray,
    val destination: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val sequence: Long,
    val acknowledgment: Long,
    val flags: Int,
    val payload: ByteArray,
)

internal data class UdpDatagram(
    val source: ByteArray,
    val destination: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
)

internal const val PROTO_TCP: Int = 6
internal const val PROTO_UDP: Int = 17
internal const val TCP_FIN: Int = 0x01
internal const val TCP_SYN: Int = 0x02
internal const val TCP_RST: Int = 0x04
internal const val TCP_PSH: Int = 0x08
internal const val TCP_ACK: Int = 0x10

internal fun ipv4Bytes(text: String): ByteArray {
    val parts = text.split('.')
    if (parts.size != 4) throw IllegalArgumentException("Not an IPv4 address: $text")
    return ByteArray(4) { index ->
        val value = parts[index].toInt()
        if (value !in 0..255) throw IllegalArgumentException("Not an IPv4 address: $text")
        value.toByte()
    }
}

internal fun ipv4Text(bytes: ByteArray, offset: Int = 0): String {
    return (0 until 4).joinToString(".") { index -> (bytes[offset + index].toInt() and 0xFF).toString() }
}

internal fun seqAdd(sequence: Long, delta: Int): Long = (sequence + delta) and 0xFFFF_FFFFL

internal fun seqBefore(left: Long, right: Long): Boolean = (left - right).toInt() < 0

internal fun parseTcp(packet: ByteArray): TcpSegment? {
    if (packet.size < 40 || (packet[0].toInt() ushr 4) != 4) return null
    val headerLength = (packet[0].toInt() and 0x0F) * 4
    if (headerLength < 20 || packet.size < headerLength + 20) return null
    val totalLength = u16(packet, 2)
    val length = minOf(packet.size, totalLength)
    if (length < headerLength + 20) return null
    val fragment = u16(packet, 6) and 0x3FFF
    if (fragment != 0) return null
    if ((packet[9].toInt() and 0xFF) != PROTO_TCP) return null
    val source = packet.copyOfRange(12, 16)
    val destination = packet.copyOfRange(16, 20)
    val tcpOffset = headerLength
    val dataOffset = ((packet[tcpOffset + 12].toInt() ushr 4) and 0x0F) * 4
    if (dataOffset < 20 || tcpOffset + dataOffset > length) return null
    val payloadStart = tcpOffset + dataOffset
    return TcpSegment(
        source = source,
        destination = destination,
        sourcePort = u16(packet, tcpOffset),
        destinationPort = u16(packet, tcpOffset + 2),
        sequence = u32(packet, tcpOffset + 4),
        acknowledgment = u32(packet, tcpOffset + 8),
        flags = packet[tcpOffset + 13].toInt() and 0xFF,
        payload = packet.copyOfRange(payloadStart, length),
    )
}

internal fun parseUdp(packet: ByteArray): UdpDatagram? {
    if (packet.size < 28 || (packet[0].toInt() ushr 4) != 4) return null
    val headerLength = (packet[0].toInt() and 0x0F) * 4
    if (headerLength < 20 || packet.size < headerLength + 8) return null
    val totalLength = u16(packet, 2)
    val length = minOf(packet.size, totalLength)
    if ((u16(packet, 6) and 0x3FFF) != 0) return null
    if ((packet[9].toInt() and 0xFF) != PROTO_UDP) return null
    val udpLength = u16(packet, headerLength + 4)
    val payloadEnd = minOf(length, headerLength + udpLength)
    if (payloadEnd < headerLength + 8) return null
    return UdpDatagram(
        source = packet.copyOfRange(12, 16),
        destination = packet.copyOfRange(16, 20),
        sourcePort = u16(packet, headerLength),
        destinationPort = u16(packet, headerLength + 2),
        payload = packet.copyOfRange(headerLength + 8, payloadEnd),
    )
}

internal fun buildTcp(segment: TcpSegment, identification: Int): ByteArray {
    val tcpLength = 20 + segment.payload.size
    val packet = ByteArray(20 + tcpLength)
    writeIpv4Header(
        packet = packet,
        totalLength = packet.size,
        identification = identification,
        protocol = PROTO_TCP,
        source = segment.source,
        destination = segment.destination,
    )
    writeU16(packet, 20, segment.sourcePort)
    writeU16(packet, 22, segment.destinationPort)
    writeU32(packet, 24, segment.sequence)
    writeU32(packet, 28, segment.acknowledgment)
    packet[32] = (5 shl 4).toByte()
    packet[33] = segment.flags.toByte()
    writeU16(packet, 34, 65535)
    segment.payload.copyInto(packet, 40)
    val sum = transportChecksum(segment.source, segment.destination, PROTO_TCP, packet, 20, tcpLength)
    writeU16(packet, 36, sum)
    return packet
}

internal fun buildUdp(datagram: UdpDatagram, identification: Int): ByteArray {
    val udpLength = 8 + datagram.payload.size
    val packet = ByteArray(20 + udpLength)
    writeIpv4Header(
        packet = packet,
        totalLength = packet.size,
        identification = identification,
        protocol = PROTO_UDP,
        source = datagram.source,
        destination = datagram.destination,
    )
    writeU16(packet, 20, datagram.sourcePort)
    writeU16(packet, 22, datagram.destinationPort)
    writeU16(packet, 24, udpLength)
    datagram.payload.copyInto(packet, 28)
    val sum = transportChecksum(datagram.source, datagram.destination, PROTO_UDP, packet, 20, udpLength)
    writeU16(packet, 26, if (sum == 0) 0xFFFF else sum)
    return packet
}

internal fun checksumValid(packet: ByteArray): Boolean {
    if (packet.size < 20) return false
    val headerLength = (packet[0].toInt() and 0x0F) * 4
    if (headerLength < 20 || packet.size < headerLength) return false
    if (internetChecksum(packet, 0, headerLength) != 0) return false
    val protocol = packet[9].toInt() and 0xFF
    val total = minOf(packet.size, u16(packet, 2))
    if (protocol == PROTO_TCP || protocol == PROTO_UDP) {
        val transportSum = transportChecksum(
            packet.copyOfRange(12, 16),
            packet.copyOfRange(16, 20),
            protocol,
            packet,
            headerLength,
            total - headerLength,
        )
        return transportSum == 0 || (protocol == PROTO_UDP && u16(packet, headerLength + 6) == 0)
    }
    return true
}

private fun writeIpv4Header(
    packet: ByteArray,
    totalLength: Int,
    identification: Int,
    protocol: Int,
    source: ByteArray,
    destination: ByteArray,
) {
    packet[0] = 0x45
    writeU16(packet, 2, totalLength)
    writeU16(packet, 4, identification and 0xFFFF)
    writeU16(packet, 6, 0x4000)
    packet[8] = 64
    packet[9] = protocol.toByte()
    source.copyInto(packet, 12)
    destination.copyInto(packet, 16)
    val sum = internetChecksum(packet, 0, 20)
    writeU16(packet, 10, sum)
}

private fun transportChecksum(
    source: ByteArray,
    destination: ByteArray,
    protocol: Int,
    packet: ByteArray,
    offset: Int,
    length: Int,
): Int {
    var sum = wordSum(source, 0, 4)
    sum += wordSum(destination, 0, 4)
    sum += protocol.toLong()
    sum += length.toLong()
    sum += wordSum(packet, offset, length)
    return fold(sum).inv() and 0xFFFF
}

private fun internetChecksum(packet: ByteArray, offset: Int, length: Int): Int {
    return fold(wordSum(packet, offset, length)).inv() and 0xFFFF
}

private fun wordSum(data: ByteArray, offset: Int, length: Int): Long {
    var sum = 0L
    var index = offset
    var remaining = length
    while (remaining > 1) {
        sum += u16(data, index).toLong()
        index += 2
        remaining -= 2
    }
    if (remaining == 1) sum += (data[index].toInt() and 0xFF).toLong() shl 8
    return sum
}

private fun fold(value: Long): Int {
    var sum = value
    while (sum shr 16 != 0L) {
        sum = (sum and 0xFFFF) + (sum shr 16)
    }
    return sum.toInt()
}

private fun u16(data: ByteArray, offset: Int): Int {
    return ((data[offset].toInt() and 0xFF) shl 8) or (data[offset + 1].toInt() and 0xFF)
}

private fun u32(data: ByteArray, offset: Int): Long {
    return ((data[offset].toLong() and 0xFF) shl 24) or
        ((data[offset + 1].toLong() and 0xFF) shl 16) or
        ((data[offset + 2].toLong() and 0xFF) shl 8) or
        (data[offset + 3].toLong() and 0xFF)
}

private fun writeU16(data: ByteArray, offset: Int, value: Int) {
    data[offset] = ((value ushr 8) and 0xFF).toByte()
    data[offset + 1] = (value and 0xFF).toByte()
}

private fun writeU32(data: ByteArray, offset: Int, value: Long) {
    data[offset] = ((value ushr 24) and 0xFF).toByte()
    data[offset + 1] = ((value ushr 16) and 0xFF).toByte()
    data[offset + 2] = ((value ushr 8) and 0xFF).toByte()
    data[offset + 3] = (value and 0xFF).toByte()
}
