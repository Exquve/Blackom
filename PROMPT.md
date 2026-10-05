# MASTER SPECIFICATION & INSTRUCTIONS: Custom Tunnel & NetShare Client (HTTP Custom Style)

You are an expert Android Systems & Network Engineer. Your task is to build a production-grade, rootless Android Tunneling client with an integrated Modem-style Hotspot Traffic Monitor (NetShare).

Follow this specification strictly. Do NOT generate the entire codebase at once. Execute one step at a time when prompted by the user.

---

## 1. System Architecture & Tech Stack
- **Language & UI:** Kotlin, Jetpack Compose, Material 3, Kotlin Coroutines, StateFlow.
- **Minimum SDK:** 26 (Android 8.0) | **Target SDK:** 34+ (Android 14+).
- **Core Tunneler Stack:**
  - Android `VpnService` bridging TUN traffic to local loopback via `tun2socks` (hev-socks5-tunnel architecture).
  - Go-based unified core (Sing-box/Xray bridge via GoMobile / C-shared `.so`) supporting:
    - V2Ray Protocols: VMess, VLESS, Trojan, Shadowsocks, WireGuard, Hysteria2.
    - Transports & Security: RAW, WebSocket, gRPC, HTTP Upgrade, mKCP, TLS, REALITY, uTLS presets.
  - Native Socket Injector for SSH / OpenVPN / SlowDNS (dnstt) with HTTP Payload injection.
- **NetShare Architecture (Rootless Hotspot Sharing):**
  - Standard Wi-Fi Hotspot on Android bypasses `VpnService` on unrooted devices.
  - The app runs an embedded local HTTP/SOCKS5 Proxy & DNS interceptor bound to `0.0.0.0:8080`.
  - Tethered clients configure this proxy to route through the active VPN tunnel.
  - The embedded server inspects client sockets to provide a modem-style live monitor.

---

## 2. Technical Modules

### Module 1: Payload Parser & Token Substitution
Processes raw HTTP injection payloads before establishing tunnel handshakes.
- **Supported Tokens:**
  - `[crlf]` -> `\r\n`
  - `[lf]` -> `\n`
  - `[cr]` -> `\r`
  - `[protocol]` -> `HTTP/1.1`
  - `[host]` -> Remote server host
  - `[port]` -> Remote server port
  - `[host_port]` -> `[host]:[port]`
  - `[split]` -> Splits payload transmission into two separate TCP write packets.
  - `[instant_split]` -> Immediate chunked socket write.
- **Custom Headers:** Injects dynamic `Host`, `X-Online-Host`, `Upgrade: websocket`, `Connection: Upgrade`.

### Module 2: NetShare Server & Live Traffic Inspector
Embedded monitoring proxy capturing real-time client metadata:
1. **Device Discovery:** Reads `/proc/net/arp` and live socket connections to track Client IP, MAC address, and device hostname.
2. **Domain/Site Sniffer:**
   - Plain HTTP: Extracts the `Host:` header from incoming requests.
   - HTTPS: Extracts the target hostname from the proxy `CONNECT host:443 HTTP/1.1` request, and parses the SNI (Server Name Indication) extension from the TLS Client Hello handshake.
3. **Per-Device Live Metrics:**
   - Client IP & MAC.
   - Currently active domain/site.
   - Timestamped browsing history list.
   - Real-time download/upload bitrate (KB/s via 1-second sliding window byte counters).
   - Cumulative data transfer (Total Bytes In / Out).

### Module 3: Tunnel Engine & Android VpnService
- Lifecycle management of `VpnService` running as an Android Foreground Service.
- Creates `tun0` virtual network interface.
- Bridges incoming TUN IP packets to the local SOCKS5 inbound port using `hev-socks5-tunnel` JNI bindings.
- Handles route tables, MTU, DNS servers, and per-app proxying (allow/disallow package list).

### Module 4: Config Management & Security Locking
- URI Import/Export: `vmess://`, `vless://`, `trojan://`, `ss://`, `hysteria2://`, and base64 subscription lists.
- QR Code scan and generation.
- Config Locking: Encrypts configuration files using AES-GCM-256. Locks profile to target Android Hardware ID (hash of `Settings.Secure.ANDROID_ID`) and enforces expiration timestamps.

### Module 5: Jetpack Compose UI
- **Dashboard / Home:** Start/Stop button, latency/ping indicator, live log console, protocol selector.
- **NetShare Modem Monitor:** Modern router-dashboard style table listing connected devices, live speeds, active sites, and historical logs.
- **Config Editor:** Raw payload input area, SNI input, bug-host configurator, proxy IP/Port settings.

---

## 3. Sequential Execution Plan

When instructed, execute only the requested step with complete, compile-ready code (no placeholders or truncated sections).

- **Step 1: Gradle & Manifest Setup**
  - Configure `app/build.gradle.kts`, root `build.gradle.kts`, `settings.gradle.kts`.
  - Add all required dependencies: Jetpack Compose, Coroutines, Room, Lifecycle, and NDK/CMake configs.
  - Implement `AndroidManifest.xml` with permissions (`INTERNET`, `ACCESS_NETWORK_STATE`, `BIND_VPN_SERVICE`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_SPECIAL_USE`, `POST_NOTIFICATIONS`, `NEARBY_WIFI_DEVICES`).

- **Step 2: Payload Parser & Socket Injector**
  - Implement `PayloadParser.kt` supporting all replacement tags, split logic, and token validation.
  - Implement `SocketInjector.kt` to handle raw TCP socket handshakes, custom SSL/TLS wraps with SNI spoofing, and payload writing.

- **Step 3: NetShare Embedded Proxy & Traffic Sniffer**
  - Implement `NetShareServer.kt`: Multi-threaded local proxy listening on `0.0.0.0:8080`.
  - Implement `SniSniffer.kt`: Parses raw bytes of TLS Client Hello packets to extract SNI domains.
  - Implement `ArpReader.kt`: Parses `/proc/net/arp` to correlate client IPs with MAC addresses.
  - Implement `ClientTrafficTracker.kt`: In-memory sliding window bitrate and total byte counter per client IP.

- **Step 4: Android VpnService & Tun2Socks Bridge**
  - Implement `TunnelVpnService.kt`: Foreground service management, notification channels, TUN interface configuration.
  - Implement JNI bindings or IPC wrapper communicating with the local core / tun2socks.

- **Step 5: UI & State Presentation**
  - Implement Jetpack Compose UI models and StateFlow viewmodels.
  - Build `HomeScreen.kt` (tunneler controls & logs).
  - Build `NetShareDashboardScreen.kt` (modem-style device manager and traffic analyzer).