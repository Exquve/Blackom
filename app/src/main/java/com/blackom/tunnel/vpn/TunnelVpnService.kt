package com.blackom.tunnel.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.blackom.tunnel.R
import java.net.DatagramSocket
import java.net.Socket
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class TunnelState {
    IDLE,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
}

/**
 * Foreground [VpnService] that owns `tun0` and hands its file descriptor to [Tun2SocksBridge].
 *
 * Call [prepare] and complete the system consent dialog before [start]. A second start while
 * the tunnel is up is ignored. [stop] and [onRevoke] both tear the session down.
 */
class TunnelVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val generation = java.util.concurrent.atomic.AtomicInteger()
    private var bridge: Tun2SocksBridge = Tun2SocksBridge()
    private var sessionJob: Job? = null
    private var inForeground: Boolean = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureChannel()
        when (intent?.action) {
            ACTION_STOP -> {
                publish(TunnelState.DISCONNECTING, getString(R.string.tunnel_state_disconnecting))
                enterForeground()
                disconnect(startId)
            }
            else -> {
                if (state.value != TunnelState.IDLE) {
                    enterForeground()
                    return START_REDELIVER_INTENT
                }
                publish(TunnelState.CONNECTING, getString(R.string.tunnel_state_connecting))
                enterForeground()
                connect(TunnelConfig.fromIntent(intent), startId)
            }
        }
        return START_REDELIVER_INTENT
    }

    override fun onRevoke() {
        disconnect(startId = -1)
        super.onRevoke()
    }

    override fun onDestroy() {
        generation.incrementAndGet()
        sessionJob?.cancel()
        bridge.stop()
        scope.coroutineContext[Job]?.cancel()
        publish(TunnelState.IDLE, getString(R.string.tunnel_state_idle))
        super.onDestroy()
    }

    private fun connect(config: TunnelConfig, startId: Int) {
        val ticket = generation.incrementAndGet()
        sessionJob?.cancel()
        val session = Tun2SocksBridge(mtu = config.mtu)
        bridge = session
        session.protector = object : TunnelProtector {
            override fun protectTcp(socket: Socket): Boolean = protect(socket)
            override fun protectUdp(socket: DatagramSocket): Boolean = protect(socket)
        }
        session.onLog = { message -> Log.i(TAG, message) }
        sessionJob = scope.launch {
            var ownedFd: Int? = null
            try {
                val problem = config.validate()
                if (problem != null) {
                    fail(ticket, startId, problem)
                    return@launch
                }
                val fd = establishTun(config)
                if (fd == null) {
                    fail(ticket, startId, "VPN permission has not been granted")
                    return@launch
                }
                ownedFd = fd
                if (ticket != generation.get()) {
                    closeFd(fd)
                    ownedFd = null
                    return@launch
                }
                publish(TunnelState.CONNECTING, "Opening ${config.socksHost}:${config.socksPort}")
                val started = withContext(Dispatchers.IO) {
                    session.startTun2Socks(fd, config.socksHost, config.socksPort)
                }
                ownedFd = null
                if (ticket != generation.get()) {
                    session.stop()
                    return@launch
                }
                if (!started) {
                    fail(ticket, startId, session.status.value.lastError ?: "tun2socks did not start")
                    return@launch
                }
                val version = session.status.value.nativeVersion?.let { " ($it)" }.orEmpty()
                publish(TunnelState.CONNECTED, "Connected to ${config.socksHost}:${config.socksPort}$version")
            } catch (cancelled: CancellationException) {
                ownedFd?.let { closeFd(it) }
                session.stop()
                throw cancelled
            } catch (error: Exception) {
                Log.e(TAG, "Tunnel start failed", error)
                ownedFd?.let { closeFd(it) }
                fail(ticket, startId, error.message ?: "Tunnel start failed")
            }
        }
    }

    private fun disconnect(startId: Int) {
        val ticket = generation.incrementAndGet()
        val session = bridge
        publish(TunnelState.DISCONNECTING, getString(R.string.tunnel_state_disconnecting))
        sessionJob?.cancel()
        sessionJob = scope.launch {
            withContext(Dispatchers.IO) { session.stop() }
            if (ticket != generation.get()) return@launch
            publish(TunnelState.IDLE, getString(R.string.tunnel_state_idle))
            leaveForeground(startId)
        }
    }

    private fun fail(ticket: Int, startId: Int, message: String) {
        if (ticket != generation.get()) return
        Log.w(TAG, message)
        publish(TunnelState.IDLE, message)
        leaveForeground(startId)
    }

    private fun establishTun(config: TunnelConfig): Int? {
        val builder = Builder()
            .setSession(config.sessionName)
            .setMtu(config.mtu)
            .addAddress(config.address, config.prefixLength)
            .setBlocking(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }
        config.dns.forEach { server -> builder.addDnsServer(server) }
        config.routes.forEach { route -> builder.addRoute(route.address, route.prefixLength) }
        applyApplicationFilter(builder, config)
        val descriptor = builder.establish() ?: return null
        return descriptor.detachFd()
    }

    private fun applyApplicationFilter(builder: Builder, config: TunnelConfig) {
        val allowed = config.allowedApplications.filter { it.isNotBlank() && it != packageName }
        if (allowed.isNotEmpty()) {
            allowed.forEach { packageName -> addPackage(builder, packageName, allowedList = true) }
            return
        }
        val denied = (config.disallowedApplications + packageName).filter { it.isNotBlank() }.distinct()
        denied.forEach { packageName -> addPackage(builder, packageName, allowedList = false) }
    }

    private fun addPackage(builder: Builder, packageName: String, allowedList: Boolean) {
        try {
            if (allowedList) {
                builder.addAllowedApplication(packageName)
            } else {
                builder.addDisallowedApplication(packageName)
            }
        } catch (error: PackageManager.NameNotFoundException) {
            Log.w(TAG, "Package is not installed: $packageName", error)
        }
    }

    private fun ensureChannel() {
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) != null) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.tunnel_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        channel.description = getString(R.string.tunnel_channel_description)
        channel.setShowBadge(false)
        manager.createNotificationChannel(channel)
    }

    private fun enterForeground() {
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        inForeground = true
    }

    private fun leaveForeground(startId: Int) {
        if (inForeground) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            inForeground = false
        }
        if (startId < 0) stopSelf() else stopSelf(startId)
    }

    private fun buildNotification(): android.app.Notification {
        val stopIntent = Intent(this, TunnelVpnService::class.java).setAction(ACTION_STOP)
        val stopPending = PendingIntent.getService(
            this,
            STOP_REQUEST,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val current = state.value
        val detail = statusMessage.value.ifBlank { stateLabel(current) }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentTitle(getString(R.string.tunnel_notification_title))
            .setContentText(detail)
            .setStyle(NotificationCompat.BigTextStyle().bigText(detail))
            .setOngoing(current != TunnelState.IDLE)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .addAction(R.drawable.ic_stat_tunnel, getString(R.string.tunnel_action_stop), stopPending)
            .build()
    }

    private fun stateLabel(current: TunnelState): String {
        return when (current) {
            TunnelState.IDLE -> getString(R.string.tunnel_state_idle)
            TunnelState.CONNECTING -> getString(R.string.tunnel_state_connecting)
            TunnelState.CONNECTED -> getString(R.string.tunnel_state_connected)
            TunnelState.DISCONNECTING -> getString(R.string.tunnel_state_disconnecting)
        }
    }

    private fun publish(current: TunnelState, message: String) {
        _state.value = current
        _statusMessage.value = message
        if (inForeground) {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification())
        }
    }

    companion object {
        const val ACTION_START: String = "com.blackom.tunnel.vpn.action.START"
        const val ACTION_STOP: String = "com.blackom.tunnel.vpn.action.STOP"
        const val CHANNEL_ID: String = "blackom_tunnel"
        const val NOTIFICATION_ID: Int = 1001

        private const val TAG: String = "TunnelVpnService"
        private const val STOP_REQUEST: Int = 1

        private val _state = MutableStateFlow(TunnelState.IDLE)
        val state: StateFlow<TunnelState> = _state.asStateFlow()

        private val _statusMessage = MutableStateFlow("")
        val statusMessage: StateFlow<String> = _statusMessage.asStateFlow()

        fun prepare(context: Context): Intent? = VpnService.prepare(context)

        fun start(context: Context, config: TunnelConfig = TunnelConfig()) {
            ContextCompat.startForegroundService(context, config.toStartIntent(context))
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, TunnelVpnService::class.java).setAction(ACTION_STOP),
            )
        }

        private fun closeFd(fd: Int) {
            runCatching { ParcelFileDescriptor.adoptFd(fd).close() }
        }
    }
}
