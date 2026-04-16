package app.slipnet.tunnel

import app.slipnet.util.AppLog as Log
import mobile.Mobile
import mobile.MobileClient
import java.net.ServerSocket

/**
 * Bridge to the Go-based MasterDNS library.
 * Provides a TCP tunnel through DNS queries using MasterDnsVPN's ARQ protocol.
 *
 * MasterDnsVPN reference: https://github.com/masterking32/MasterDnsVPN
 */
object MasterdnsBridge {
    private const val TAG = "MasterdnsBridge"

    private var client: MobileClient? = null
    private var currentPort: Int = 0
    @Volatile private var pendingReleasePort: Int = 0

    fun getClientPort(): Int = currentPort

    /**
     * Start the MasterDNS client.
     *
     * @param domains Comma-separated list of MasterDns tunnel domains
     * @param encryptionKey Shared encryption key (required)
     * @param encryptionMethod 0=None 1=XOR 2=ChaCha20 3=AES-128 4=AES-192 5=AES-256
     * @param resolversText Newline-separated list of resolver IPs (e.g. "8.8.8.8\n1.1.1.1")
     * @param listenPort Local SOCKS5 port
     * @param listenHost Local SOCKS5 bind address (default: 127.0.0.1)
     * @return Result indicating success or failure
     */
    fun startClient(
        domains: String,
        encryptionKey: String,
        encryptionMethod: Int = 2,
        resolversText: String,
        listenPort: Int,
        listenHost: String = "127.0.0.1"
    ): Result<Unit> {
        Log.i(TAG, "========================================")
        Log.i(TAG, "Starting MasterDNS client")
        Log.i(TAG, "  Domains: $domains")
        Log.i(TAG, "  Encryption Method: $encryptionMethod")
        Log.i(TAG, "  Listen: $listenHost:$listenPort")
        Log.i(TAG, "========================================")

        if (domains.isBlank()) {
            return Result.failure(IllegalArgumentException("At least one domain is required"))
        }
        if (encryptionKey.isBlank()) {
            return Result.failure(IllegalArgumentException("Encryption key is required"))
        }

        stopClient()

        var actualPort = listenPort
        if (isPortInUse(listenPort)) {
            Log.w(TAG, "Port $listenPort still in use, scanning for alternative port")
            var found = false
            for (alt in (listenPort + 1)..(listenPort + 10)) {
                if (!isPortInUse(alt)) {
                    Log.i(TAG, "Using alternative port $alt (preferred $listenPort was still draining)")
                    actualPort = alt
                    found = true
                    break
                }
            }
            if (!found) {
                Log.w(TAG, "All alternative ports busy, waiting up to 3s for port $listenPort")
                if (!waitForPortAvailable(listenPort, 3_000)) {
                    return Result.failure(RuntimeException("Port $listenPort is still in use by a previous MasterDNS instance"))
                }
            }
        }

        return try {
            val newClient = Mobile.newClient(
                domains,
                encryptionKey,
                encryptionMethod,
                resolversText,
                actualPort,
                listenHost
            )
            client = newClient
            currentPort = actualPort

            newClient.start()

            Thread.sleep(200)

            if (newClient.isRunning) {
                Log.i(TAG, "MasterDNS client started successfully on port $actualPort")

                if (verifySocks5Listening(listenHost, actualPort)) {
                    Log.d(TAG, "Tunnel verified listening on $listenHost:$actualPort")
                } else {
                    Log.w(TAG, "Tunnel verification failed, but client reports running")
                }

                Result.success(Unit)
            } else {
                Log.e(TAG, "MasterDNS client failed to start - not running")
                client = null
                Result.failure(RuntimeException("MasterDNS client failed to start"))
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start MasterDNS client", e)
            client = null
            Result.failure(e)
        }
    }

    fun stopClient() {
        val c = client
        val port = if (c != null) currentPort else pendingReleasePort

        if (c != null) {
            client = null
            pendingReleasePort = port
            try {
                Log.d(TAG, "Stopping MasterDNS client...")
                c.stop()
                if (port > 0) {
                    try {
                        java.net.Socket().use { s ->
                            s.connect(java.net.InetSocketAddress("127.0.0.1", port), 500)
                        }
                    } catch (_: Exception) {}
                }
                Thread.sleep(100)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping MasterDNS client", e)
            }
            currentPort = 0
        }

        if (port > 0) {
            val portFree = if (isPortInUse(port)) {
                Log.w(TAG, "Port $port still in use after MasterDNS stop, waiting briefly...")
                waitForPortAvailable(port, 1000)
            } else {
                true
            }
            if (portFree) {
                pendingReleasePort = 0
                Log.d(TAG, "MasterDNS client stopped (port $port released)")
            } else {
                Log.w(TAG, "MasterDNS client stopped but port $port still held by Go runtime")
            }
        }
    }

    suspend fun stopClientBlocking() = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
        stopClient()
    }

    fun isRunning(): Boolean {
        return client?.isRunning == true
    }

    fun isClientHealthy(): Boolean {
        val c = client ?: return false
        return try {
            c.isRunning
        } catch (e: Exception) {
            Log.w(TAG, "Health check failed", e)
            false
        }
    }

    private fun waitForPortAvailable(port: Int, maxWaitMs: Long = 5000): Boolean {
        val startTime = System.currentTimeMillis()
        while (System.currentTimeMillis() - startTime < maxWaitMs) {
            if (!isPortInUse(port)) {
                return true
            }
            Log.d(TAG, "Waiting for port $port to be released...")
            Thread.sleep(50)
        }
        return !isPortInUse(port)
    }

    private fun isPortInUse(port: Int): Boolean {
        return try {
            ServerSocket().use { serverSocket ->
                serverSocket.reuseAddress = true
                serverSocket.bind(java.net.InetSocketAddress("127.0.0.1", port))
                false
            }
        } catch (e: java.net.BindException) {
            true
        } catch (e: Exception) {
            Log.w(TAG, "Error checking port $port: ${e.message}")
            true
        }
    }

    private fun verifySocks5Listening(host: String, port: Int): Boolean {
        return try {
            java.net.Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(host, port), 2000)
                true
            }
        } catch (e: Exception) {
            Log.w(TAG, "Tunnel verify failed: ${e.message}")
            false
        }
    }
}
