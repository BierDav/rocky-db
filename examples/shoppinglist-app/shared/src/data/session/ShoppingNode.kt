package org.example.examples.shopping.data.session

import androidx.room.RoomDatabase
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.example.examples.shopping.data.ShoppingRepository
import org.example.examples.shopping.data.coordination.Approvals
import org.example.examples.shopping.data.db.ShoppingDatabase
import org.example.examples.shopping.data.db.ShoppingSchema
import org.example.examples.shopping.data.household.Household
import org.example.examples.shopping.data.household.NodeKind
import org.example.examples.shopping.data.household.PairingCode
import org.example.examples.shopping.data.tips.HouseholdTips
import org.example.examples.shopping.util.readText
import org.example.examples.shopping.util.removeFile
import org.example.examples.shopping.util.replaceText
import rocky.PeerTransport
import rocky.Rocky
import rocky.RockyConfiguration
import rocky.RockyDatabase
import rocky.RockyNetworkService
import rocky.SecretStore
import rocky.ServiceCoordinator
import rocky.room.RockyRoom
import rocky.room.managedRockyRoom

/** What differs per platform: where data and keys live, how Room is built and how devices reach each other. */
class ShoppingPlatform(
    val directory: String,
    /** How this device names itself when it starts a household. */
    val deviceName: String,
    val room: (path: String) -> RoomDatabase.Builder<ShoppingDatabase>,
    /** Read on each open, so a reset can choose fresh keys. */
    val secrets: () -> SecretStore? = { null },
    /** Read on each open: iroh unless a driver chose another transport before the first one. */
    val transport: () -> PeerTransport = { PeerTransport.Iroh() },
    /** Read on each open, like [transport]: the deployment's coordination service; none disables decisions. */
    val coordinator: suspend () -> ServiceCoordinator? = { null },
    /** Sees each opened database first, for instance to follow Android's app lifecycle. */
    val opened: (RockyDatabase) -> Unit = {},
    /** Sees each database before it closes, undoing [opened]. */
    val closed: (RockyDatabase) -> Unit = {},
    /** On reset, after [directory] is removed: forgets what else the installation kept, such as keys and settings. */
    val erase: suspend () -> Unit = {},
    /** Platform visibility cancels application upkeep alongside SDK sync. */
    val foreground: Flow<Boolean> = flowOf(true),
    val diagnostic: (String) -> Unit = {},
)

/** One open installation: Rocky, Room on its file and the household's background work. Close it to release them. */
class ShoppingNode private constructor(
    val rocky: RockyDatabase,
    private val room: RockyRoom<ShoppingDatabase>,
    val self: String,
    /** Whether the deployment has a coordination service, whether or not this device composes it. */
    coordinated: Boolean,
    foreground: Flow<Boolean>,
    private val kindPath: String,
    initialKind: NodeKind?,
    private val closed: (RockyDatabase) -> Unit,
    internal val failure: Deferred<Throwable>,
    private val backgroundErrors: CoroutineExceptionHandler,
    private val platform: ShoppingPlatform,
    online: Boolean,
) {
    val repository = ShoppingRepository(room.room, rocky)
    val household = Household(room.room, rocky, self)
    val approvals = Approvals(room.room, rocky, household, self, coordinated)
    val tips = HouseholdTips(rocky, platform.room, platform.directory)
    val isTrusted: Boolean get() = rocky.isIssuer
    val canCreateLists: Boolean get() = isTrusted || kind == NodeKind.Full
    private val mutableOnline = MutableStateFlow(online)

    /** The **Networking enabled** switch, kept across restarts: a device switched off reopens without a network. */
    val online: StateFlow<Boolean> = mutableOnline.asStateFlow()
    private var attached: RockyNetworkService? = null
    private val networking = Mutex()

    suspend fun setOnline(enabled: Boolean) = networking.withLock {
        if (enabled) removeFile(offlinePath(platform.directory)) else replaceText(offlinePath(platform.directory), "")
        if (enabled && rocky.openedNetwork == null && attached == null) {
            // Opened offline: attaching starts the network, and what this device published meanwhile leaves now.
            attached = rocky.attach(platform.transport())
            rocky.setAutomaticSync(true)
            rocky.enterForeground()
        }
        rocky.setNetworkingEnabled(enabled)
        mutableOnline.value = enabled
    }
    var kind: NodeKind? = initialKind
        private set

    private suspend fun rememberKind(kind: NodeKind) {
        replaceText(kindPath, kind.name)
        this.kind = kind
    }
    private val work = CoroutineScope(SupervisorJob() + Dispatchers.IO + backgroundErrors).launch {
        foreground.distinctUntilChanged().collectLatest { visible ->
            if (visible) {
                coroutineScope {
                    launch { household.run() }
                    launch { approvals.run() }
                    launch { tips.run() }
                }
            }
        }
    }

    suspend fun close() = withContext(NonCancellable) {
        work.cancelAndJoin()
        try {
            closed(rocky)
        } finally {
            try {
                attached?.close()
            } finally {
                room.close()
            }
        }
    }

    companion object {
        private fun configuration(platform: ShoppingPlatform, service: ServiceCoordinator?, online: Boolean = true): RockyConfiguration = Rocky.configure(platform.directory, ShoppingSchema) {
            secrets(platform.secrets())
            coordinator(service)
            networking {
                transport = platform.transport()
                enabled = online
            }
        }

        private fun offlinePath(directory: String) = "$directory/networking-disabled"

        /** A new household with this device as its first trusted device. */
        suspend fun create(platform: ShoppingPlatform): ShoppingNode = open(platform, trusted = true) { coordinator ->
            configuration(platform, coordinator).create()
        }.configure {
            // Rocky defines no bookmark: the household follows `main`, and a schema migration's opening inherits
            // the signed minimum of trusted devices in sync.
            rocky.tips.createBookmark("main")
            rocky.tips.follow("main")
            rocky.tips.setGenesisMinimum(1u)
            rememberKind(NodeKind.Trusted)
            household.record(self, platform.deviceName, NodeKind.Trusted)
            Approvals.start(household.trusted)
        }

        /** Joins with a scanned [code]; a partial device holds only the lists shared with it. */
        suspend fun join(platform: ShoppingPlatform, code: PairingCode): ShoppingNode = open(platform, trusted = code.kind == NodeKind.Trusted) { coordinator ->
            configuration(platform, coordinator).join(code.invitation)
        }.configure {
            rememberKind(code.kind)
            rocky.partitions.role(code.kind.role)
            if (isTrusted) household.record(self, code.name, NodeKind.Trusted)
        }

        /**
         * Opens the existing installation. With networking switched off it opens without a network, so a schema this
         * app publishes on opening stays on this device until networking is switched on again. A device composing the
         * coordination service needs its network to open; it opens with networking off instead, and a coordinated
         * publication stays private until its close is final anyway.
         */
        suspend fun resume(platform: ShoppingPlatform, confirmation: String? = null): ShoppingNode = open(platform, trusted = null) { coordinator ->
            configuration(platform, coordinator, readText(offlinePath(platform.directory)) == null || coordinator != null).open(confirmation)
        }.configure {
            if (isTrusted && rocky.observeStatus().first().authority.verifiedRevocation == null && household.devices().first().none { it.node == self }) {
                household.record(self, platform.deviceName, NodeKind.Trusted)
            }
        }

        private suspend fun ShoppingNode.configure(block: suspend ShoppingNode.() -> Unit): ShoppingNode = try {
            platform.diagnostic("opening stage=configure_start")
            block()
            tips.keepSeals()
            platform.diagnostic("opening stage=configure_ready")
            this
        } catch (error: Throwable) {
            close()
            throw error
        }

        /**
         * Only trusted devices compose the coordination service: they alone end tips' logs.
         * A member that composed it would hold every seal of a coordinated tip back until it could confirm the
         * terminal itself, which only trusted nodes can. [trusted] is null when the kind is read from the device.
         */
        private suspend fun open(platform: ShoppingPlatform, trusted: Boolean?, open: suspend (ServiceCoordinator?) -> RockyDatabase): ShoppingNode {
            var opened: ShoppingNode? = null
            try {
                return withContext(Dispatchers.IO) {
                    platform.diagnostic("opening stage=runtime_start")
                    val configured = platform.coordinator()
                    val kindPath = "${platform.directory}/device-kind"
                    val kind = readText(kindPath)?.let { requireNotNull(NodeKind.of(it)) { "Unknown local device kind" } }
                    val rocky = open(configured.takeIf { trusted ?: (kind == null || kind == NodeKind.Trusted) })
                    platform.diagnostic("opening stage=runtime_ready")
                    var room: RockyRoom<ShoppingDatabase>? = null
                    try {
                        // Before anything syncs: the persisted switch also holds for a device opened with its network.
                        if (readText(offlinePath(platform.directory)) != null && rocky.openedNetwork != null) rocky.setNetworkingEnabled(false)
                        platform.opened(rocky)
                        val self = rocky.session().node
                        // Room keeps only a lock file next to Rocky's.
                        val failure = CompletableDeferred<Throwable>()
                        val backgroundErrors = CoroutineExceptionHandler { _, error -> failure.complete(error) }
                        val openedRoom = managedRockyRoom({ rocky }, { platform.room("${platform.directory}/shopping") }, Dispatchers.IO + backgroundErrors)
                        room = openedRoom
                        platform.diagnostic("opening stage=room_ready")
                        val online = readText(offlinePath(platform.directory)) == null
                        ShoppingNode(rocky, openedRoom, self, configured != null, platform.foreground, kindPath, kind, platform.closed, failure, backgroundErrors, platform, online).also { opened = it }
                    } catch (error: Throwable) {
                        withContext(NonCancellable) {
                            try {
                                platform.closed(rocky)
                                room?.close()
                            } finally {
                                rocky.close()
                            }
                        }
                        throw error
                    }
                }
            } catch (error: Throwable) {
                // Cancellation can discard the result when returning from the IO dispatcher.
                withContext(NonCancellable) { opened?.close() }
                throw error
            }
        }
    }
}
