package rocky

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.*
import rocky.internal.native.NativeBinding
import rocky.internal.native.NativeConnection
import rocky.internal.native.NativeDatabase
import rocky.internal.native.NativeDatabaseSession
import rocky.internal.native.NativeException
import rocky.internal.native.NativeNetwork
import rocky.internal.native.NativeNetworkService
import rocky.internal.native.NativeTableEvents
import rocky.internal.native.NativeTransactionOutcome
import rocky.internal.native.prepareDevice

/**
 * The sealed state a read-only driver connection reads instead of the live tables: a [Seal] this device keeps, or
 * the seal a [Bookmark] shows, resolved when the connection opens. See `docs/runtime/kept-seals.md`.
 */
sealed interface RockyBinding {
    data class Seal(val seal: String) : RockyBinding
    data class Bookmark(val name: String) : RockyBinding
}

/** How a committed transaction with replayed writes stands on this device. */
sealed interface RockyTransactionOutcome {
    data object Applied : RockyTransactionOutcome

    /** Its writes are gone: `constraint`, `admission`, `schema` or `engine`; [sealed] makes the drop final. */
    data class Dropped(val reason: String, val sealed: Boolean) : RockyTransactionOutcome
}

/** A transaction replay dropped: its [token], as [RockyDatabase.transactionOutcome] takes it, and its outcome. */
class RockyDrop(val token: ByteArray, val outcome: RockyTransactionOutcome.Dropped)

/** Database ownership is independent of sessions and of an optional network. */
class RockyDatabase private constructor(
    internal val native: NativeDatabase,
    nativeSession: NativeDatabaseSession,
    client: RockyClient,
    domain: String,
    issuer: Boolean,
) : RockySession(nativeSession, client, domain, issuer) {
    private val lifecycle = Mutex()
    private var closed = false

    /** The service attached by create/join/open; closing it leaves the database open. */
    val openedNetwork: RockyNetworkService? = native.openedNetwork()?.let(::RockyNetworkService)

    /** Attaches an in-process log for development; its ledger lasts only for this process. */
    suspend fun coordinate(log: DevelopmentLog) = nativeCall { log.native.attach(native) }

    /** Each session owns its observations and cancellation, while sharing committed storage. */
    fun openSession(): RockySession = native.session().let { session -> RockySession(session, RockyClient(SessionTransport(session, domain)), domain, isIssuer) }
    suspend fun attach(transport: PeerTransport): RockyNetworkService {
        currentCoroutineContext().ensureActive()
        var attached: RockyNetworkService? = null
        try {
            val service = withContext(NonCancellable) { nativeCall { RockyNetworkService(withNetwork(transport) { native.attach(it ?: error("missing network")) }) } }
            attached = service
            currentCoroutineContext().ensureActive()
            return service
        } catch (error: Throwable) {
            withContext(NonCancellable) { attached?.close() }
            throw error
        }
    }

    /**
     * For a process the platform may freeze or kill: cancels the native automatic pass promptly, so none
     * runs after this returns, closes live links and stops local-network discovery. The file, sessions, attached network and its
     * endpoint stay open, and reads and writes continue; acknowledged writes are already durable.
     */
    suspend fun enterBackground() = lifecycle.withLock {
        client.call(request("network_background"))
    }

    /** Allows live links again and resumes automatic sync with an immediate pass if opened with it. */
    suspend fun enterForeground() = lifecycle.withLock {
        client.call(request("network_foreground"))
    }

    /**
     * The native handles of a SQL driver, such as `rocky-sqlite`'s: a writer is a secure SQL session, a reader
     * steps snapshot cursors. See `docs/runtime/sql-driver.md`.
     */
    suspend fun driverConnection(
        readOnly: Boolean,
        profile: String? = null,
        transactionTimeoutMillis: Long? = null,
        binding: RockyBinding? = null,
    ): NativeConnection = nativeCall {
        native.connect(
            readOnly,
            profile,
            transactionTimeoutMillis?.toULong(),
            when (binding) {
                null -> null
                is RockyBinding.Seal -> NativeBinding.Seal(binding.seal)
                is RockyBinding.Bookmark -> NativeBinding.Bookmark(binding.name)
            },
        )
    }

    /**
     * How the transaction a driver connection committed under [token] stands: null until one of its replayed
     * writes replayed. A local commit stays visible until replay drops it.
     */
    suspend fun transactionOutcome(token: ByteArray): RockyTransactionOutcome? = nativeCall {
        when (val outcome = native.transactionOutcome(token)) {
            null -> null
            is NativeTransactionOutcome.Applied -> RockyTransactionOutcome.Applied
            is NativeTransactionOutcome.Dropped -> RockyTransactionOutcome.Dropped(outcome.reason, outcome.sealed)
        }
    }

    /**
     * Each transaction a replay drops on this device, this device's or another's, after the local commit that removed
     * its writes. Applications tell the user; nothing is retried for them.
     */
    fun drops(): Flow<RockyDrop> = flow {
        val events = driverTableEvents()
        try {
            while (true) {
                for (token in nativeCall { events.next() }.dropped) {
                    (transactionOutcome(token) as? RockyTransactionOutcome.Dropped)?.let { emit(RockyDrop(token, it)) }
                }
            }
        } finally {
            events.destroy()
        }
    }

    /** Committed changes of `tables`, or of every table, for a driver to invalidate what it read. */
    suspend fun driverTableEvents(tables: List<String>? = null): NativeTableEvents = nativeCall { native.observeTables(tables) }
    suspend fun backup(archive: String): JsonObject = nativeCall {
        Json.parseToJsonElement(native.backup(archive)).jsonObject
    }
    override suspend fun close() = withContext(NonCancellable) {
        lifecycle.withLock {
            if (!closed) {
                closed = true
                try {
                    super.close()
                } finally {
                    try {
                        nativeCall { native.shutdown() }
                    } finally {
                        openedNetwork?.destroy()
                        native.destroy()
                    }
                }
            }
        }
    }
    companion object : PlatformOpeners() {
        private suspend fun make(automaticSync: Boolean, open: () -> NativeDatabase): RockyDatabase {
            currentCoroutineContext().ensureActive()
            var opened: RockyDatabase? = null
            try {
                val database = withContext(Dispatchers.IO + NonCancellable) {
                    val native = nativeCall { open() }
                    try {
                        val domain = native.scope()
                        val session = native.session()
                        val client = RockyClient(SessionTransport(session, domain))
                        val info = client.call(request("domain"))
                        RockyDatabase(native, session, client, domain, info.getValue("issuer").jsonPrimitive.boolean).also { opened = it }
                    } catch (error: Throwable) {
                        native.closeAfterFailure()
                        throw error
                    }
                }
                currentCoroutineContext().ensureActive()
                if (automaticSync) {
                    database.setAutomaticSync(true)
                    database.enterForeground()
                }
                return database
            } catch (error: Throwable) {
                withContext(NonCancellable) { opened?.close() }
                throw error
            }
        }
        private suspend fun NativeDatabase.closeAfterFailure() = withContext(NonCancellable) {
            try {
                shutdown()
            } finally {
                destroy()
            }
        }

        /** A new installation writes at once: its node credential already carries its author number. */
        private suspend fun RockyDatabase.withAuthors(required: Boolean): RockyDatabase {
            try {
                if (required && status().data.bootstrapPending) syncOnce()
            } catch (error: Throwable) {
                // A member whose issuer did not answer asks again on its next sync.
                if (required || error !is RockyException) {
                    close()
                    throw error
                }
            }
            return this
        }

        /** Whether [directory] holds an installation to `open` or `resume`. */
        fun exists(directory: String): Boolean = fileExists("$directory/identity.json")

        /** Local composition: no network is started unless supplied. */
        suspend fun local(directory: String, schema: Schema, secrets: SecretStore? = null, coordinator: ServiceCoordinator? = null, identity: IdentityProvider? = null): RockyDatabase = make(false) { NativeDatabase.create(directory, schema.json(), secretProvider(secrets), identityProvider(identity), null, coordinator?.trustBundle, null) }

        /** Installs an independently supplied credential bundle after Credentials.prepare. */
        suspend fun install(
            directory: String,
            schema: Schema,
            supplied: JsonObject,
            secrets: SecretStore? = null,
            transport: PeerTransport? = null,
            coordinator: ServiceCoordinator? = null,
            identity: IdentityProvider? = null,
        ): RockyDatabase = make(false) {
            withNetwork(transport) { selected ->
                NativeDatabase.install(
                    directory,
                    schema.json(),
                    supplied.toString(),
                    secretProvider(secrets),
                    identityProvider(identity),
                    selected,
                    coordinator?.trustBundle,
                )
            }
        }

        /**
         * A new domain owned by this device's identity, [identity]'s or one made in the secret store, whose key is the
         * domain's publisher key, with its certified node author number.
         */
        suspend fun create(directory: String, schema: Schema, transport: PeerTransport = PeerTransport.Iroh(), secrets: SecretStore? = null, automaticSync: Boolean = true, coordinator: ServiceCoordinator? = null, identity: IdentityProvider? = null): RockyDatabase = make(automaticSync) { withNetwork(transport) { NativeDatabase.create(directory, schema.json(), secretProvider(secrets), identityProvider(identity), it, coordinator?.trustBundle, null) } }
            .withAuthors(required = true)

        /** Enrolls [identity], or one made in the secret store, with an invitation; its node certificate carries its author number. */
        suspend fun join(directory: String, schema: Schema, invitation: String, transport: PeerTransport = PeerTransport.Iroh(), secrets: SecretStore? = null, automaticSync: Boolean = true, coordinator: ServiceCoordinator? = null, identity: IdentityProvider? = null): RockyDatabase = make(automaticSync) { withNetwork(transport) { NativeDatabase.join(directory, schema.json(), invitation, requireNotNull(it), secretProvider(secrets), identityProvider(identity), coordinator?.trustBundle) } }
            .let { it.withAuthors(required = it.isIssuer) }

        /**
         * Another node of [identity], which already holds grants: the node of it that [contact] names hands it what the
         * identity holds, and [identity] certifies this node with an author number it reserves. No issuer and no
         * invitation is involved.
         */
        suspend fun enrollIdentity(directory: String, schema: Schema, contact: String, identity: IdentityProvider, transport: PeerTransport = PeerTransport.Iroh(), secrets: SecretStore? = null, automaticSync: Boolean = true, coordinator: ServiceCoordinator? = null): RockyDatabase = make(automaticSync) { withNetwork(transport) { NativeDatabase.enrollIdentity(directory, schema.json(), contact, requireNotNull(it), requireNotNull(identityProvider(identity)), secretProvider(secrets), coordinator?.trustBundle) } }
            .let { it.withAuthors(required = false) }

        /** Resumes the installation in [directory], or creates a new domain there. */
        suspend fun openOrCreate(directory: String, schema: Schema, transport: PeerTransport = PeerTransport.Iroh(), secrets: SecretStore? = null, automaticSync: Boolean = true, coordinator: ServiceCoordinator? = null, confirmation: String? = null, identity: IdentityProvider? = null): RockyDatabase = if (exists(directory)) {
            resume(directory, schema, transport, secrets, automaticSync, coordinator, confirmation, identity)
        } else {
            create(directory, schema, transport, secrets, automaticSync, coordinator, identity)
        }

        /** Opens an installation; one installed under an application's [identity] needs that provider every time. */
        suspend fun open(directory: String, schema: Schema, transport: PeerTransport? = null, secrets: SecretStore? = null, automaticSync: Boolean = false, coordinator: ServiceCoordinator? = null, confirmation: String? = null, identity: IdentityProvider? = null): RockyDatabase = make(automaticSync) {
            withNetwork(transport) {
                if (confirmation == null) NativeDatabase.open(directory, schema.json(), secretProvider(secrets), identityProvider(identity), it, coordinator?.trustBundle) else NativeDatabase.openConfirmed(directory, schema.json(), confirmation, secretProvider(secrets), identityProvider(identity), it, coordinator?.trustBundle)
            }
        }
        suspend fun resume(directory: String, schema: Schema, transport: PeerTransport = PeerTransport.Iroh(), secrets: SecretStore? = null, automaticSync: Boolean = true, coordinator: ServiceCoordinator? = null, confirmation: String? = null, identity: IdentityProvider? = null): RockyDatabase = open(directory, schema, transport, secrets, automaticSync, coordinator, confirmation, identity)
        suspend fun restore(directory: String, schema: Schema, archive: String, invitation: String, transport: PeerTransport = PeerTransport.Iroh(), secrets: SecretStore? = null, coordinator: ServiceCoordinator? = null): RockyDatabase = make(false) { withNetwork(transport) { NativeDatabase.restore(directory, schema.json(), archive, invitation, requireNotNull(it), secretProvider(secrets), coordinator?.trustBundle) } }
        fun newHandle(): String = newMutationHandle()
    }
}

/** Ends only this attached service; borrowed transports and endpoints stay application-owned. */
class RockyNetworkService internal constructor(private val native: NativeNetworkService) {
    internal fun destroy() = native.destroy()
    suspend fun close() = withContext(NonCancellable) {
        try {
            native.shutdown()
        } finally {
            native.destroy()
        }
    }
}

/** Credential lifecycle over managed storage, independently usable from coordination. */
class Credentials internal constructor(internal val session: RockySession) {
    companion object : PlatformCredentialOpeners() {
        /** Prepares the public identity and node keys for an independent issuer: [identity]'s, or one made in the secret store; secret material stays in the providers. */
        suspend fun prepare(directory: String, secrets: SecretStore? = null, identity: IdentityProvider? = null): JsonObject = withContext(Dispatchers.IO) {
            nativeCall { Json.parseToJsonElement(prepareDevice(directory, secretProvider(secrets), identityProvider(identity))).jsonObject }
        }
    }
    suspend fun status(): SessionStatus = session.session()
    suspend fun renew(): SessionStatus = session.renew()
    suspend fun pairing(profile: GrantProfile, label: ByteArray? = null): PairingInvitation = session.pairing(profile, label)
    suspend fun invitationOpen(uri: String): Boolean = session.invitationOpen(uri)

    /** Another device of this user, an issuer unless `issuing = false`; see `RockySession.pairDevice`. */
    suspend fun pairDevice(issuing: Boolean = true): PairingInvitation = session.pairDevice(issuing)

    /** Raw grants or a profile for a prepared device; see `RockySession.grant`. */
    suspend fun grant(device: JsonObject, grants: List<Grant>, ttlSeconds: Long? = null, delegations: Int? = null, authors: Int? = null): JsonObject = session.grant(device, GrantProfile.Grants(grants), ttlSeconds, delegations, authors)

    /** Narrowed grants of this device for a prepared device; see `RockySession.delegate`. */
    suspend fun delegate(device: JsonObject, grants: List<Grant>, ttlSeconds: Long? = null, delegations: Int? = null, authors: Int? = null): JsonObject = session.delegate(device, GrantProfile.Grants(grants), ttlSeconds, delegations, authors)

    /** Replaces this device's credentials with a supplied bundle; see `RockySession.install`. */
    suspend fun install(supplied: JsonObject): SessionStatus = session.install(supplied)

    suspend fun revoke(node: String) = session.revoke(node)
    suspend fun devices(): List<Device> = session.devices()
    suspend fun setDeviceLabel(node: String, label: ByteArray) = session.setDeviceLabel(node, label)
    suspend fun logout(purge: Boolean = false) = session.logout(purge)
}

private fun network(peers: PeerTransport): NativeNetwork = when (peers) {
    is PeerTransport.Endpoint -> NativeNetwork.endpoint(
        (
            peers.endpoint as? RockyEndpoint
                ?: throw RockyException("rejected", false, "the endpoint must be a RockyEndpoint")
            ).native,
    )

    is PeerTransport.Iroh -> NativeNetwork.starter(
        buildJsonObject {
            put("kind", "iroh")
            put("relay", peers.relay)
            put("lookup", peers.lookup)
            put("topic", peers.topic)
            put("local", peers.local)
            peers.bind?.let { put("bind", it) }
        }.toString(),
    )
}
internal suspend fun <T> nativeCall(call: suspend () -> T): T = try {
    call()
} catch (error: NativeException.Request) {
    if (error.code == "confirmation_required" || error.code == "confirmation_mismatch") {
        throw RolloutConfirmationRequired(RolloutImpact.parse(error.detail), error.code == "confirmation_mismatch")
    }
    throw RockyException(error.code, error.retryable, error.detail)
} catch (error: NativeException.Failure) {
    throw RockyException("storage", true, error.detail)
}

private class SessionTransport(private val native: NativeDatabaseSession, scope: String) : Transport {
    private val domain = Json.parseToJsonElement(scope)
    override suspend fun call(request: JsonObject): JsonObject = nativeCall {
        val response = Json.parseToJsonElement(
            native.call(
                buildJsonObject {
                    put("version", 1)
                    put("scope", domain)
                    put("request", request)
                }.toString(),
            ),
        ).jsonObject
        check(response.getValue("version").jsonPrimitive.int == 1)
        if (response.getValue("status").jsonPrimitive.content == "error") {
            val error = response.getValue("error").jsonObject
            throw RockyException(
                error.getValue("code").jsonPrimitive.content,
                error.getValue("retryable").jsonPrimitive.boolean,
                error.getValue("message").jsonPrimitive.content,
            )
        }
        response.getValue("value").jsonObject
    }
    override suspend fun close() = withContext(NonCancellable) {
        try {
            native.shutdown()
        } finally {
            native.destroy()
        }
    }
}

private inline fun <T> withNetwork(peers: PeerTransport?, call: (NativeNetwork?) -> T): T {
    val selected = peers?.let(::network)
    return try {
        call(selected)
    } finally {
        selected?.destroy()
    }
}
