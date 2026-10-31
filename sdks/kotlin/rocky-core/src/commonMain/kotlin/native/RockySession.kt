package rocky

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.*
import rocky.internal.native.NativeDatabaseSession

/** One enrolled device's secure database: the native engine, its enrollment and background sync. */
open class RockySession internal constructor(private val nativeSession: NativeDatabaseSession, internal val client: RockyClient, override val domain: String, val isIssuer: Boolean) : RuntimePort {
    private val closing = Mutex()

    // One SQL transaction at a time on this session.
    private val writing = Mutex()
    private var closed = false
    val credentials: Credentials get() = Credentials(this)
    val partitions: Partitions get() = client.partitions
    val tips: Tips get() = client.tips
    suspend fun status(): DatabaseStatus = nativeCall { nativeSession.status() }
    suspend fun statusAfter(token: String): DatabaseStatus = nativeCall { nativeSession.statusAfter(token) }
    fun observeStatus(): Flow<DatabaseStatus> = client.observation {
        var snapshot = status()
        while (true) {
            emit(snapshot)
            snapshot = statusAfter(snapshot.token)
        }
    }

    /** What the database did in the background: the kept events, then each new one. See [RockyEvent]. */
    fun activity(): Flow<RockyEvent> = client.activity()

    /** `committed` tells whether a write committed under `handle`. */
    suspend fun reconcile(handle: String): JsonObject = client.recoverMutation(handleBytes(handle))

    /** Persisted pruning policy for one granted collection; at least one other copy is always required. */
    suspend fun retention(collection: String, policy: RetentionPolicy? = null, maintain: Boolean = false): RetentionStatus = RetentionStatus.decode(
        client.call(
            request("retention") {
                put("collection", collection)
                policy?.let { put("policy", it.json()) }
                put("maintain", maintain)
            },
        ),
    )

    /** Bounds apply to this open database; set them again after reopening. */
    suspend fun retentionLimits(limits: RetentionLimits? = null): RetentionLimits = RetentionLimits.decode(client.call(request("retention_limits") { limits?.let { put("limits", it.json()) } }))
    suspend fun generation(): GenerationStatus = status().data.generation
    override fun observe(query: JsonObject): Flow<JsonObject> = client.observe(query)
    override suspend fun read(query: JsonObject): JsonObject = client.read(query)
    override suspend fun <T> write(handle: String, block: suspend SqlWrite.() -> T): T = transaction(handle, null, block)

    /** Local changes held because a newer schema removed what they write; see [HeldChanges]. */
    suspend fun heldChanges(): HeldChanges = HeldChanges.decode(client.call(request("held_changes")))

    /** Drops held change `id`; it is never sent. */
    suspend fun dropHeld(id: String): HeldChanges = HeldChanges.decode(client.call(request("drop_held") { put("id", id) }))

    /**
     * Re-authors held change `id` as `block`: an ordinary new transaction under `handle`, mapped to this schema and
     * stamped now, so it replaces what [HeldField.current] shows. The change leaves the list when it commits.
     */
    suspend fun <T> reauthor(id: String, handle: String = newMutationHandle(), block: suspend SqlWrite.() -> T): T = transaction(handle, id, block)

    /** Whether this device is a trusted node of its domain's coordinated logs, and the tip it follows. */
    suspend fun coordinatedStatus(): CoordinatedStatus = client.coordinatedStatus()

    private suspend fun <T> transaction(handle: String, reauthors: String?, block: suspend SqlWrite.() -> T): T = writing.withLock {
        val committed = handleBytes(handle)
        val transaction = object : SqlWrite {
            override suspend fun nextId(table: String): Long = client.nextId(table).toLong()
            override suspend fun nextId(table: String, vararg partitionValues: Any?): Long = client.nextId(table, JsonArray(partitionValues.map(::cell))).toLong()
            override suspend fun execute(sql: String, vararg values: Any?): Long = client.sql(sql, JsonArray(values.map(::cell))).text("changes").toLong()
        }
        client.sql("BEGIN")
        try {
            transaction.block().also {
                client.call(
                    request("sql") {
                        put("sql", "COMMIT")
                        put("handle", committed)
                        reauthors?.let { put("reauthors", it) }
                    },
                )
            }
        } catch (error: Throwable) {
            // Fails harmlessly when the transaction already ended.
            withContext(NonCancellable) { runCatching { client.sql("ROLLBACK") } }
            throw error
        }
    }

    /** A fresh invitation for one device with `profile`, replacing the previous one. Only an issuer invites. */
    suspend fun pairing(profile: GrantProfile, label: ByteArray? = null): PairingInvitation {
        val result = client.call(
            request("pairing") {
                put("profile", profile.json())
                label?.let { put("label", bytes(it)) }
            },
        )
        return PairingInvitation(result.text("uri"), result.text("expires").toLong(), profile(result.getValue("profile").jsonObject), result.text("sequence").toLong(), result.text("id"))
    }

    /** Whether this issuer's persisted invitation can still enroll a new device, also after reopening. */
    suspend fun invitationOpen(uri: String): Boolean = client.call(request("invitation_open") { put("uri", uri) }).getValue("open").jsonPrimitive.boolean

    /**
     * Starter pairing of another device under its own identity. By default that identity gets issuer authority, with
     * its own author numbers, so losing either device locks nobody out; `issuing = false` pairs a writer of every table
     * instead. A device sharing this identity's provider joins with `RockyDatabase.enrollIdentity` instead.
     */
    suspend fun pairDevice(issuing: Boolean = true): PairingInvitation = pairing(
        if (issuing) {
            GrantProfile.Issuer
        } else {
            GrantProfile.Writer(client.call(request("domain")).getValue("collections").jsonArray.map { it.jsonPrimitive.content }.toSet())
        },
    )
    suspend fun session(): SessionStatus = status(client.call(request("session")))

    /**
     * Fresh credentials from any issuer: the same grants, with tables a later generation grants like held ones.
     * Adopting a generation needs none; a revoked device is refused.
     */
    suspend fun renew(): SessionStatus = status(client.call(request("renew")))
    private fun status(result: JsonObject) = SessionStatus(
        result.text("principal"),
        result.text("node"),
        revocations(result.getValue("revocations").jsonObject),
        result.text("expires").toLong(),
        result.getValue("issuer").jsonPrimitive.boolean,
        profile(result.getValue("profile").jsonObject),
        result.text("transport"),
    )

    /**
     * Issues `profile` to the device whose public keys `device` names, as `Credentials.prepare` reported them. Returns
     * the bundle that device passes to `RockyDatabase.install`. It carries reader keys: hand it over like a secret.
     * The device is then known like an enrolled one. Only an issuer grants. `delegations` above 1 lets the device
     * delegate further itself. `authors` reserves that many numbers for the recipient's nodes.
     */
    suspend fun grant(device: JsonObject, profile: GrantProfile, ttlSeconds: Long? = null, delegations: Int? = null, authors: Int? = null): JsonObject = issue("grant", device, profile, ttlSeconds, delegations, authors)

    /**
     * Delegates `profile`, which must narrow this device's own grants, to a prepared device. Any device whose credentials
     * allow a further delegation does so; the delegate receives no more rights, tables, columns or lifetime than this
     * device holds, and renews by being delegated to again and calling `install`.
     */
    suspend fun delegate(device: JsonObject, profile: GrantProfile, ttlSeconds: Long? = null, delegations: Int? = null, authors: Int? = null): JsonObject = issue("delegate", device, profile, ttlSeconds, delegations, authors)
    private suspend fun issue(kind: String, device: JsonObject, profile: GrantProfile, ttlSeconds: Long?, delegations: Int?, authors: Int?): JsonObject = client.call(
        request(kind) {
            put("device", device)
            if (profile is GrantProfile.Grants) put("grants", grants(profile.grants)) else put("profile", profile.json())
            ttlSeconds?.let { put("ttl", it) }
            delegations?.let { put("delegations", it) }
            authors?.let { put("authors", it) }
        },
    ).getValue("supplied").jsonObject

    /** Replaces this device's credentials with a supplied bundle, such as a renewed delegation. They are verified first. */
    suspend fun install(supplied: JsonObject): SessionStatus = status(client.call(request("install") { put("supplied", supplied) }))

    /** Every other device the replicated issuer registry records. Only an issuer reads it. */
    suspend fun devices(): List<Device> = client.call(request("devices")).getValue("devices").jsonArray.map { it.jsonObject }.map {
        Device(
            it.text("node"),
            it.text("user"),
            it.text("enrolled").toLong(),
            it.getValue("revoked").jsonPrimitive.boolean,
            (it["profile"] as? JsonObject)?.let(::profile) ?: GrantProfile.Grants(emptyList()),
            it["expires"]?.jsonPrimitive?.contentOrNull?.toLong(),
            (it["label"] as? JsonArray)?.map { byte -> byte.jsonPrimitive.int.toByte() }?.toByteArray(),
            it["invitation"]?.jsonPrimitive?.contentOrNull,
        )
    }

    /** Sets the opaque application label, at most 256 bytes, of a device the registry records. Only an issuer does. */
    suspend fun setDeviceLabel(node: String, label: ByteArray) {
        client.call(
            request("device_label") {
                put("node", node)
                put("label", JsonArray(label.map { JsonPrimitive(it.toInt() and 0xff) }))
            },
        )
    }

    /** This device's contact for another enrolled device to add. Needs an attached network that accepts. */
    suspend fun contact(): Contact = client.call(request("contact")).let { Contact(it.text("uri"), it.text("node"), routes(it)) }

    /** Routes a preissued invitation or issuer contact through a custody peer; grants stay unchanged. */
    suspend fun routeEnrollment(uri: String, custodyContact: String): String = client.call(
        request("enrollment_route") {
            put("uri", uri)
            put("contact", custodyContact)
        },
    ).text("uri")

    /** Asks admitted contacts for a 16-byte node ID; a hint grants no access. */
    suspend fun requestContact(nodeId: String): String? = client.call(request("contact_request") { put("id", nodeId) }).getValue("node").jsonPrimitive.contentOrNull

    /**
     * Keeps the device a contact names as a contact to sync with, or learns its new routes. A contact grants
     * nothing: any device of the domain whose credentials and the revocation set admit it is served.
     */
    suspend fun addPeer(contact: String): String = client.call(request("peer_add") { put("contact", contact) }).text("node")

    /** Forgets a peer, an issuer included: any issuer renews any device. [AuthorityStatus.renewalRoutes] reports known renewal routes. */
    suspend fun removePeer(node: String) {
        client.call(request("peer_remove") { put("node", node) })
    }

    /** Every peer met or kept as a contact; [Peer.isConfigured] tells them apart. */
    suspend fun peers(): List<Peer> = nativeCall { nativeSession.peers() }

    /** Each discovery path as on, off or unavailable with its reason; a found peer appears in [peers] with source `discovery`. */
    suspend fun discovery(): DiscoveryStatus = nativeCall { nativeSession.discovery() }

    /** The network service's state and bounds, independent of the database's. */
    suspend fun network(): NetworkStatus = nativeCall { nativeSession.network() }

    /**
     * Signs a revocation statement ending one node's certificate and starts a new key epoch for the tables it read;
     * remaining devices receive both when they renew. Other nodes of its identity keep working. Data it already
     * decrypted stays with it. Another issuer's node is revoked the same way; no issuer holds the publisher key.
     */
    suspend fun revoke(node: String) {
        client.call(request("revoke") { put("node", node) })
    }

    /**
     * Revokes an identity: every chain through it ends, so all its nodes stop at once, and so does every grant it
     * signed as an issuer. The owner's identity is never revoked.
     */
    suspend fun revokeIdentity(identity: String) {
        client.call(request("revoke") { put("identity", identity) })
    }

    /** Deletes this device's keys and ends its sessions; `purge` also removes its local data on close. */
    suspend fun logout(purge: Boolean = false) {
        client.call(request("logout") { put("purge", purge) })
    }
    suspend fun setNetworkingEnabled(enabled: Boolean) = nativeCall { nativeSession.setNetworkingEnabled(enabled) }
    suspend fun syncOnce(): ReconciliationReport = nativeCall { nativeSession.syncOnce() }
    suspend fun setAutomaticSync(enabled: Boolean) = nativeCall { nativeSession.setAutomaticSync(enabled) }

    /** The owner's control of this domain on its coordination service, with the tenant's control key. */
    fun service(tenant: ByteArray): ServiceOwner = ServiceOwner(this, tenant)

    open suspend fun close() = withContext(NonCancellable) {
        closing.withLock {
            if (!closed) {
                closed = true
                client.close()
            }
        }
    }
    companion object {
        private fun routes(value: JsonObject) = value.getValue("routes").jsonArray.map { it.jsonObject }.map { Route(it.text("transport"), it.text("address")) }
        private fun JsonObject.text(name: String): String = getValue(name).jsonPrimitive.content
        internal fun GrantProfile.json(): JsonObject = buildJsonObject {
            when (this@json) {
                is GrantProfile.Custody -> {
                    put("kind", "custody")
                    put("scopes", JsonArray(tables.map(::JsonPrimitive)))
                }

                is GrantProfile.Reader -> {
                    put("kind", "reader")
                    put("scopes", JsonArray(tables.map(::JsonPrimitive)))
                }

                is GrantProfile.Writer -> {
                    put("kind", "writer")
                    put("scopes", JsonArray(tables.map(::JsonPrimitive)))
                }

                GrantProfile.Issuer -> put("kind", "issuer")

                is GrantProfile.Grants -> {
                    put("kind", "grants")
                    put("grants", grants(grants))
                }
            }
        }
        internal fun grants(grants: List<Grant>) = JsonArray(
            grants.map { grant ->
                buildJsonObject {
                    put("scope", grant.table)
                    put("rights", JsonArray(grant.rights.map { JsonPrimitive(it.wire) }))
                    grant.columns?.let { put("columns", JsonArray(it.map(::JsonPrimitive))) }
                }
            },
        )
        internal fun revocations(value: JsonObject) = RevocationStatus(value.text("digest"), value.getValue("statements").jsonPrimitive.content.toULong())
        internal fun profile(value: JsonObject): GrantProfile {
            fun tables() = value.getValue("scopes").jsonArray.map { it.jsonPrimitive.content }.toSet()
            return when (val kind = value.text("kind")) {
                "custody" -> GrantProfile.Custody(tables())

                "reader" -> GrantProfile.Reader(tables())

                "writer" -> GrantProfile.Writer(tables())

                "issuer" -> GrantProfile.Issuer

                "grants" -> GrantProfile.Grants(
                    value.getValue("grants").jsonArray.map { it.jsonObject }.map { grant ->
                        Grant(
                            grant.text("scope"),
                            grant.getValue("rights").jsonArray.map { Right.of(it.jsonPrimitive.content) }.toSet(),
                            grant["columns"]?.jsonArray?.map { it.jsonPrimitive.content }?.toSet(),
                        )
                    },
                )

                else -> throw IllegalStateException("unknown grant profile $kind")
            }
        }
        fun newHandle(): String {
            val bytes = secureBytes(32)
            return bytes.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
        }
    }
}
