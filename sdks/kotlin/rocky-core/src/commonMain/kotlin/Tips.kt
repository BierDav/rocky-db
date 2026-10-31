package rocky

import kotlinx.serialization.json.*

/** Sealed history and the application bookmarks that devices follow. IDs are lowercase hex digests. */
class Tips internal constructor(private val client: RockyClient) {
    private suspend fun call(action: String, body: JsonObjectBuilder.() -> Unit = {}): JsonObject = client.call(
        request("tips") {
            put("action", action)
            body()
        },
    )

    suspend fun status(): TipStatus = TipStatus.decode(call("status"))
    suspend fun inspect(): TipInspection = TipInspection.decode(call("inspect"))

    /**
     * Continues the followed tip and advances its bookmark, or closes it when [close] is true. With a coordinated
     * log it fails [RockyException] `sealed` when another seal ended the log first and `coordinator_unavailable`
     * (retryable) when the coordinator did not confirm; nothing is published then.
     */
    suspend fun seal(close: Boolean = false): TipStatus = TipStatus.decode(call("seal") { put("close", close) })

    /**
     * The owner recovers the followed tip when no ordinary seal can end its coordinated log: one `continue` seal
     * replaces the log's exact head, and every bookmark on the tip follows it. Fails [RockyException] `rejected` on
     * another device and `stale_recovery` when the log moved meanwhile.
     */
    suspend fun recover(): TipStatus = TipStatus.decode(call("recover"))

    /** Opens a separate line on [seal]; [minimumInSync] is the domain's coordinated-log minimum, which a device cannot infer. */
    suspend fun open(seal: String, minimumInSync: UInt): String {
        require(minimumInSync > 0u) { "minimumInSync must be positive" }
        return call("open") {
            put("seal", seal)
            put("minimum_in_sync", minimumInSync.toLong())
        }.getValue("tip").jsonPrimitive.content
    }

    /** The owner signs how many trusted nodes must acknowledge a genesis-line seal its log committed for it to be final. */
    suspend fun setGenesisMinimum(minimumInSync: UInt): TipStatus {
        require(minimumInSync > 0u) { "minimumInSync must be positive" }
        return TipStatus.decode(call("genesis_minimum") { put("minimum_in_sync", minimumInSync.toLong()) })
    }

    /**
     * Finalizes ready seals of the followed path and compacts at the newest one that is final or has [keep] seals
     * after it. Final seals compact automatically during sync. Call this for earlier compaction at nonfinal
     * seals, which can still lose a race; keeping seals avoids a rebootstrap then.
     */
    suspend fun compact(keep: UInt = 0u): TipCompaction = TipCompaction.decode(call("compact") { put("keep", keep.toLong()) })

    /** Where this device's compaction of the followed path stands; nothing is compacted. */
    suspend fun compaction(): TipCompaction = TipCompaction.decode(call("compaction"))

    /**
     * Names the seals this device keeps from now on, among those of the tips it follows; seals no longer named are
     * released at once. A seal is kept once this device holds every frame through its frontier. Read a kept seal
     * through a connection bound to it ([RockyBinding]). See `docs/runtime/kept-seals.md`.
     */
    suspend fun keep(kept: KeptSeals): KeptSeals = KeptSeals.decode(
        call("keep") {
            putJsonObject("kept") {
                put("bookmarked", kept.bookmarked)
                put("latest", kept.latest.toLong())
                put("every", kept.every)
            }
        },
    )

    /** The seals this device keeps. */
    suspend fun kept(): KeptSeals = KeptSeals.decode(call("kept"))

    /**
     * Asks the next syncs to pull [seal]'s state from a device that keeps it, so that [open] and [follow] may start
     * there; nothing changes in the rows. [inspect] shows the seal `held` once pulled.
     */
    suspend fun pull(seal: String): TipStatus = TipStatus.decode(call("pull") { put("seal", seal) })

    /** Creates [name] on [tip], or on the followed tip when omitted. */
    suspend fun createBookmark(name: String, tip: String? = null): TipStatus = TipStatus.decode(
        call("create") {
            put("name", name)
            tip?.let { put("tip", it) }
        },
    )
    suspend fun moveBookmark(name: String, tip: String): TipStatus = TipStatus.decode(
        call("move") {
            put("name", name)
            put("tip", tip)
        },
    )
    suspend fun deleteBookmark(name: String): TipStatus = TipStatus.decode(call("delete") { put("name", name) })

    /** Persists a branch switch and pulls its starting seal; recovery completes it after sync or restart. */
    suspend fun followWhenReady(name: String): TipStatus = TipStatus.decode(call("follow_when_ready") { put("name", name) })

    /** Rebuilds the local workspace at [name]; writes then belong to that bookmark's line. */
    suspend fun follow(name: String): TipStatus = TipStatus.decode(call("follow") { put("name", name) })

    /** Releases local frames of an unfollowed tip when no retained evidence depends on them. */
    suspend fun drop(tip: String): TipStatus = TipStatus.decode(call("drop") { put("tip", tip) })

    /**
     * The owner grants [identity] trust for this domain: it opens tips and moves bookmarks backward or sideways.
     * Hand [TrustGrant.grant] to a device of that identity for [installTrust].
     */
    suspend fun trust(identity: String): TrustGrant = TrustGrant.decode(call("trust") { put("identity", identity) })

    /** Installs a trusted grant the owner issued to this device's identity. */
    suspend fun installTrust(grant: String): TipStatus = TipStatus.decode(call("install_trust") { put("grant", grant) })

    /** The owner revokes a trusted grant by its [TrustGrant.capability]; the identity keeps its other grants. */
    suspend fun revokeTrust(capability: String) {
        client.call(request("revoke") { put("trust", capability) })
    }
}

/** The owner's trusted grant to [identity]: [grant] is opaque hex its device installs, [capability] what revocation names. */
data class TrustGrant(val identity: String, val capability: String, val grant: String) {
    internal companion object {
        fun decode(value: JsonObject) = TrustGrant(
            value.getValue("identity").jsonPrimitive.content,
            value.getValue("capability").jsonPrimitive.content,
            value.getValue("grant").jsonPrimitive.content,
        )
    }
}

/**
 * The seals a device keeps: the seal each bookmarked tip starts from ([bookmarked]), the [latest] so many, or
 * [every] one. Keeping the latest seal lets a device open a branch on it after writing on.
 */
data class KeptSeals(val bookmarked: Boolean = false, val latest: UInt = 0u, val every: Boolean = false) {
    internal companion object {
        fun decode(value: JsonObject) = KeptSeals(
            value.getValue("bookmarked").jsonPrimitive.boolean,
            value.unsigned("latest").toUInt(),
            value.getValue("every").jsonPrimitive.boolean,
        )
    }
}

/** A per-author sequence through which a device or seal has seen operations. */
data class TipAuthorMark(val author: UInt, val sequence: ULong)

/** Evidence below a seal that a future compaction could release; this call does not compact. */
data class TipEvidence(val operations: ULong, val bytes: ULong)

/** The last frontier this device has seen from a node. */
data class TipLogFrontier(val author: String, val held: ULong, val applied: ULong)

/** One resource scope, as its JSON encoding, and per-author log positions. */
data class TipScopeFrontier(val scope: String, val logs: List<TipLogFrontier>)
data class TipDeviceFrontier(val node: String, val tip: String?, val frontiers: List<TipScopeFrontier>)

data class TipStatus(
    val bookmark: String?,
    val tip: String,
    val operationsSinceSeal: ULong,
    val evidenceReleasable: TipEvidence?,
    val devices: List<TipDeviceFrontier>,
    val pendingFollow: String? = null,
) {
    internal companion object {
        fun decode(value: JsonObject) = TipStatus(
            value.nullableText("bookmark"),
            value.text("tip"),
            value.unsigned("operations_since_seal"),
            (value.getValue("evidence_releasable") as? JsonObject)?.let { TipEvidence(it.unsigned("operations"), it.unsigned("bytes")) },
            value.objects("devices").map { device ->
                TipDeviceFrontier(
                    device.text("node"),
                    device.nullableText("tip"),
                    device.objects("frontiers").map { frontier ->
                        TipScopeFrontier(
                            frontier.text("scope"),
                            frontier.objects("logs").map { TipLogFrontier(it.text("author"), it.unsigned("held"), it.unsigned("applied")) },
                        )
                    },
                )
            },
            value.nullableText("pending_follow"),
        )
    }
}

/** One resource scope, as its JSON encoding, and why it kept operations. */
data class TipPruneBlock(val scope: String, val reason: String)

/**
 * This device's compaction of the followed path: the newest [finalized] seal, the seal the base sits at, finalized
 * seals still [uncompacted], why the next seal [waiting] is not finalized, and a seal to [rebootstrap] at when the
 * compacted one lost a race. [pruned] and [blocked] report what a `compact` call released; status reports none.
 */
data class TipCompaction(
    val finalized: String?,
    val compacted: String?,
    val uncompacted: List<String>,
    val waiting: String?,
    val rebootstrap: String?,
    val pruned: ULong,
    val blocked: List<TipPruneBlock>,
) {
    internal companion object {
        fun decode(value: JsonObject) = TipCompaction(
            value.nullableText("finalized"),
            value.nullableText("compacted"),
            value.getValue("uncompacted").jsonArray.map { it.jsonPrimitive.content },
            value.nullableText("waiting"),
            value.nullableText("rebootstrap"),
            value.unsigned("pruned"),
            value.objects("blocked").map { TipPruneBlock(it.text("scope"), it.text("reason")) },
        )
    }
}

sealed interface TipSealAction {
    data class Continue(val schema: String) : TipSealAction
    data object Close : TipSealAction
}

/** Who signed a seal or move; races resolve to a final seal, then the owner, trusted, issuer, then the lower digest. */
enum class TipAuthority { OWNER, TRUSTED, ISSUER }

/**
 * A seal; [canonical] is false for a concurrent seal of the same tip that lost.
 * A [revoked] seal's signer was revoked; it takes part in no race. A [final] seal was committed by its tip's
 * coordinated log and acknowledged by enough trusted nodes; it beats every other seal of its tip. [checkpoints]
 * lists the checkpoints of its state a device may rebootstrap from. [held] says how this device holds its state,
 * which a branch opening needs; null when it is shallow here. [recovery] is set on the owner's recovery of a stuck tip.
 */
data class TipSeal(
    val id: String,
    val tip: String,
    val frontier: List<TipAuthorMark>,
    val action: TipSealAction,
    val canonical: Boolean,
    val authority: TipAuthority,
    val revoked: Boolean,
    val final: Boolean,
    val checkpoints: List<TipCheckpoint>,
    val held: TipHeld? = null,
    val recovery: TipRecovery? = null,
)

/** The owner's recovery: it abandons the committed entries of its tip's log after [retained] through [replaced]. */
data class TipRecovery(val retained: ULong, val replaced: ULong)

/** How a device holds a seal's state: [KEPT] in history tables, a [CHECKPOINT] base there, or its [LIVE] tables now. */
enum class TipHeld { KEPT, CHECKPOINT, LIVE }

/**
 * A checkpoint of one [scope] at a seal, signed by the node [signer] and listed by [authority]; [rows] is its size.
 * Its body moves only when a device asks for it.
 */
data class TipCheckpoint(
    val id: String,
    val scope: String,
    val checkpoint: String,
    val signer: String,
    val authority: TipAuthority,
    val rows: ULong,
)
data class TipOpening(val id: String, val seal: String, val schema: String, val minimumInSync: UInt)
data class BookmarkMove(val id: String, val from: String?, val to: String?, val authority: TipAuthority, val revoked: Boolean)

/** A move that lost a race along its bookmark's path, named `main/1`, `main/2`; its tip stays a branch. */
data class LosingMove(val name: String, val move: String, val tip: String?)
data class TipBookmark(val name: String, val tip: String?, val moves: List<BookmarkMove>, val losers: List<LosingMove>)
data class TipNode(val node: String, val followedTip: String?, val keptTips: List<String>?, val keptSeals: List<String>?)

/** The complete verified graph and locally known node holdings, for developer inspection. */
data class TipInspection(
    val scope: String,
    val genesis: String,
    val schema: String,
    /** Trusted acknowledgments that make a genesis-line seal final; null until the owner signs one. */
    val genesisMinimum: UInt?,
    val seals: List<TipSeal>,
    val openings: List<TipOpening>,
    val bookmarks: List<TipBookmark>,
    val nodes: List<TipNode>,
) {
    internal companion object {
        fun decode(value: JsonObject) = TipInspection(
            value.text("scope"),
            value.text("genesis"),
            value.text("schema"),
            value.getValue("genesis_minimum").jsonPrimitive.contentOrNull?.toUInt(),
            value.objects("seals").map {
                TipSeal(
                    it.text("id"),
                    it.text("tip"),
                    it.frontier(),
                    when (val action = it.text("action")) {
                        "continue" -> TipSealAction.Continue(it.text("schema"))
                        "close" -> TipSealAction.Close
                        else -> throw IllegalArgumentException("unknown tip seal action $action")
                    },
                    it.getValue("canonical").jsonPrimitive.boolean,
                    it.authority(),
                    it.getValue("revoked").jsonPrimitive.boolean,
                    it.getValue("final").jsonPrimitive.boolean,
                    it.objects("checkpoints").map { checkpoint ->
                        TipCheckpoint(
                            checkpoint.text("id"),
                            checkpoint.text("scope"),
                            checkpoint.text("checkpoint"),
                            checkpoint.text("signer"),
                            checkpoint.authority(),
                            checkpoint.unsigned("rows"),
                        )
                    },
                    it.nullableText("held")?.let { held -> TipHeld.valueOf(held.uppercase()) },
                    (it["recovery"] as? JsonObject)?.let { recovery ->
                        TipRecovery(recovery.unsigned("retained"), recovery.unsigned("replaced"))
                    },
                )
            },
            value.objects("openings").map { TipOpening(it.text("id"), it.text("seal"), it.text("schema"), it.text("minimum_in_sync").toUInt()) },
            value.objects("bookmarks").map {
                TipBookmark(
                    it.text("name"),
                    it.nullableText("tip"),
                    it.objects("moves").map { move ->
                        BookmarkMove(
                            move.text("id"),
                            move.nullableText("from"),
                            move.nullableText("to"),
                            move.authority(),
                            move.getValue("revoked").jsonPrimitive.boolean,
                        )
                    },
                    it.objects("losers").map { loser -> LosingMove(loser.text("name"), loser.text("move"), loser.nullableText("tip")) },
                )
            },
            value.objects("nodes").map { TipNode(it.text("node"), it.nullableText("followed_tip"), it.nullableStrings("kept_tips"), it.nullableStrings("kept_seals")) },
        )
    }
}

private fun JsonObject.text(name: String): String = getValue(name).jsonPrimitive.content
private fun JsonObject.nullableText(name: String): String? = getValue(name).jsonPrimitive.contentOrNull
private fun JsonObject.unsigned(name: String): ULong = text(name).toULong()
private fun JsonObject.objects(name: String): List<JsonObject> = getValue(name).jsonArray.map { it.jsonObject }
private fun JsonObject.nullableStrings(name: String): List<String>? = (getValue(name) as? JsonArray)?.map { it.jsonPrimitive.content }
private fun JsonObject.authority(): TipAuthority = when (val authority = text("authority")) {
    "owner" -> TipAuthority.OWNER
    "trusted" -> TipAuthority.TRUSTED
    "issuer" -> TipAuthority.ISSUER
    else -> throw IllegalArgumentException("unknown tip authority $authority")
}
private fun JsonObject.frontier(): List<TipAuthorMark> = objects("frontier").map { TipAuthorMark(it.text("author").toUInt(), it.unsigned("sequence")) }
