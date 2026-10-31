package rocky

import kotlinx.coroutines.flow.Flow
import kotlinx.serialization.json.JsonObject

/** A write is durably committed before this port acknowledges it. */
interface RuntimePort {
    val domain: String
    fun observe(query: JsonObject): Flow<JsonObject>
    suspend fun read(query: JsonObject): JsonObject

    /**
     * Runs `block` as one SQL transaction committed under `handle`; a failure rolls it back. Persist `handle` first;
     * after uncertainty, reconcile it instead of writing again: another transaction under a committed handle is refused.
     * Inserts need this device's author for the table.
     */
    suspend fun <T> write(handle: String = newMutationHandle(), block: suspend SqlWrite.() -> T): T
}

/**
 * Statements of one open transaction. Values are `null`, `Boolean`, `Int`, `Long`, `Double`, `String` or `ByteArray`.
 *
 * The transaction replicates as an intent: its statements with their bound values, which every replica replays in
 * one canonical order. A value read and computed in application code is frozen when bound (read-modify-write), so
 * write `SET n = n + ?` when the result must follow concurrent writes. Replay refuses clock and random functions:
 * bind timestamps, such as `updated_at`, as values. A replica drops the whole transaction when its replay fails a
 * unique index, reference, `CHECK` or [Assertion] (`constraint`), a grant (`admission`), the current schema
 * (`schema`) or the engine (`engine`); the local commit stays visible until then, and
 * [RockyDatabase.transactionOutcome] reports it. Ids of new rows come from [nextId]; a row never changes its
 * partition columns, so a move deletes it and inserts it, with a new id, in the target partition.
 */
interface SqlWrite {
    /** A Rocky-issued `id` for a new row of `table`, signed under this device's author. */
    suspend fun nextId(table: String): Long

    /** Partition values follow partitionBy order; the adapter must implement this boundary. */
    suspend fun nextId(table: String, vararg partitionValues: Any?): Long {
        require(partitionValues.isEmpty()) { "this runtime port does not support partitioned ids" }
        return nextId(table)
    }

    /** Runs one statement and returns how many rows it changed. */
    suspend fun execute(sql: String, vararg values: Any?): Long
}

/** A single-use `rocky://join/…` URI. It carries the issuer's routes, the invitation secret and the profile it grants. */
data class PairingInvitation(val uri: String, val expiresAtEpochSeconds: Long, val profile: GrantProfile, val sequence: Long, val id: String)

/** A right a raw grant names on one table. */
enum class Right(val wire: String) {
    Read("read"),
    Insert("insert"),
    Update("update"),
    Delete("delete"),
    Custody("custody"),
    ;

    companion object {
        fun of(wire: String): Right = entries.firstOrNull { it.wire == wire } ?: throw IllegalStateException("unknown right $wire")
    }
}

/** Rights over one table, limited to `columns` when given. Custody grants no read access. */
data class Grant(val table: String, val rights: Set<Right>, val columns: Set<String>? = null)

/**
 * What a device may do. There is no default: the issuer names one. `Grants` is the primitive;
 * reader, writer and issuer are the optional starter layer built on it.
 */
sealed interface GrantProfile {
    /** Holds encrypted frames of the named tables without reader keys. */
    data class Custody(val tables: Set<String>) : GrantProfile

    /** Reads, and holds the keys of, the named tables. */
    data class Reader(val tables: Set<String>) : GrantProfile

    /** Reads and writes the named tables. */
    data class Writer(val tables: Set<String>) : GrantProfile

    /** Writes every table and holds the domain's publisher key: it invites, renews and revokes devices, other issuers included. */
    object Issuer : GrantProfile

    /** Exactly these raw grants. */
    data class Grants(val grants: List<Grant>) : GrantProfile
}

/**
 * How devices reach each other. Sessions are authenticated and encrypted above every transport,
 * and a domain is bound to none: a device may come back on another one and learn new routes.
 */
sealed interface PeerTransport {
    /**
     * The starter's own iroh endpoint. `relay` is `default`, `staging`, `disabled` or a relay URL. `lookup` is where
     * endpoint addresses are published and resolved: `default` (n0's DNS service), `disabled` or a pkarr relay URL.
     * `topic` finds domain members through a rendezvous record on the lookup service, `local` on the local network
     * over mDNS. Disabling `local` also disables multicast gateway discovery.
     * See `docs/runtime/sdk-transports.md#discovery`.
     */
    data class Iroh(
        val relay: String = "default",
        val lookup: String = "default",
        val topic: Boolean = true,
        val local: Boolean = true,
        val bind: String? = null,
    ) : PeerTransport {
        companion object {
            /** No relay, lookup service or discovery: peers are reached at their contacts' addresses only. */
            fun isolated(bind: String = "127.0.0.1:0") = Iroh("disabled", "disabled", topic = false, local = false, bind = bind)
        }
    }

    /** An endpoint the application owns, which also serves its own protocols. Closing the database leaves it open. */
    class Endpoint(val endpoint: AppEndpoint) : PeerTransport
}

/** An application-owned endpoint backed by `RockyEndpoint`. */
interface AppEndpoint

/** One reliable ordered byte stream, as chunks. Implementations must not fail `close`. */
interface ByteStream {
    /** The next bytes, at most `max`. Empty once the peer finished. */
    suspend fun read(max: Int): ByteArray

    /** Delivers `bytes` in order; returns once they are accepted. */
    suspend fun write(bytes: ByteArray)

    /** No more writes follow: the peer's `read` ends after what was sent. */
    suspend fun finish()

    /** Abandons the stream; a pending `read` ends. */
    suspend fun close()
}

/** A `rocky://peer/…` URI naming this device and its current route. It grants nothing. */
data class Contact(val uri: String, val node: String, val routes: List<Route>)

/** Platform storage for an installation's keys, such as a keychain. Names use only `[a-z0-9._-]`. */
interface SecretStore {
    fun load(name: String): ByteArray?
    fun store(name: String, secret: ByteArray)
    fun delete(name: String)
}

/** What an identity signs; a provider may show it to its user or refuse it. */
enum class IdentityPurpose(internal val wire: String) {
    NodeCertificate("node_certificate"),
    Capability("capability"),
    Revocation("revocation"),
    Statement("statement"),
}

/**
 * The identity that holds a database's permissions, such as a passkey's: every node of it signs under a certificate
 * the identity signed. It returns its 32-byte public key and 64-byte Ed25519 signatures and never the private key;
 * [reserveAuthor] hands each author number of `first..last` out once. See `docs/runtime/sdk-enrollment.md#identities`.
 */
interface IdentityProvider {
    fun publicKey(): ByteArray
    fun sign(purpose: IdentityPurpose, message: ByteArray): ByteArray
    fun reserveAuthor(first: Int, last: Int): Int
}

/** The authority this device holds. Keys are lowercase hex; `expiresAtEpochSeconds` ends its credentials. `transport` is the attached network's kind. */
data class SessionStatus(val principal: String, val node: String, val revocations: RevocationStatus, val expiresAtEpochSeconds: Long, val isIssuer: Boolean, val profile: GrantProfile, val transport: String)

/**
 * Another device's record in the replicated issuer registry, which every issuer reads: the profile its grants amount
 * to (empty grants when only partition grants are known), when its latest chain expires and an
 * opaque application [label] of at most 256 bytes.
 */
data class Device(
    val node: String,
    val user: String,
    val enrolledAtEpochSeconds: Long,
    val revoked: Boolean,
    val profile: GrantProfile,
    val expiresAtEpochSeconds: Long? = null,
    val label: ByteArray? = null,
    val invitationId: String? = null,
)

/** Unique operation identity, not a credential. Persist it with the queued action. */
fun newMutationHandle(): String = kotlin.random.Random.Default.nextBytes(32)
    .joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
