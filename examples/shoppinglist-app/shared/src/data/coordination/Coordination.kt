package org.example.examples.shopping.data.coordination

import kotlinx.coroutines.flow.*
import kotlinx.serialization.json.*
import org.example.examples.shopping.data.db.ShoppingDatabase
import org.example.examples.shopping.data.db.TrustedRows
import org.example.examples.shopping.data.household.Household
import org.example.examples.shopping.util.randomBytes
import rocky.*
import rocky.room.settledOnRocky

/** A request for approval as a device sees it. [requester] and [decider] are device names where known. */
data class Approval(val key: String, val title: String, val note: String, val requester: String, val approved: Boolean?, val decider: String?)

/** Where this device stands with the coordination service. */
sealed interface Coordinated {
    /** Opened without a coordinator, such as over direct TCP: decisions are unavailable. */
    data object Unavailable : Coordinated

    /** A trusted device waits for the household's tenant, or another device's identity, to sync. */
    data class Waiting(val reason: String) : Coordinated
    data class Registered(val revision: Long, val trusted: Int, val expiresAtEpochSeconds: Long) : Coordinated

    /** A member writes requests and reads committed decisions. */
    data object Member : Coordinated
    data class Failed(val message: String) : Coordinated
}

/**
 * Ordinary request and decision rows. Rocky orders no writes through the coordination service, so concurrent decisions
 * on different devices are not excluded; this device decides only a request it holds undecided.
 */
class Approvals internal constructor(
    private val database: ShoppingDatabase,
    private val rocky: RockyDatabase,
    private val household: Household,
    private val self: String,
    val coordinated: Boolean,
) {
    private val mutableStatus = MutableStateFlow<Coordinated>(
        if (!coordinated) {
            Coordinated.Unavailable
        } else if (rocky.isIssuer) {
            Coordinated.Waiting("Starting")
        } else {
            Coordinated.Member
        },
    )
    val status: StateFlow<Coordinated> = mutableStatus.asStateFlow()

    fun requests(): Flow<List<Approval>> {
        val devices = if (rocky.isIssuer) household.devices() else flowOf(emptyList())
        return combine(database.approvals().requests(), database.approvals().decisions(), devices) { requests, decisions, rows ->
            fun name(node: String): String = if (node == self) "This device" else rows.firstOrNull { it.node == node }?.name ?: "Another device"
            requests.map { request ->
                val decision = decisions.firstOrNull { it.key == request.key }
                Approval(request.key, request.title, request.note, name(request.requester), decision?.approved, decision?.let { name(it.decider) })
            }
        }.settledOnRocky()
    }

    /** Asking is an ordinary write, including while offline. */
    suspend fun ask(title: String, note: String): String? {
        require(title.isNotBlank())
        rocky.write {
            execute("INSERT INTO requests(key,title,note,requester,id) VALUES(?,?,?,?,?)", RockyDatabase.newHandle(), title.trim(), note.trim(), self, nextId("requests"))
        }
        return null
    }

    /** Decides a request this device holds undecided, as an ordinary write. */
    suspend fun decide(key: String, approve: Boolean): String? {
        check(coordinated && rocky.isIssuer) { "Only a trusted device with coordination may decide" }
        if (database.approvals().requests().first().none { it.key == key }) return "The request has not reached this device yet"
        val previous = database.approvals().decisions().first().firstOrNull { it.key == key }
        if (previous != null) return if (previous.approved) "Another device already approved it" else "Another device already declined it"
        rocky.write {
            execute("INSERT INTO decisions(key,approved,decider,id) VALUES(?,?,?,?)", key, approve, self, nextId("decisions"))
        }
        return null
    }

    /** Keeps the domain's trusted-node control registered until cancelled. */
    suspend fun run() {
        if (coordinated && rocky.isIssuer) register()
    }

    private suspend fun register() = rocky.maintainCoordination(
        store = object : CoordinationRegistrationStore {
            override fun observe(): Flow<CoordinationRegistration?> = household.trusted.coordination().map { row ->
                row?.let {
                    CoordinationRegistration(it.tenant, it.registration, it.revision, it.control, it.members.split(",").filter(String::isNotEmpty).toSet(), it.expires, it.applied)
                }
            }.settledOnRocky()
            override suspend fun compareAndSet(expected: CoordinationRegistration, replacement: CoordinationRegistration): Boolean = household.trusted.replaceCoordination(expected, replacement)
        },
        members = household.registry().map { devices ->
            (devices.filter { !it.revoked && it.profile == GrantProfile.Issuer }.map { it.user } + rocky.session().principal).toSet()
        },
        onState = { state ->
            mutableStatus.value = when (state) {
                CoordinationAvailability.WaitingForRegistration -> Coordinated.Waiting("Waiting for the household's coordination key to sync")
                is CoordinationAvailability.Registered -> Coordinated.Registered(state.revision, state.members, state.expiresAtEpochSeconds)
                is CoordinationAvailability.Failed -> Coordinated.Failed("Coordination service: ${state.cause.message}")
            }
        },
    )

    companion object {
        /** On the founding device only: the household's tenant key and registration, applied once online. */
        internal suspend fun start(trusted: TrustedRows) = trusted.startCoordination(randomBytes(32), RockyDatabase.newHandle())
    }
}
