package org.example.examples.shopping.data.db

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import rocky.RockyDatabase
import rocky.Row
import rocky.SchemaBuilder

/**
 * Tables only trusted devices read: device names and kinds, each trusted device's open pairing code, and the
 * household's coordination tenant. Members hold no grant on them. Room declares none of them, and the application never queries them on members.
 */
val trustedTables: SchemaBuilder.() -> Unit = {
    table("devices") {
        text("node")
        text("name")
        text("kind")
        primaryKey("node")
    }
    table("invitations") {
        text("issuer")
        text("kind")
        text("name")
        text("code")
        integer("expires")
        primaryKey("issuer")
    }
    table("coordination") {
        text("key")
        blob("tenant")
        text("registration")
        integer("revision")
        text("control")
        text("members")
        integer("expires")
        boolean("applied")
        primaryKey("key")
    }
}

/** Trusted-only description, also carried by the registry label. */
data class DeviceRow(val node: String, val name: String, val kind: String)

/** The open pairing [code] of the trusted device [issuer]: Rocky keeps one per issuer, used once until [expires]. */
data class InvitationRow(val issuer: String, val kind: String, val name: String, val code: String, val expires: Long)

/**
 * The household's domain on the coordination service: the [tenant] key that controls it, its [registration] and
 * the control [revision] for [members]. [control] is the id of that revision's request, [applied] once accepted.
 */
class CoordinationRow(
    val tenant: ByteArray,
    val registration: String,
    val revision: Long,
    val control: String,
    val members: String,
    val expires: Long,
    val applied: Boolean,
)

/** Reads and writes the [trustedTables] through Rocky's own API, on trusted devices only. */
internal class TrustedRows(private val rocky: RockyDatabase) {
    fun devices(): Flow<List<DeviceRow>> = rows("devices").map { rows ->
        rows.map { DeviceRow(it.text("node"), it.text("name"), it.text("kind")) }
    }

    suspend fun record(node: String, name: String, kind: String) = write {
        if (execute("UPDATE devices SET name = ?, kind = ? WHERE node = ?", name, kind, node) == 0L) {
            execute("INSERT INTO devices(id, node, name, kind) VALUES(?, ?, ?, ?)", nextId("devices"), node, name, kind)
        }
    }

    suspend fun forget(node: String) = write { execute("DELETE FROM devices WHERE node = ?", node) }

    fun invitations(): Flow<List<InvitationRow>> = rows("invitations").map { rows ->
        rows.map { InvitationRow(it.text("issuer"), it.text("kind"), it.text("name"), it.text("code"), it.integer("expires")) }
    }

    /** Records [issuer]'s new invitation, which replaced its previous one. */
    suspend fun openInvitation(issuer: String, kind: String, name: String, code: String, expires: Long) = write {
        if (execute("UPDATE invitations SET kind = ?, name = ?, code = ?, expires = ? WHERE issuer = ?", kind, name, code, expires, issuer) == 0L) {
            execute(
                "INSERT INTO invitations(id, issuer, kind, name, code, expires) VALUES(?, ?, ?, ?, ?, ?)",
                nextId("invitations"),
                issuer,
                kind,
                name,
                code,
                expires,
            )
        }
    }
    suspend fun closeInvitation(issuer: String, code: String) = write { execute("DELETE FROM invitations WHERE issuer = ? AND code = ?", issuer, code) }

    fun coordination(): Flow<CoordinationRow?> = rows("coordination").map { rows ->
        rows.firstOrNull()?.let {
            CoordinationRow(
                it.blob("tenant"),
                it.text("registration"),
                it.integer("revision"),
                it.text("control"),
                it.text("members"),
                it.integer("expires"),
                it.boolean("applied"),
            )
        }
    }

    /** On the founding device only: the first revision, whose members are named once there are any. */
    suspend fun startCoordination(tenant: ByteArray, registration: String) = write {
        execute(
            "INSERT INTO coordination(id, key, tenant, registration, revision, control, members, expires, applied) VALUES(?, 'household', ?, ?, 1, ?, '', 0, 0)",
            nextId("coordination"),
            tenant,
            registration,
            registration,
        )
    }
    suspend fun replaceCoordination(expected: rocky.CoordinationRegistration, replacement: rocky.CoordinationRegistration): Boolean {
        val session = rocky.openSession()
        return try {
            session.write {
                execute(
                    "UPDATE coordination SET revision = ?, control = ?, members = ?, expires = ?, applied = ? WHERE key = 'household' AND revision = ? AND control = ? AND members = ? AND expires = ? AND applied = ?",
                    replacement.revision, replacement.control, replacement.members.sorted().joinToString(","), replacement.expiresAtEpochSeconds, replacement.applied,
                    expected.revision, expected.control, expected.members.sorted().joinToString(","), expected.expiresAtEpochSeconds, expected.applied,
                ) == 1L
            }
        } finally {
            session.close()
        }
    }

    private fun rows(table: String): Flow<List<Row>> = rocky.observe(ShoppingSchema.table(table).query()).map(Row::decode)
    private suspend fun write(block: suspend rocky.SqlWrite.() -> Unit) {
        val session = rocky.openSession()
        try {
            session.write(RockyDatabase.newHandle(), block)
        } finally {
            session.close()
        }
    }
}
