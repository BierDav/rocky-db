@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package rocky.binding

import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.locks.ReentrantLock
import kotlinx.atomicfu.locks.withLock
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.*
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import platform.posix.pthread_self
import rocky.internal.native.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BindingSpikeTest {
    @Test
    fun rustThreadCallbacksEnrollOverLoopbackIroh() = runBlocking {
        withTimeout(30_000) {
            val root = NSTemporaryDirectory() + "rocky-binding-" + NSUUID().UUIDString
            val caller = pthread_self()
            val secrets = Secrets { pthread_self() == caller }
            val ownerNetwork = NativeNetwork.starter(LOOPBACK)
            val memberNetwork = NativeNetwork.starter(LOOPBACK)
            val owner = NativeDatabase.create("$root/owner", SCHEMA, secrets, ownerNetwork, null, null)
            val session = owner.session()
            var member: NativeDatabase? = null
            try {
                val status = call(owner, session, buildJsonObject { put("type", "session") })
                assertTrue(status.getValue("node").jsonPrimitive.content.isNotEmpty())
                assertTrue(secrets.rustThreadCalls.value > 0)
                val pairing = call(owner, session, buildJsonObject {
                    put("type", "pairing")
                    put("profile", buildJsonObject {
                        put("kind", "writer")
                        put("scopes", JsonArray(listOf(JsonPrimitive("items"))))
                    })
                })
                member = NativeDatabase.join("$root/member", SCHEMA, pairing.getValue("uri").jsonPrimitive.content, memberNetwork, null, null)
                assertEquals(owner.scope(), member.scope())
            } finally {
                member?.let { it.shutdown(); it.destroy() }
                session.shutdown()
                session.destroy()
                owner.shutdown()
                owner.destroy()
                ownerNetwork.destroy()
                memberNetwork.destroy()
                NSFileManager.defaultManager.removeItemAtPath(root, null)
            }
        }
    }
}

private suspend fun call(database: NativeDatabase, session: NativeDatabaseSession, request: JsonObject): JsonObject {
    val frame = buildJsonObject {
        put("version", 1)
        put("scope", Json.parseToJsonElement(database.scope()))
        put("request", request)
    }
    val reply = Json.parseToJsonElement(session.call(frame.toString())).jsonObject
    assertEquals("ok", reply.getValue("status").jsonPrimitive.content, reply.toString())
    return reply.getValue("value").jsonObject
}

private class Secrets(private val onCallerThread: () -> Boolean) : NativeSecretStore {
    private val lock = ReentrantLock()
    private val values = mutableMapOf<String, ByteArray>()
    val rustThreadCalls = atomic(0)
    private fun called() {
        if (!onCallerThread()) rustThreadCalls.incrementAndGet()
    }
    override fun load(name: String): ByteArray? = lock.withLock {
        called()
        values[name]?.copyOf()
    }
    override fun store(name: String, secret: ByteArray) = lock.withLock {
        called()
        values[name] = secret.copyOf()
    }
    override fun delete(name: String) = lock.withLock {
        called()
        values.remove(name)
        Unit
    }
}

/** The starter's iroh on loopback: no relay, lookup or discovery. */
private const val LOOPBACK = """{"kind":"iroh","relay":"disabled","lookup":"disabled","topic":false,"local":false,"bind":"127.0.0.1:0"}"""
private const val SCHEMA = """{"application":"binding","version":1,"format":6,"tables":[{"name":"items","class":"replayed","columns":[{"name":"key","type":"text","not_null":true},{"name":"title","type":"text","not_null":true}],"primary_key":["key"]}]}"""
