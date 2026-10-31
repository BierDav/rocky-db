package consumer

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlinx.serialization.json.*
import rocky.*
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

private val schema = schema("packaged") {
    table("items") {
        text("title")
        primaryKey("id")
    }
}
private val table = schema.table("items")
private fun handle(n: Int) = n.toString(16).padStart(64, '0')
private suspend fun titles(port: RuntimePort) = Row.decode(port.read(table.query())).map { it.text("title") }

/** Credential primitives and a delegated credentials, using only the packaged library. */
private suspend fun credentialPrimitives(root: File) {
    val issuer = RockyDatabase.local(File(root, "issuer"), schema)
    var executor: RockyDatabase? = null
    var delegate: RockyDatabase? = null
    try {
        val keys = Credentials.prepare(File(root, "executor"))
        val all = listOf(Grant("items", setOf(Right.Read, Right.Insert, Right.Update, Right.Delete, Right.Custody)))
        val x = RockyDatabase.install(
            File(root, "executor"),
            schema,
            issuer.credentials.grant(keys, all, delegations = 2, authors = 2),
        ).also { executor = it }
        check(!x.isIssuer)
        val delegated = Credentials.prepare(File(root, "delegate"))
        val writes = listOf(Grant("items", setOf(Right.Read, Right.Insert, Right.Custody)))
        val d = RockyDatabase.install(
            File(root, "delegate"),
            schema,
            x.credentials.delegate(delegated, writes, authors = 1),
        ).also { delegate = it }
        check(!d.isIssuer)
        // The principal keeps 2 for this node and delegates 3.
        d.write {
            val id = nextId("items")
            check(id ushr 32 == 3L)
            execute("INSERT INTO items(id,title) VALUES(?, 'delegated')", id)
        }
    } finally {
        delegate?.close()
        executor?.close()
        issuer.close()
    }
}

/** The shopping schema's group, title policy and references, declared and installed from the packaged library. */
private suspend fun groupedLists(root: File) {
    val shopping = schema("shopping", version = 3) {
        table("lists") {
            text("title")
            primaryKey("id")
            partitionBy("id", group = "list")
        }
        table("categories") {
            integer("list")
            text("name")
            primaryKey("list", "id")
            partitionBy("list", group = "list")
            reference("list", "lists", onDelete = Delete.Cascade)
        }
        table("items") {
            integer("list")
            text("key")
            text("title")
            integer("category", nullable = true)
            primaryKey("list", "key")
            partitionBy("list", group = "list")
            unique("list", "title")
            reference("list", "lists", onDelete = Delete.Cascade)
            reference(listOf("list", "category"), "categories", onDelete = Delete.SetNull)
        }
    }
    val db = RockyDatabase.local(root, shopping)
    try {
        val list = db.partitions.next("lists").getValue("id").jsonPrimitive.content.toLong()
        val category = db.write {
            check(nextId("lists") == list)
            execute("INSERT INTO lists(id, title) VALUES(?, ?)", list, "Groceries")
            nextId("categories", list).also { execute("INSERT INTO categories(id, list, name) VALUES(?, ?, ?)", it, list, "Dairy") }
        }
        db.write { execute("INSERT INTO items(id, list, key, title, category) VALUES(?, ?, ?, ?, ?)", nextId("items", list), list, "k1", "Milk", category) }
        check(runCatching { db.write { execute("INSERT INTO items(id, list, key, title) VALUES(?, ?, ?, ?)", nextId("items", list), list, "k2", "Milk") } }.isFailure)
        db.write { execute("DELETE FROM categories WHERE list = ? AND id = ?", list, category) }
        val items = Row.decode(
            db.read(
                query(
                    "SELECT id, title, category FROM items WHERE list = ?",
                    JsonArray(
                        listOf(
                            buildJsonObject {
                                put("type", "integer")
                                put("value", list.toString())
                            },
                        ),
                    ),
                ),
            ),
        )
        check(items.single().isNull("category") && items.single().text("title") == "Milk")
    } finally {
        db.close()
    }
}

/** Runs with only this consumer, packaged jars and a JVM: no repository, native paths or build tools. */
fun main(args: Array<String>) = runBlocking {
    val root = File(args.single()).also { it.mkdirs() }
    val directory = File(root, "database")
    var db = RockyDatabase.local(directory, schema)
    // The application defines the bookmark it follows; Rocky defines none.
    db.tips.createBookmark("main")
    db.tips.follow("main")
    check(db.network().attachment == rocky.AttachmentState.Detached)
    val a = db.openSession()
    val b = db.openSession()
    val node = a.credentials.status().node
    check(a.credentials.status().isIssuer)
    val initial = a.observeStatus().first()
    val revision = initial.data.revision
    val changed = async(start = CoroutineStart.UNDISPATCHED) {
        a.observeStatus().first { it.data.revision > revision }
    }
    // The issuer assigns its own author; inserts are signed under it.
    val action = handle(1)
    suspend fun apples() = b.write(action) { execute("INSERT INTO items(id, title) VALUES(?, ?)", nextId("items"), "apples") }
    apples()
    check(withTimeout(5000) { changed.await() }.data.revision > revision)
    // Lost foreign acknowledgment: reconcile the handle rather than writing again. Another transaction under it is refused.
    check(b.reconcile(action).getValue("committed").jsonPrimitive.boolean)
    check(runCatching { apples() }.exceptionOrNull() is RockyException)
    check(titles(b) == listOf("apples"))
    val waiting = async(start = CoroutineStart.UNDISPATCHED) { a.observeStatus().first { false } }
    waiting.cancelAndJoin()
    a.close()
    check(titles(b) == listOf("apples"))
    val endpoint = RockyEndpoint.bind(ByteArray(32) { 42 }, relay = "disabled", lookup = "disabled", bind = "127.0.0.1:0")
    val attached = db.attach(PeerTransport.Endpoint(endpoint))
    check(db.network().attachment == rocky.AttachmentState.Attached && db.network().ownership == rocky.NetworkOwnership.Application)
    attached.close()
    check(db.network().attachment == rocky.AttachmentState.Detached)
    check(endpoint.address().isNotEmpty())
    val owned = db.attach(PeerTransport.Iroh.isolated())
    // An issuer backup includes the registry projection, so restore with issuer read grants.
    val invitation = db.credentials.pairing(GrantProfile.Issuer)
    val archive = File(root, "device.backup")
    db.backup(archive)
    val restored = RockyDatabase.restore(
        File(root, "restored"),
        schema,
        archive,
        invitation.uri,
        PeerTransport.Iroh.isolated(),
    )
    check(restored.credentials.status().node != db.credentials.status().node)
    check(restored.credentials.status().isIssuer)
    check(titles(restored) == listOf("apples"))
    restored.close()
    owned.close()
    db.close()
    check(endpoint.address().isNotEmpty())
    endpoint.shutdown()
    // Reopen under the same identity and upgrade additively without reauthoring the action.
    val upgraded = schema.copy(version = 2, tables = listOf(Table("items", listOf(Column.text("title"), Column.text("note", nullable = true)), primaryKey = listOf("id"))))
    db = RockyDatabase.open(directory, upgraded)
    check(db.credentials.status().node == node)
    check(db.generation().current.schema == 2u)
    check(titles(db) == listOf("apples"))
    check(Row.decode(db.read(upgraded.table("items").query())).single().isNull("note"))
    check(db.reconcile(action).getValue("committed").jsonPrimitive.boolean)
    db.close()
    db = RockyDatabase.open(directory, upgraded)
    check(db.credentials.status().node == node)
    check(Row.decode(db.read(upgraded.table("items").query())).single().isNull("note"))
    check(db.reconcile(action).getValue("committed").jsonPrimitive.boolean)
    db.close()
    // Cancellation during native construction still closes the admitted database and leaves it reopenable.
    val began = CountDownLatch(1)
    val proceed = CountDownLatch(1)
    val firstStore = AtomicBoolean(true)
    val keys = ConcurrentHashMap<String, ByteArray>()
    val store = object : SecretStore {
        override fun load(name: String): ByteArray? = keys[name]
        override fun store(name: String, secret: ByteArray) {
            if (firstStore.compareAndSet(true, false)) {
                began.countDown()
                proceed.await()
            }
            keys[name] = secret
        }
        override fun delete(name: String) {
            keys.remove(name)
        }
    }
    val cancelledDirectory = File(root, "cancelled-open")
    val opening = launch { RockyDatabase.local(cancelledDirectory, schema, secrets = store).close() }
    withContext(Dispatchers.IO) { check(began.await(10, java.util.concurrent.TimeUnit.SECONDS)) }
    opening.cancel()
    proceed.countDown()
    withTimeout(10000) { opening.join() }
    check(opening.isCancelled)
    val reopened = RockyDatabase.open(cancelledDirectory, schema, secrets = store)
    check(reopened.credentials.status().isIssuer)
    reopened.close()
    credentialPrimitives(File(root, "primitives"))
    groupedLists(File(root, "lists"))
    println("Packaged consumer passed: grouped partitioned constraints, credential primitives, delegated credentials, local sessions, authority/progress Flow, reconciliation, owned/borrowed networks, fresh restore and generation reopen")
}
