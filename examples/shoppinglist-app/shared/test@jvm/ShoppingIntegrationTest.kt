package org.example.examples.shopping

import kotlinx.coroutines.*
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.*
import kotlinx.serialization.json.*
import org.example.examples.shopping.data.ShoppingRepository
import org.example.examples.shopping.data.db.ShoppingDatabase
import org.example.examples.shopping.data.db.ShoppingSchema
import org.example.examples.shopping.data.db.ShoppingTables
import org.example.examples.shopping.data.db.list
import org.example.examples.shopping.data.db.shoppingRoomOverlay
import org.example.examples.shopping.data.household.NodeKind
import rocky.*
import rocky.room.createRockyPartition
import rocky.room.followRocky
import java.io.File
import java.nio.file.Files
import kotlin.test.*

/** A table for enrollment, transport and sync tests that need no Room; rows are written with SQL. */
internal val ItemsSchema = schema("shopping") {
    table("items") {
        text("title")
        boolean("completed")
        primaryKey("id")
    }
}

/** Installs this device's author for `table`, assigned by [issuer]; inserts need it. */
internal suspend fun RuntimePort.insertItem(title: String) = write { execute("INSERT INTO items(id, title, completed) VALUES(?, ?, ?)", nextId("items"), title, false) }

class ShoppingIntegrationTest {
    private fun directory(): File = Files.createTempDirectory("rocky-room-test").toFile()

    /** Loopback iroh: no relay and no address lookup, so tests need no network. */
    private fun local(): PeerTransport = PeerTransport.Iroh.isolated()
    private fun loopback(): PeerTransport = PeerTransport.Iroh.isolated()
    private val items get() = ItemsSchema.table("items")
    private val writer = GrantProfile.Writer(setOf("items"))
    private suspend fun RockyDatabase.add(title: String) = insertItem(title)
    private suspend fun RockyDatabase.titles() = Row.decode(read(items.query())).map { it.text("title") }.sorted()

    @Test fun `a Kotlin protocol and Rocky share an endpoint the application owns`() = runBlocking {
        val root = directory()
        fun secret() = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val endpoint = RockyEndpoint.bind(
            secret(),
            relay = "disabled",
            lookup = "disabled",
            bind = "127.0.0.1:0",
            protocols = mapOf(
                "example/echo/1" to { _, stream ->
                    while (true) {
                        val chunk = stream.read(1024)
                        if (chunk.isEmpty()) break
                        stream.write(chunk)
                    }
                    stream.finish()
                },
            ),
        )
        val caller = RockyEndpoint.bind(secret(), relay = "disabled", lookup = "disabled", bind = "127.0.0.1:0")
        suspend fun echo(): String {
            val stream = caller.connect(endpoint.address(), "example/echo/1")
            try {
                stream.write("hello".toByteArray())
                stream.finish()
                var reply = ByteArray(0)
                while (true) {
                    val chunk = stream.read(1024)
                    if (chunk.isEmpty()) break
                    reply += chunk
                }
                return String(reply)
            } finally {
                stream.close()
            }
        }
        var a: RockyDatabase? = RockyDatabase.create(File(root, "a"), ItemsSchema, PeerTransport.Endpoint(endpoint), automaticSync = false)
        var b: RockyDatabase? = null
        try {
            b = RockyDatabase.join(File(root, "b"), ItemsSchema, a!!.pairing(writer).uri, local(), automaticSync = false)
            a.add("Milk")
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Milk"), b.titles())
            assertEquals("hello", echo())
            assertEquals(rocky.NetworkOwnership.Application, a.network().ownership)
            // Closing Rocky leaves the endpoint and the application's protocol running.
            a.close()
            a = null
            assertEquals("hello", echo())
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { it.outcome == rocky.AttemptOutcome.Failed } || peer.skip == rocky.SkipReason.Backoff })
            // The same endpoint, and so the same address, serves the database again.
            a = RockyDatabase.resume(File(root, "a"), ItemsSchema, PeerTransport.Endpoint(endpoint), automaticSync = false)
            a.add("Eggs")
            // The application signals renewed reachability; an explicit sync respects back-off.
            b.setNetworkingEnabled(true) // The reattached endpoint is a connectivity change; clear its back-off.
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Eggs", "Milk"), b.titles())
        } finally {
            b?.close()
            a?.close()
            // The final shutdown is the application's.
            endpoint.shutdown()
            caller.shutdown()
            root.deleteRecursively()
        }
    }

    @Test fun `a duplicate title drops one transaction and both devices report it`() = runBlocking {
        val unique = schema("shopping") {
            table("items") {
                text("title")
                boolean("completed")
                primaryKey("id")
                unique("title")
            }
        }
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), unique, loopback(), automaticSync = false)
        var b: RockyDatabase? = null
        try {
            b = RockyDatabase.join(File(root, "b"), unique, a.pairing(writer).uri, loopback(), automaticSync = false)
            // The device whose replay drops a transaction reports it.
            val drop = async(start = CoroutineStart.UNDISPATCHED) { withTimeout(20_000) { merge(a.drops(), b.drops()).first() } }
            a.insertItem("Bread")
            b.insertItem("Bread")
            repeat(2) { b.syncOnce() }
            assertEquals("constraint", drop.await().outcome.reason)
            for (database in listOf(a, b)) assertEquals(listOf("Bread"), Row.decode(database.read(unique.table("items").query())).map { it.text("title") })
        } finally {
            b?.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `members sync directly while the creator is closed`() = runBlocking {
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), ItemsSchema, loopback(), automaticSync = false)
        var b: RockyDatabase? = null
        var c: RockyDatabase? = null
        try {
            b = RockyDatabase.join(File(root, "b"), ItemsSchema, a.pairing(writer).uri, loopback(), automaticSync = false)
            c = RockyDatabase.join(File(root, "c"), ItemsSchema, a.pairing(writer).uri, loopback(), automaticSync = false)
            assertTrue(b.contact().uri.startsWith("rocky://peer/"))
            assertEquals(b.session().node, c.addPeer(b.contact().uri))
            // A device of the domain is served without being a contact: only the dialing side needs one.
            c.add("Eggs")
            a.close()
            assertTrue(c.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Eggs"), b.titles())
            assertFalse(b.peers().single { it.node == c.session().node }.isConfigured)
            b.addPeer(c.contact().uri)
            b.add("Milk")
            assertTrue(c.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Eggs", "Milk"), b.titles())
            assertEquals(b.titles(), c.titles())
            val peers = c.peers()
            assertTrue(peers.single { it.isIssuer }.attempts.any { it.outcome == rocky.AttemptOutcome.Failed })
            assertTrue(peers.single { !it.isIssuer }.attempts.any { it.operation == rocky.AttemptOperation.Reconcile && it.outcome == rocky.AttemptOutcome.Completed })
            assertEquals("iroh", peers.single { !it.isIssuer }.routes.single().transport)
            val network = c.network()
            assertEquals(rocky.AttachmentState.Attached, network.attachment)
            assertEquals(rocky.NetworkOwnership.Rocky, network.ownership)
            assertEquals("iroh", network.kind)
            assertEquals(32uL, network.inbound?.limit)
            b.removePeer(peers.single { it.isIssuer }.node)
            assertEquals(listOf(c.session().node), b.peers().map { it.node })
            assertFalse(b.observeStatus().first().authority.renewalRoutes.isNotEmpty())
            b.add("Bread")
            assertTrue(c.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Bread", "Eggs", "Milk"), c.titles())
            b.removePeer(c.session().node)
            assertTrue(b.peers().none { it.isConfigured })
        } finally {
            c?.close()
            b?.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `raw grants and delegation reach devices that are not issuers without Rust`() = runBlocking<Unit> {
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), ItemsSchema, loopback(), automaticSync = false)
        var s: RockyDatabase? = null
        var d: RockyDatabase? = null
        try {
            val inserts = listOf(Grant("items", setOf(Right.Read, Right.Insert, Right.Custody)))
            val readsTitles = listOf(Grant("items", setOf(Right.Read, Right.Custody), columns = setOf("title")))
            // The issuer grants raw rights, and one further delegation, to a device it prepared nothing for.
            val sKeys = Credentials.prepare(File(root, "s"))
            s = RockyDatabase.install(File(root, "s"), ItemsSchema, a.credentials.grant(sKeys, inserts, delegations = 2), transport = loopback())
            assertEquals(GrantProfile.Grants(inserts), s.session().profile)
            assertFalse(s.isIssuer)
            assertEquals(GrantProfile.Grants(inserts), a.devices().single().profile)
            // A delegate never receives more than its delegator holds.
            val dKeys = Credentials.prepare(File(root, "d"))
            assertFailsWith<RockyException> { s.credentials.delegate(dKeys, listOf(Grant("items", setOf(Right.Read, Right.Delete)))) }
            assertFailsWith<RockyException> { s.credentials.delegate(dKeys, inserts, delegations = 2) }
            d = RockyDatabase.install(File(root, "d"), ItemsSchema, s.credentials.delegate(dKeys, inserts), transport = loopback())
            assertEquals(GrantProfile.Grants(inserts), d.session().profile)
            assertFailsWith<RockyException> { d.credentials.delegate(Credentials.prepare(File(root, "e")), inserts) }
            for ((left, right) in listOf(a to s, a to d)) {
                left.addPeer(right.contact().uri)
                right.addPeer(left.contact().uri)
            }
            a.add("Milk")
            s.add("Eggs")
            d.add("Jam")
            assertTrue(s.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertTrue(d.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertTrue(s.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Eggs", "Jam", "Milk"), a.titles())
            assertEquals(a.titles(), d.titles())
            // A delegated chain is renewed by its delegator, here narrower: the delegate now only reads.
            assertFailsWith<RockyException> { d.renew() }
            val renewed = d.credentials.install(s.credentials.delegate(dKeys, readsTitles))
            assertEquals(GrantProfile.Grants(readsTitles), renewed.profile)
            assertFailsWith<RockyException> { d.add("Forged") }
        } finally {
            d?.close()
            s?.close()
            a.close()
            root.deleteRecursively()
        }
    }

    /** A full device: it edits lists it receives and reads the tables trusted devices write. */
    private val shopper = NodeKind.Full.profile
    private val checkout = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }.first { File(it, "project.yaml").isFile }

    @Test fun `the packaged schema is the current Room export's`() {
        val export = File(checkout, "shared/schemas/org.example.examples.shopping.data.db.ShoppingDatabase/8.json").readText()
        assertEquals(ShoppingSchema.definitionJson("09".repeat(32)), schemaFromRoom("shopping", export, shoppingRoomOverlay).definitionJson("09".repeat(32)))
        assertEquals(ShoppingSchema.json(), schemaFromRoom("shopping", export, shoppingRoomOverlay).json())
    }

    /** Shares [list] from [owner] with [reader] through one envelope, which the reader's next sync delivers. */
    private suspend fun share(owner: ShoppingRepository, reader: RockyDatabase, list: Long) {
        // A joined device finishes its own bootstrap before it starts a list from a checkpoint.
        assertTrue(reader.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
        owner.share(list, listOf(reader.session().node))
    }

    @Test fun `a list shares its categories and items and deleting a category hides only its links`() = runBlocking {
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), ShoppingSchema, local(), automaticSync = false)
        val da = openShoppingDatabase(File(root, "a"), a)
        val repository = ShoppingRepository(da, a)
        try {
            val list = repository.createList("Groceries")
            val other = repository.createList("Hardware")
            assertNotEquals(list, other)
            val dairy = repository.addCategory(list, "Dairy")
            val fresh = repository.addCategory(list, "Fresh")
            val milk = repository.add(list, "Milk", setOf(dairy, fresh))
            val eggs = repository.add(list, "Eggs")
            repository.categorize(list, eggs, dairy, member = true)
            repository.categorize(list, eggs, dairy, member = true)
            // Titles are unique per list, not across lists.
            assertFailsWith<Exception> { repository.add(list, "Milk") }
            repository.add(other, "Milk")
            // New items go last; placing one writes only its own key.
            assertEquals(listOf("Milk", "Eggs"), da.items().all(list).map { it.title })
            repository.place(list, da.items().all(list), eggs, 0)
            assertEquals(listOf("Eggs", "Milk"), da.items().all(list).map { it.title })
            fun links() = runBlocking { da.itemCategories().observe(list).first().map { it.item to it.category }.toSet() }
            assertEquals(setOf(milk to dairy, milk to fresh, eggs to dairy), links())

            // One call: one envelope per recipient covers the list's every table, and waits here for sync.
            val reader = Credentials.prepare(File(root, "reader")).getValue("node").jsonPrimitive.content
            repository.share(list, listOf(reader))
            assertEquals(listOf(reader to DeliveryState.Pending), repository.deliveries(list).map { it.node to it.state })
            val status = a.list(list).status()
            assertEquals(ShoppingTables.toSet(), status.tables.map { it.table }.toSet())
            assertTrue(status.tables.all { it.keyEpochs == status.epochs })

            repository.deleteCategory(list, dairy)
            val items = da.items().all(list)
            assertEquals(listOf(eggs, milk), items.map { it.id })
            assertEquals(setOf(milk to fresh), links())
            assertEquals(listOf("Fresh"), da.categories().all(list).map { it.name })

            repository.deleteList(list)
            assertTrue(da.items().all(list).isEmpty())
            assertEquals(listOf("Hardware"), da.lists().all().map { it.title })
            assertEquals(listOf("Milk"), da.items().all(other).map { it.title })
        } finally {
            da.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `a failed move preserves category links and a move deletes and inserts in one transaction`() = runBlocking {
        val root = directory()
        val rocky = RockyDatabase.create(File(root, "a"), ShoppingSchema, local(), automaticSync = false)
        val room = openShoppingDatabase(File(root, "a"), rocky)
        val repository = ShoppingRepository(room, rocky)
        try {
            val from = repository.createList("From")
            val to = repository.createList("To")
            val category = repository.addCategory(from, "Dairy")
            val item = repository.add(from, "Milk", setOf(category))
            assertFailsWith<Exception> { repository.move(from, item, Long.MAX_VALUE) }
            assertEquals(listOf(item), room.items().all(from).map { it.id })
            assertEquals(listOf(item to category), room.itemCategories().observe(from).first().map { it.item to it.category })
            val moved = assertNotNull(repository.move(from, item, to))
            assertNull(repository.move(from, item, to))
            assertTrue(room.items().all(from).isEmpty())
            assertEquals(listOf(moved to "Milk"), room.items().all(to).map { it.id to it.title })
            assertTrue(room.itemCategories().observe(from).first().isEmpty())
            assertTrue(room.itemCategories().observe(to).first().isEmpty())
        } finally {
            room.close()
            rocky.close()
            root.deleteRecursively()
        }
    }

    @Test fun `concurrent partition creation owns id preparation and callback failures roll back`() = runBlocking {
        val root = directory()
        val rocky = RockyDatabase.local(File(root, "a"), ShoppingSchema)
        val room = openShoppingDatabase(File(root, "a"), rocky)
        val repository = ShoppingRepository(room, rocky)
        try {
            val ids = kotlinx.coroutines.coroutineScope {
                (1..8).map { index -> async { repository.createList("List $index") } }.map { it.await() }
            }
            assertEquals(8, ids.toSet().size)
            assertEquals(ids.toSet(), room.lists().all().map { it.id }.toSet())
            var callbacks = 0
            assertFailsWith<IllegalStateException> {
                room.createRockyPartition(rocky, "lists") { id ->
                    callbacks++
                    room.lists().insert(org.example.examples.shopping.data.db.entity.ShoppingList(id, "Rolled back"))
                    error("application failure")
                }
            }
            assertEquals(1, callbacks)
            assertEquals(8, room.lists().all().size)
            repository.createList("After rollback")
            assertEquals(9, room.lists().all().size)
        } finally {
            room.close()
            rocky.close()
            root.deleteRecursively()
        }
    }

    @Test fun `offline DAO edits converge with conflicting fields and permanent deletion`() = runBlocking {
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), ShoppingSchema, local(), automaticSync = false)
        val da = openShoppingDatabase(File(root, "a"), a)
        val ra = ShoppingRepository(da, a)
        var b: RockyDatabase? = null
        var db: ShoppingDatabase? = null
        try {
            val invitation = a.pairing(shopper)
            assertTrue(invitation.uri.startsWith("rocky://join/"))
            b = RockyDatabase.join(File(root, "b"), ShoppingSchema, invitation.uri, local(), automaticSync = false)
            // Joining installed the authors its issuer assigned over the network.
            db = openShoppingDatabase(File(root, "b"), b)
            val rb = ShoppingRepository(db, b)
            val list = ra.createList("Groceries")
            share(ra, b, list)
            val id = ra.add(list, "Milk")
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(listOf("Groceries"), db.lists().all().map { it.title })
            assertEquals(listOf("Milk"), db.items().all(list).map { it.title })
            a.setNetworkingEnabled(false)
            b.setNetworkingEnabled(false)
            ra.rename(list, id, "Oat milk")
            rb.check(list, id, true)
            rb.add(list, "Eggs")
            assertEquals(2, db.items().all(list).size)
            assertEquals(rocky.SkipReason.NetworkingDisabled, b.syncOnce().skip)
            a.setNetworkingEnabled(true)
            b.setNetworkingEnabled(true)
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(da.items().all(list), db.items().all(list))
            assertEquals("Oat milk" to true, da.items().all(list).first { it.id == id }.let { it.title to it.completed })
            a.setNetworkingEnabled(false)
            ra.delete(list, id)
            rb.rename(list, id, "Late rename")
            a.setNetworkingEnabled(true)
            b.syncOnce()
            assertEquals(listOf("Eggs"), db.items().all(list).map { it.title })
            assertEquals(da.items().all(list), db.items().all(list))
        } finally {
            db?.close()
            b?.close()
            da.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `filtered DAO flows follow local and synced writes`() = runBlocking {
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), ShoppingSchema, loopback(), automaticSync = false)
        val da = openShoppingDatabase(File(root, "a"), a)
        var b: RockyDatabase? = null
        var db: ShoppingDatabase? = null
        var following: Job? = null
        try {
            b = RockyDatabase.join(File(root, "b"), ShoppingSchema, a.pairing(shopper).uri, loopback(), automaticSync = false)
            db = openShoppingDatabase(File(root, "b"), b)
            val repository = ShoppingRepository(db, b)
            val owner = ShoppingRepository(da, a)
            val list = owner.createList("Groceries")
            share(owner, b, list)
            following = launch(Dispatchers.IO) { db.followRocky(b) }
            val synced = async(Dispatchers.IO) { withTimeout(20_000) { repository.observe(list, "tea", false).first { it.isNotEmpty() } } }
            val id = owner.add(list, "Green Tea")
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(id, synced.await().single().id)
            val checked = async(Dispatchers.IO) { withTimeout(20_000) { repository.observe(list, "tea", false).first { it.isEmpty() } } }
            repository.check(list, id, true)
            checked.await()
            assertTrue(repository.observe(list).first().single().completed)
        } finally {
            following?.cancelAndJoin()
            db?.close()
            b?.close()
            da.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `native SDK supports independent tables and full width nullable integers`() = runBlocking {
        val root = directory()
        val schema = schema("stock") {
            table("products") {
                text("name")
                integer("quantity")
                text("note", nullable = true)
                primaryKey("id")
            }
            table("categories") {
                text("name")
                primaryKey("id")
            }
        }
        val products = schema.table("products")
        val categories = schema.table("categories")
        suspend fun RockyDatabase.category(name: String) = write { execute("INSERT INTO categories(id, name) VALUES(?, ?)", nextId("categories"), name) }
        val a = RockyDatabase.create(File(root, "a"), schema, local(), automaticSync = false)
        var b: RockyDatabase? = null
        try {
            a.write { execute("INSERT INTO products(id, name, quantity, note) VALUES(?, ?, ?, ?)", nextId("products"), "Coffee", Long.MAX_VALUE, null) }
            a.category("Drinks")
            val row = Row.decode(a.read(products.query())).single()
            assertEquals(Long.MAX_VALUE, row.integer("quantity"))
            assertTrue(row.isNull("note"))
            assertEquals("Drinks", Row.decode(a.read(categories.query())).single().text("name"))
            // A failed statement rolls its whole transaction back.
            assertFailsWith<RockyException> {
                a.write {
                    execute("INSERT INTO categories(id, name) VALUES(?, ?)", nextId("categories"), "Rolled back")
                    execute("INSERT INTO missing VALUES(1)")
                }
            }
            assertEquals(1, Row.decode(a.read(categories.query())).size)
            val invitation = a.pairing(GrantProfile.Writer(setOf("products")))
            assertFailsWith<Exception> { RockyDatabase.join(File(root, "wrong"), ItemsSchema, invitation.uri, local(), automaticSync = false) }
            b = RockyDatabase.join(File(root, "b"), schema, invitation.uri, local(), automaticSync = false)
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            // A scoped writer of products cannot write categories.
            assertFailsWith<RockyException> { b.category("Forged") }
            assertEquals(Long.MAX_VALUE, Row.decode(b.read(products.query())).single().integer("quantity"))
            b.write { execute("UPDATE products SET quantity = ? WHERE id = ?", Long.MIN_VALUE, row.id.toLong()) }
            b.syncOnce()
            assertEquals(Long.MIN_VALUE, Row.decode(a.read(products.query())).single().integer("quantity"))
        } finally {
            b?.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `native lifecycle cancels observations and releases locks for compatible resume`() = runBlocking {
        val root = directory()
        var runtime = RockyDatabase.create(root, ItemsSchema, local(), automaticSync = false)
        try {
            assertFailsWith<Exception> { RockyDatabase.resume(root, ItemsSchema, local(), automaticSync = false) }
            val observation = async(start = CoroutineStart.UNDISPATCHED) {
                runtime.observe(ItemsSchema.table("items").query()).take(1).toList()
            }
            withTimeout(10_000) { observation.await() }
            runtime.add("Persisted")
            val waiting = launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    runtime.observe(ItemsSchema.table("items").query()).collect()
                } catch (_: IllegalStateException) { /* Native closure terminates subscriptions. */ } catch (_: RockyException) { /* Native closure terminates subscriptions. */ }
            }
            runtime.close()
            withTimeout(10_000) { waiting.join() }
            runtime.close()
            // An application-local version change now rebuilds the projection without changing replicated identity.
            runtime = RockyDatabase.resume(root, ItemsSchema.copy(version = 2), local(), automaticSync = false)
            assertEquals(1u, runtime.generation().current.schema)
            assertEquals("Persisted", Row.decode(runtime.read(ItemsSchema.table("items").query())).single().text("title"))
        } finally {
            runtime.close()
            root.deleteRecursively()
        }
    }

    @Test fun `enrollment keeps keys in the supplied store and revocation and logout end authority`() = runBlocking {
        val root = directory()
        val keys = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()
        val store = object : SecretStore {
            override fun load(name: String): ByteArray? = keys[name]
            override fun store(name: String, secret: ByteArray) {
                keys[name] = secret
            }
            override fun delete(name: String) {
                keys.remove(name)
            }
        }
        var a = RockyDatabase.create(File(root, "a"), ItemsSchema, local(), store, automaticSync = false)
        var b: RockyDatabase? = null
        var c: RockyDatabase? = null
        try {
            assertFalse(File(root, "a/secrets").exists())
            // The owner's identity, whose key is the publisher key, stays in the supplied store.
            assertTrue(keys.keys.any { it.endsWith(".identity") })
            assertFalse(keys.keys.any { it.endsWith(".publisher") })
            val invitation = a.pairing(writer)
            b = RockyDatabase.join(File(root, "b"), ItemsSchema, invitation.uri, local(), automaticSync = false)
            assertTrue(File(root, "b/secrets").isDirectory)
            assertFailsWith<RockyException> { RockyDatabase.join(File(root, "used"), ItemsSchema, invitation.uri, local(), automaticSync = false) }
            c = RockyDatabase.join(File(root, "c"), ItemsSchema, a.pairing(writer).uri, local(), automaticSync = false)
            val session = b.session()
            assertEquals("iroh", session.transport)
            assertFalse(session.isIssuer)
            assertEquals(writer, session.profile)
            assertEquals(listOf(writer, writer), a.devices().map { it.profile })
            assertNotEquals(session.principal, session.node)
            assertEquals(setOf(session.node, c.session().node), a.devices().map { it.node }.toSet())
            assertFailsWith<RockyException> { b.pairing(writer) }
            assertTrue(b.renew().expiresAtEpochSeconds >= session.expiresAtEpochSeconds)

            a.revoke(c.session().node)
            assertTrue(a.devices().single { it.revoked }.node == c.session().node)
            a.add("After revocation")
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals(session.revocations.statements + 1uL, b.session().revocations.statements)
            assertEquals(1, Row.decode(b.read(ItemsSchema.table("items").query())).size)
            assertEquals("revoked", assertFailsWith<rocky.RockyException> { c.syncOnce() }.code)
            assertFailsWith<RockyException> { c.renew() }
            assertTrue(Row.decode(c.read(ItemsSchema.table("items").query())).isEmpty())

            assertFailsWith<RockyException> { a.logout() }
            b.logout(purge = true)
            assertFailsWith<RockyException> { b.read(ItemsSchema.table("items").query()) }
            b.close()
            b = null
            assertFalse(File(root, "b/rocky.sqlite").exists())
            assertFalse(File(root, "b/secrets").exists())
            assertFailsWith<RockyException> { RockyDatabase.resume(File(root, "b"), ItemsSchema, local(), automaticSync = false) }

            // The creator's keys live only in its store: without them it cannot resume.
            a.close()
            assertFailsWith<RockyException> { RockyDatabase.resume(File(root, "a"), ItemsSchema, local(), automaticSync = false) }
            a = RockyDatabase.resume(File(root, "a"), ItemsSchema, local(), store, automaticSync = false)
            assertTrue(a.isIssuer)
        } finally {
            c?.close()
            b?.close()
            a.close()
            root.deleteRecursively()
        }
    }

    @Test fun `sync splits expanded JSON pages without skipping large records`() = runBlocking {
        val root = directory()
        val a = RockyDatabase.create(File(root, "a"), ItemsSchema, local(), automaticSync = false)
        var b: RockyDatabase? = null
        try {
            val items = ItemsSchema.table("items")
            repeat(40) { a.add("$it:" + "x".repeat(12_000)) }
            b = RockyDatabase.join(File(root, "b"), ItemsSchema, a.pairing(writer).uri, local(), automaticSync = false)
            assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
            assertEquals((0 until 40).toSet(), Row.decode(b.read(items.query())).map { it.text("title").substringBefore(':').toInt() }.toSet())
        } finally {
            b?.close()
            a.close()
            root.deleteRecursively()
        }
    }
}
