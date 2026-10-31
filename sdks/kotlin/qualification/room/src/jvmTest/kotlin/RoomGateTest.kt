package rocky.room.qualification

import androidx.room.PooledConnection
import androidx.room.Room
import androidx.room.deferredTransaction
import androidx.room.immediateTransaction
import androidx.room.useReaderConnection
import androidx.room.useWriterConnection
import androidx.sqlite.SQLiteException
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import rocky.*
import rocky.room.ROOM_PROFILE
import rocky.room.setRockyDatabase
import rocky.room.setRockySeal
import rocky.sqlite.RockySQLiteDriver
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.*

/** What one Room transaction publishes, and what peers, readers and ordinary SQLite see of it. */
class RoomGateTest {
    private val root = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }.first { File(it, "rust-toolchain.toml").isFile }
    private val schema = schemaFromRoom(
        "shop",
        File(root, "sdks/kotlin/qualification/room/schemas/rocky.room.qualification.ShopDatabase/1.json").readText(),
    )
    private fun loopback(): PeerTransport = PeerTransport.Iroh.isolated()
    private fun item(key: String, title: String, list: String = "l1") = ShopItem(key, list, title)
    private fun room(directory: File, database: RockyDatabase): ShopDatabase = Room.databaseBuilder<ShopDatabase>(File(directory, "shop").path).setRockyDatabase(database).build()

    /** Inspect the live file in another process so SQLite's lock bookkeeping is shared correctly. */
    private fun <T> file(directory: File, block: (FileReader) -> T): T = block(FileReader(File(directory, "rocky.sqlite")))
    private class FileReader(private val path: File) {
        fun rows(sql: String): List<List<String?>> {
            val process = ProcessBuilder("sqlite3", "-readonly", "-json", "-cmd", ".explain off", path.path, sql).start()
            check(
                process.waitFor(10, TimeUnit.SECONDS).also { finished ->
                    if (!finished) process.destroyForcibly().waitFor()
                },
            ) { "SQLite inspection timed out" }
            val output = process.inputStream.bufferedReader().readText()
            val error = process.errorStream.bufferedReader().readText()
            check(process.exitValue() == 0) { error }
            if (output.isBlank()) return emptyList()
            return Json.parseToJsonElement(output).jsonArray.map { row ->
                row.jsonObject.values.map { it.jsonPrimitive.contentOrNull }
            }
        }
    }

    /** Bundles this device authored, as the Rust driver test counts them. */
    private fun bundles(directory: File): Long = file(directory) { it.rows("SELECT count(DISTINCT handle) FROM secure_bundle_handles").single().single()!!.toLong() }

    private class Devices(val directory: File, val a: RockyDatabase, val b: RockyDatabase, val roomA: ShopDatabase, val roomB: ShopDatabase)
    private fun <T> pair(block: suspend Devices.() -> T): T = runBlocking {
        val directory = Files.createTempDirectory("room-gate").toFile()
        val a = RockyDatabase.create(File(directory, "a"), schema, loopback(), automaticSync = false)
        try {
            val b = RockyDatabase.join(
                File(directory, "b"),
                schema,
                a.pairing(GrantProfile.Writer(setOf("lists", "items"))).uri,
                loopback(),
                automaticSync = false,
            )
            try {
                val roomA = room(File(directory, "a"), a)
                val roomB = room(File(directory, "b"), b)
                try {
                    Devices(directory, a, b, roomA, roomB).block()
                } finally {
                    roomA.close()
                    roomB.close()
                }
            } finally {
                b.close()
            }
        } finally {
            a.close()
            directory.deleteRecursively()
        }
    }

    @Test fun aRoomTransactionIsOneBundleOnPeersAndAnOversizedOneFailsWhole() = pair {
        // Register before authoring: the join's final sync can carry the write before syncOnce.
        val events = b.driverTableEvents()
        val before = bundles(File(directory, "a"))
        roomA.shop().createList(ShopList("l1", "Groceries"), listOf(item("i1", "Milk"), item("i2", "Eggs"), item("i3", "Jam")))
        assertEquals(before + 1, bundles(File(directory, "a")))
        assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
        val applied = withTimeout(10_000) {
            var change = events.next()
            while ("items" !in change.tables) change = events.next()
            change
        }
        assertEquals(setOf("items", "lists"), applied.tables.toSet(), "one commit applied the parent and its children")
        assertEquals(3, roomB.shop().withItems("l1")?.items?.size)

        // The debug native build steps 2,049 single-row inserts slower than the 5 s default lease, which is not
        // what this checks: a longer lease, one reservation and the sequences that follow it.
        val bulk = Room.databaseBuilder<ShopDatabase>(File(directory, "bulk").path)
            .setDriver(RockySQLiteDriver(a, ROOM_PROFILE, transactionTimeoutMillis = 60_000)).setQueryCoroutineContext(Dispatchers.IO).build()
        val oversized = try {
            assertFailsWith<SQLiteException> {
                bulk.useWriterConnection { writer ->
                    writer.immediateTransaction {
                        val first = bulk.shop().nextId("items")
                        bulk.shop().insertItems(List(2_049) { item("big$it", "Bulk $it").copy(id = first + it) })
                    }
                }
            }
        } finally {
            bulk.close()
        }
        assertContains(oversized.message.orEmpty(), "Error code: 18")
        assertEquals(before + 1, bundles(File(directory, "a")), "nothing published, nothing split")
        assertEquals(3, roomA.shop().items("l1").size)
        b.syncOnce()
        assertEquals(3, roomB.shop().items("l1").size)
    }

    @Test fun aDaoReadsASealKeptTwoSealsAgoUnchanged() = pair {
        a.tips.createBookmark("main")
        a.tips.follow("main")
        a.tips.keep(KeptSeals(every = true))
        roomA.shop().createList(ShopList("l1", "Groceries"), listOf(item("i1", "Milk"), item("i2", "Eggs")))
        // A continue seal's id is its successor tip.
        val kept = a.tips.seal().tip
        val sealed = roomA.shop().items("l1")
        roomA.shop().update(sealed.single { it.key == "i1" }.copy(title = "Oat milk"))
        a.tips.seal()
        roomA.shop().createItems(listOf(item("i3", "Jam")))
        roomA.shop().delete(sealed.single { it.key == "i2" })
        a.tips.seal()
        roomA.shop().createItems(listOf(item("i4", "Bread")))
        assertEquals(TipHeld.KEPT, a.tips.inspect().seals.single { it.id == kept }.held)

        val bound = Room.databaseBuilder<ShopDatabase>(File(directory, "sealed").path).setRockySeal(a, RockyBinding.Seal(kept)).build()
        try {
            assertEquals(sealed, bound.shop().items("l1"), "the same DAO returns the seal's rows")
            assertEquals(listOf(Summary("l1", 2, 0)), bound.shop().summary())
            assertEquals(listOf("Bread", "Jam", "Oat milk"), roomA.shop().items("l1").map { it.title })
            val refused = assertFailsWith<SQLiteException> { bound.shop().createItems(listOf(item("i9", "Never"))) }
            assertContains(refused.message.orEmpty(), "Error code: 8")
            assertEquals(sealed, bound.shop().items("l1"))
        } finally {
            bound.close()
        }
    }

    @Test fun aDaoObtainsEachIdBeforeItsInsertInOneTransaction() = pair {
        // Counted from table events, not the file: a second SQLite in this process must not hold it during sync.
        val events = a.driverTableEvents()
        val created = roomA.shop().createList(ShopList("l1", "Groceries"), listOf(item("i1", "Milk"), item("i2", "Eggs")))!!
        assertEquals(setOf("items", "lists"), withTimeout(10_000) { events.next() }.tables.toSet(), "reservations and inserts commit once")
        // An id is the node's next sequence for this table: the first list, then consecutive items.
        assertEquals(1L, created.list.id and 0xFFFF_FFFFL)
        val ids = created.items.sortedBy { it.key }.map { it.id }
        assertEquals(listOf(1L, 2L), ids.map { it and 0xFFFF_FFFFL })
        assertEquals(created.list.id ushr 32, ids.first() ushr 32, "the node signs every table under one author number")
        assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
        assertEquals(created, roomB.shop().withItems("l1"), "peers see the issued ids")
        // Another device issues under its own author.
        val fromB = roomB.shop().createItems(listOf(item("i3", "Jam"))).single()
        assertNotEquals(ids.first() ushr 32, fromB.id ushr 32)
        assertEquals(1L, fromB.id and 0xFFFF_FFFFL)
        // A rolled-back transaction releases its reservation.
        var released = 0L
        assertFailsWith<IllegalStateException> {
            roomA.useWriterConnection { writer ->
                writer.immediateTransaction {
                    released = roomA.shop().nextId("items")
                    error("undo")
                }
            }
        }
        assertEquals(3L, released and 0xFFFF_FFFFL)
        assertEquals(released, roomA.shop().createItems(listOf(item("i4", "Bread"))).single().id)
        // Outside a write transaction there is nothing to reserve an id for.
        val outside = assertFailsWith<SQLiteException> { roomA.shop().nextId("items") }
        assertContains(outside.message.orEmpty(), "rocky_next_id needs a write transaction")
        // An entity whose id Rocky did not issue is refused, and nothing is published.
        assertFailsWith<SQLiteException> { roomA.shop().insertItems(listOf(item("i5", "Unissued"))) }
        assertFailsWith<SQLiteException> { roomA.shop().insertItems(listOf(item("i5", "Skipped").copy(id = released + 2))) }
        assertTrue(b.syncOnce().peers.any { peer -> peer.attempts.any { attempt -> attempt.operation == rocky.AttemptOperation.Reconcile && attempt.outcome == rocky.AttemptOutcome.Completed } })
        assertEquals(listOf("i1", "i2", "i3", "i4"), roomB.shop().items("l1").map { it.key }.sorted())
        assertEquals(roomB.shop().items("l1"), roomA.shop().items("l1"))
    }

    @Test fun readersNeverBlockTheWriter() = pair {
        roomA.shop().createList(ShopList("l1", "Groceries"), listOf(item("i1", "Milk")))
        suspend fun count(connection: PooledConnection) = connection.usePrepared("SELECT count(*) FROM items") {
            it.step()
            it.getLong(0)
        }
        val seen = roomA.useReaderConnection { reader ->
            reader.deferredTransaction {
                val first = count(reader)
                // The writer commits while this read transaction holds its snapshot, well inside the 5 s lease.
                // Outside this coroutine's context, which Room would bind to the reader connection.
                CoroutineScope(Dispatchers.IO).async { withTimeout(2_000) { roomA.shop().createItems(listOf(item("i2", "Eggs"))) } }.await()
                listOf(first, count(reader))
            }
        }
        assertEquals(listOf(1L, 1L), seen)
        assertEquals(2, roomA.shop().items("l1").size)
    }

    @Test fun theFileOpensWithOrdinarySqliteAndShowsRealKeysAndIndexes() = pair {
        roomA.shop().createList(ShopList("l1", "Groceries"), listOf(item("i1", "Milk"), item("i2", "Eggs")))
        file(File(directory, "a")) { sqlite ->
            assertContains(sqlite.rows("SELECT sql FROM sqlite_master WHERE name = 'items'").single().single()!!, "PRIMARY KEY")
            // name and pk of each column
            assertEquals(listOf("key", "1"), sqlite.rows("PRAGMA table_info(items)").first().let { listOf(it[1], it[5]) })
            assertEquals(listOf("items_by_list", "items_identity"), sqlite.rows("PRAGMA index_list(items)").map { it[1] }.filter { it!!.startsWith("items_") }.sortedBy { it })
            assertEquals(listOf("id"), sqlite.rows("PRAGMA index_info(items_identity)").map { it[2] })
            assertEquals(listOf("list", "title"), sqlite.rows("PRAGMA index_info(items_by_list)").map { it[2] })
            assertTrue(sqlite.rows("EXPLAIN QUERY PLAN SELECT title FROM items WHERE list = 'l1'").any { "items_by_list" in it.last().orEmpty() })
            assertEquals(listOf("Eggs", "Milk"), sqlite.rows("SELECT title FROM items WHERE list = 'l1' ORDER BY title").map { it.single() })
        }
    }
}
