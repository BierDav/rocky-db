package rocky.sqlite

import androidx.sqlite.SQLiteConnection
import androidx.sqlite.SQLiteDriver
import androidx.sqlite.SQLiteException
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import androidx.sqlite.execSQL
import kotlinx.coroutines.runBlocking
import rocky.RockyDatabase
import rocky.RockyTransactionOutcome
import rocky.schema
import kotlin.test.*
import rocky.testing.TestFile as File
import rocky.testing.TestFiles as Files

class RockySQLiteDriverTest {
    private val shopping = schema("shopping", version = 1) {
        table("lists") {
            text("key")
            text("title")
            primaryKey("key")
        }
        table("items") {
            text("key")
            text("list")
            text("title")
            integer("completed")
            blob("note", nullable = true)
            primaryKey("key")
            index("items_by_list", "list")
        }
    }

    private fun <T> withDatabase(block: suspend (RockyDatabase, SQLiteDriver) -> T): T = runBlocking {
        val directory: File = Files.createTempDirectory("rocky-sqlite").toFile()
        val database = RockyDatabase.local(directory.path, shopping)
        try {
            block(database, RockySQLiteDriver(database))
        } finally {
            database.close()
            directory.deleteRecursively()
        }
    }
    private fun SQLiteConnection.count(table: String): Long = prepare("SELECT count(*) FROM $table").use {
        it.step()
        it.getLong(0)
    }
    private fun SQLiteConnection.reader(): SQLiteConnection = also { it.execSQL("PRAGMA query_only = 1") }

    /** Reserves the next row id of [table] in this connection's write transaction. */
    private fun SQLiteConnection.nextId(table: String): Long = prepare("SELECT rocky_next_id(?)").use {
        it.bindText(1, table)
        assertTrue(it.step())
        it.getLong(0)
    }

    /** Runs [sql] with the first of consecutive ids reserved for it bound to its only parameter. */
    private fun SQLiteConnection.insertFrom(table: String, sql: String) = prepare(sql).use {
        it.bindLong(1, nextId(table))
        assertFalse(it.step())
    }

    /** Inserts lists [keys] in the open transaction, one statement each. */
    private fun SQLiteConnection.insertLists(keys: IntRange, key: (Int) -> String, title: (Int) -> String) = prepare("INSERT INTO lists(key, title, id) VALUES(?, ?, ?)").use { insert ->
        for (i in keys) {
            insert.bindText(1, key(i))
            insert.bindText(2, title(i))
            insert.bindLong(3, nextId("lists"))
            assertFalse(insert.step())
            insert.reset()
        }
    }
    private fun code(error: SQLiteException): Int = Regex("Error code: (\\d+)").find(error.message.orEmpty())!!.groupValues[1].toInt()

    @Test fun aTransactionWithSavepointsCommitsOnceAndReadersKeepTheirSnapshot() = withDatabase { _, driver ->
        val writer = driver.open("shopping")
        val reader = driver.open("shopping").reader()
        writer.execSQL("BEGIN IMMEDIATE TRANSACTION")
        assertTrue(writer.inTransaction())
        writer.prepare("INSERT INTO lists(key, title, id) VALUES(?, ?, ?)").use { insert ->
            insert.bindText(1, "l1")
            insert.bindText(2, "Groceries")
            insert.bindLong(3, writer.nextId("lists"))
            assertFalse(insert.step())
        }
        val ids = mutableListOf<Long>()
        writer.prepare("INSERT INTO items(key, list, title, completed, note, id) VALUES(?, 'l1', ?, 0, ?, ?)").use { insert ->
            for ((key, title) in listOf("i1" to "Milk", "i2" to "Eggs")) {
                insert.bindText(1, key)
                insert.bindText(2, title)
                insert.bindBlob(3, byteArrayOf(7))
                insert.bindLong(4, writer.nextId("items").also { ids += it })
                insert.step()
                insert.reset()
            }
        }
        assertEquals(ids.first() + 1, ids.last(), "reservations of one table continue its author's sequence")
        writer.execSQL("SAVEPOINT 'nested'")
        writer.execSQL("DELETE FROM items")
        writer.execSQL("ROLLBACK TRANSACTION TO SAVEPOINT 'nested'")
        writer.execSQL("RELEASE SAVEPOINT 'nested'")
        assertEquals(2, writer.count("items"))
        writer.execSQL("END TRANSACTION")
        assertFalse(writer.inTransaction())

        // A read transaction keeps its snapshot while the writer commits.
        reader.execSQL("BEGIN DEFERRED TRANSACTION")
        assertEquals(2, reader.count("items"))
        writer.execSQL("DELETE FROM items WHERE key = 'i2'")
        assertEquals(2, reader.count("items"))
        reader.execSQL("END TRANSACTION")
        assertEquals(1, reader.count("items"))
        reader.prepare("SELECT key, title, note FROM items").use { rows ->
            assertEquals(listOf("key", "title", "note"), rows.getColumnNames())
            assertTrue(rows.step())
            assertEquals("Milk", rows.getText(1))
            assertContentEquals(byteArrayOf(7), rows.getBlob(2))
            assertFalse(rows.step())
        }
        val refused = assertFailsWith<SQLiteException> { reader.execSQL("DELETE FROM items") }
        assertEquals(8, code(refused))
        // An id is reserved only inside the write transaction that inserts it.
        assertEquals(8, code(assertFailsWith<SQLiteException> { reader.nextId("items") }))
        assertEquals(1, code(assertFailsWith<SQLiteException> { writer.nextId("items") }))
        writer.close()
        reader.close()
    }

    @Test fun pagesStreamAndStatementsRerunAfterReset() = withDatabase { _, driver ->
        val writer = driver.open("shopping")
        // A transaction replays at most 256 statements.
        for (chunk in (1..700).chunked(200)) {
            writer.execSQL("BEGIN IMMEDIATE TRANSACTION")
            writer.insertLists(chunk.first()..chunk.last(), { "l" + it.toString().padStart(4, '0') }, { "list $it" })
            writer.execSQL("END TRANSACTION")
        }
        val reader = driver.open("shopping").reader()
        reader.prepare("SELECT key FROM lists WHERE title LIKE ? ORDER BY key").use { query ->
            query.bindText(1, "list%")
            var rows = 0
            while (query.step()) rows++
            assertEquals(700, rows)
            // A reset runs the statement again with the same bindings; an early reset drops the rest.
            query.reset()
            assertTrue(query.step())
            assertEquals("l0001", query.getText(0))
            query.reset()
            query.clearBindings()
            query.bindText(1, "none")
            assertFalse(query.step())
        }
        writer.close()
        reader.close()
    }

    @Test fun bundleLimitsAndDeniedStatementsAreSQLiteErrors() = withDatabase { _, driver ->
        val writer = driver.open("shopping")
        writer.execSQL("BEGIN IMMEDIATE TRANSACTION")
        writer.insertLists(1..257, { "l$it" }, { "x" })
        val oversized = assertFailsWith<SQLiteException> { writer.execSQL("END TRANSACTION") }
        assertEquals(18, code(oversized))
        assertFalse(writer.inTransaction())
        assertEquals(0, writer.count("lists"))
        writer.execSQL("BEGIN IMMEDIATE TRANSACTION")
        val duplicate = assertFailsWith<SQLiteException> {
            writer.insertFrom("lists", "INSERT INTO lists(key, title, id) VALUES('a', 'x', ?)")
            writer.insertFrom("lists", "INSERT INTO lists(key, title, id) VALUES('a', 'y', ?)")
        }
        assertEquals(1555, code(duplicate))
        writer.execSQL("ROLLBACK TRANSACTION")
        // An id Rocky did not issue is refused.
        assertFailsWith<SQLiteException> { writer.execSQL("INSERT INTO lists(key, title, id) VALUES('b', 'x', 0)") }
        assertEquals(0, writer.count("lists"))
        for (sql in listOf("PRAGMA user_version", "CREATE TABLE extra(id TEXT)", "SELECT * FROM sqlite_master")) {
            assertEquals(23, code(assertFailsWith<SQLiteException>(sql) { writer.execSQL(sql) }), sql)
        }
        writer.close()
    }

    @Test fun replayedTablesDeclareChecksReferencesAndAssertions() = runBlocking {
        val shop = schema("shop", version = 1) {
            val teams = table("teams") {
                tableClass = rocky.TableClass.Replayed
                integer("cap")
                text("name")
                generated(rocky.Column.integer("doubled"), "cap * 2")
                check("cap BETWEEN 1 AND 2")
                check("doubled <= 4")
                index(rocky.Index("teams_name", emptyList(), unique = true, expressions = listOf("lower(name)"), where = "cap > 0"))
                primaryKey("id")
            }
            table("members") {
                tableClass = rocky.TableClass.Replayed
                reference("team", teams, rocky.Delete.Cascade, deferred = true)
                primaryKey("id")
            }
            assertion("team_cap", "SELECT t.id FROM teams t JOIN members m ON m.team = t.id GROUP BY t.id HAVING COUNT(*) > MIN(t.cap)")
        }
        val json = shop.definitionJson("0".repeat(64))
        assertTrue("\"cap BETWEEN 1 AND 2\"" in json && "\"deferred\":true" in json && "\"select_sql\"" in json, json)
        val directory: File = Files.createTempDirectory("rocky-sqlite").toFile()
        val database = RockyDatabase.local(directory.path, shop)
        try {
            val writer = RockySQLiteDriver(database).open("shop")
            writer.execSQL("BEGIN IMMEDIATE TRANSACTION")
            writer.insertFrom("teams", "INSERT INTO teams(cap, name, id) VALUES(1, 'a', ?)")
            assertFails { writer.insertFrom("teams", "INSERT INTO teams(cap, name, id) VALUES(1, 'A', ?)") }
            assertFails { writer.execSQL("UPDATE teams SET cap = 3") }
            writer.execSQL("ROLLBACK TRANSACTION")
            writer.close()
        } finally {
            database.close()
            directory.deleteRecursively()
        }
    }

    @Test fun aReplayedCommitReportsItsOutcome() = runBlocking {
        val counters = schema("counters", version = 1) {
            table("counters") {
                tableClass = rocky.TableClass.Replayed
                text("key")
                integer("amount")
                primaryKey("key")
            }
        }
        val directory: File = Files.createTempDirectory("rocky-sqlite").toFile()
        val database = RockyDatabase.local(directory.path, counters)
        try {
            val writer = RockySQLiteDriver(database).open("counters")
            writer.execSQL("BEGIN IMMEDIATE TRANSACTION")
            writer.insertFrom("counters", "INSERT INTO counters(key, amount, id) VALUES('c', 1, ?)")
            writer.execSQL("UPDATE counters SET amount = amount + 1 WHERE key = 'c'")
            writer.execSQL("END TRANSACTION")
            val token = assertNotNull(writer.committedTransaction())
            assertEquals(RockyTransactionOutcome.Applied, database.transactionOutcome(token))
            assertEquals(
                2,
                writer.prepare("SELECT amount FROM counters").use {
                    it.step()
                    it.getLong(0)
                },
            )
            assertNull(database.transactionOutcome(ByteArray(32)))
            writer.close()
        } finally {
            database.close()
            directory.deleteRecursively()
        }
    }

    // The bundled native getters dereference null pointers for NULL/empty text.
    // Keep calling Rocky's getters directly and retain the full JVM reference calls.
    private fun referenceText(statement: androidx.sqlite.SQLiteStatement): String = try {
        statement.getText(0)
    } catch (error: NullPointerException) {
        if (statement.isNull(0) || (statement.getColumnType(0) == androidx.sqlite.SQLITE_DATA_BLOB && referenceBlob(statement).isEmpty())) "" else throw error
    }
    private fun referenceBlob(statement: androidx.sqlite.SQLiteStatement): ByteArray = try {
        statement.getBlob(0)
    } catch (error: NullPointerException) {
        if (statement.isNull(0)) ByteArray(0) else throw error
    }

    @Test fun gettersConvertAsTheBundledEngine() = withDatabase { _, driver ->
        val rocky = driver.open("shopping")
        val bundled = BundledSQLiteDriver().open(":memory:")
        val values: List<(androidx.sqlite.SQLiteStatement) -> Unit> = listOf(
            { it.bindNull(1) }, { it.bindLong(1, 42) }, { it.bindLong(1, Long.MIN_VALUE) },
            { it.bindDouble(1, 0.1) }, { it.bindDouble(1, 1.0) }, { it.bindDouble(1, -2.5e-7) }, { it.bindDouble(1, 1e20) },
            { it.bindDouble(1, 123456789.123456789) }, { it.bindDouble(1, 9.3e18) },
            { it.bindText(1, "12abc") }, { it.bindText(1, " -7.5e2x") }, { it.bindText(1, "abc") }, { it.bindText(1, "") },
            { it.bindText(1, "99999999999999999999") }, { it.bindBlob(1, "3.5".encodeToByteArray()) }, { it.bindBlob(1, ByteArray(0)) },
        )
        for ((index, bind) in values.withIndex()) {
            // Each getter reads a fresh row: the engine caches conversions, so their order would matter.
            fun read(connection: SQLiteConnection, reference: Boolean = false) = listOf<(androidx.sqlite.SQLiteStatement) -> Any>(
                { it.getColumnType(0) },
                { it.isNull(0) },
                { it.getLong(0) },
                { it.getDouble(0) },
                { if (reference) referenceText(it) else it.getText(0) },
                { (if (reference) referenceBlob(it) else it.getBlob(0)).toList() },
            ).mapIndexed { getterIndex, getter ->
                connection.prepare(if (reference) referenceSql(getterIndex >= 4) else "SELECT ?").use {
                    bind(it)
                    assertTrue(it.step())
                    getter(it)
                }
            }
            assertEquals(read(bundled, reference = true), read(rocky), "value $index")
        }
        // Rocky's scalar codec has one zero: a negative zero reads back as 0.0.
        rocky.prepare("SELECT ?").use {
            it.bindDouble(1, -0.0)
            assertTrue(it.step())
            assertEquals(0.0.toBits(), it.getDouble(0).toBits())
        }
        bundled.close()
        rocky.close()
    }
}
