package rocky.qualification

import androidx.room.Room
import androidx.sqlite.driver.bundled.BundledSQLiteDriver
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import rocky.RockyDatabase
import rocky.RockyException
import rocky.schema
import rocky.schemaFromRoom
import rocky.sqlite.RockySQLiteDriver
import java.io.File
import java.nio.file.Files
import kotlin.test.*

class RoomScalarsTest {
    @Test fun definitionBuilderReopensThroughNativeBindings() = runBlocking {
        val root = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .first { File(it, "rust-toolchain.toml").isFile }
        val exported = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.SampleDatabase/1.json").readText()
        val imported = schemaFromRoom("samples", exported)
        val handmade = schema("samples") {
            table("samples") {
                text("sensor")
                integer("sequence")
                real("reading", nullable = true)
                blob("raw", nullable = true)
                primaryKey("sensor", "sequence")
                index("samples_by_reading", listOf(rocky.IndexColumn("reading", descending = true)))
            }
        }
        val directory = Files.createTempDirectory("rocky-native-schema").toFile()
        try {
            val database = RockyDatabase.local(directory, handmade)
            try {
                assertTrue(database.read(handmade.table("samples").query()).getValue("rows").toString() == "[]")
            } finally {
                database.close()
            }
            val reopened = RockyDatabase.open(directory, imported)
            try {
                assertEquals("[]", reopened.read(imported.table("samples").query()).getValue("rows").toString())
            } finally {
                reopened.close()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun groupPartitionSharesOneSecretForEveryTable() = runBlocking<Unit> {
        val grouped = schema("groupsecret") {
            table("lists") {
                text("name")
                primaryKey("name")
                partitionBy("name", group = "list")
            }
            table("items") {
                text("list")
                text("key")
                primaryKey("list", "key")
                partitionBy("list", group = "list")
            }
            table("attachments") {
                text("list")
                text("key")
                primaryKey("list", "key")
                partitionBy("list", group = "list")
            }
        }
        val directory = Files.createTempDirectory("rocky-group-secret").toFile()
        try {
            val database = RockyDatabase.local(File(directory, "issuer"), grouped)
            try {
                val list = JsonArray(listOf(rocky.text("A")))
                assertEquals(1, database.partitions.create("list", list).getValue("epoch").jsonObject.getValue("generation").jsonPrimitive.int)
                val status = database.partitions.status("list", list)
                assertEquals(listOf(1L), status.getValue("epochs").jsonArray.map { rocky.KeyEpoch.fromJson(it).generation })
                val tables = status.getValue("tables").jsonArray.map { it.jsonObject }
                assertEquals(listOf("attachments", "items", "lists"), tables.map { it.getValue("table").jsonPrimitive.content }.sorted())
                assertTrue(tables.all { it.getValue("epochs") == status.getValue("epochs") && it.getValue("current") == status.getValue("current") })
                val device = rocky.Credentials.prepare(File(directory, "reader"))
                val shared = database.partitions.share("list", list, JsonArray(listOf(device.getValue("node"))))
                assertEquals(listOf(device.getValue("node")), shared.getValue("recipients").jsonArray.toList())
                // The envelope waits for sync; only this sharer knows it is pending.
                val recipients = database.partitions.status("list", list).getValue("recipients").jsonArray.map { it.jsonObject }
                assertEquals(listOf("pending"), recipients.map { it.getValue("state").jsonPrimitive.content })
                assertFailsWith<RockyException> { database.partitions.share("list", list, JsonArray(listOf(device.getValue("node"))), epoch = rocky.KeyEpoch(2, "0".repeat(64))) }
                assertFailsWith<RockyException> { database.partitions.subscribe("list", list, omit = listOf("photos")) }
            } finally {
                database.close()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun partitionedRoomOverlayAndViews() = runBlocking {
        val root = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .first { File(it, "rust-toolchain.toml").isFile }
        val exported = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.PartitionDatabase/1.json").readText()
        val imported = schemaFromRoom("partitionroom", exported) { table("partition_samples") { partitionBy("sensor") } }
        val handmade = schema("partitionroom") {
            table("partition_samples") {
                text("sensor")
                integer("sequence")
                integer("reading")
                primaryKey("sensor", "sequence")
                partitionBy("sensor")
            }
            view("partial_partition_samples", "SELECT * FROM partition_samples")
        }
        assertEquals(handmade.definitionJson("09".repeat(32)), imported.definitionJson("09".repeat(32)))
        val directory = Files.createTempDirectory("rocky-partition-room").toFile()
        try {
            val database = RockyDatabase.local(directory, imported)
            try {
                for (sensor in listOf("A", "B")) database.partitions.create("partition_samples", JsonArray(listOf(rocky.text(sensor))))
                val ids = mutableListOf<Long>()
                for ((sensor, reading) in listOf("A" to 10L, "B" to 20L)) {
                    database.write {
                        val id = nextId("partition_samples", sensor)
                        ids += id
                        execute("INSERT INTO partition_samples(sensor,sequence,reading,id) VALUES(?,?,?,?)", sensor, 1L, reading, id)
                    }
                }
                assertEquals(ids[0] + 1, ids[1])
                RockySQLiteDriver(database).open("partitions").use { connection ->
                    connection.prepare("SELECT SUM(reading) FROM partial_partition_samples").use { statement ->
                        assertTrue(statement.step())
                        assertEquals(30L, statement.getLong(0))
                    }
                }
            } finally {
                database.close()
            }
            val reopened = RockyDatabase.open(directory, handmade)
            try {
                assertEquals(2, reopened.read(rocky.query("SELECT * FROM partial_partition_samples")).getValue("rows").let { (it as kotlinx.serialization.json.JsonArray).size })
            } finally {
                reopened.close()
            }
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun scalarsAndCompoundKeys() = runBlocking {
        val directory = Files.createTempDirectory("rocky-room-scalars")
        val database = Room.databaseBuilder<SampleDatabase>(directory.resolve("samples.sqlite").toString())
            .setDriver(BundledSQLiteDriver()).build()
        try {
            val dao = database.dao()
            dao.insert(Sample("s", 7, 1.25, byteArrayOf(0, -1, 42), id = 1))
            val row = dao.all().single()
            assertEquals(1.25, row.reading)
            assertContentEquals(byteArrayOf(0, -1, 42), row.raw)
            assertFails { dao.insert(Sample("s", 7, 2.0, null, id = 2)) }
            dao.insert(Sample("s", 8, null, null, id = 2))
            assertNull(dao.all().last().reading)
            assertNull(dao.all().last().raw)
        } finally {
            database.close()
            directory.toFile().deleteRecursively()
        }
    }
}
