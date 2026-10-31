package rocky.qualification

import androidx.room.Room
import androidx.sqlite.SQLiteException
import kotlinx.coroutines.runBlocking
import rocky.*
import rocky.room.setRockyDatabase
import java.io.File
import java.nio.file.Files
import kotlin.test.*

class RoomConstraintsTest {
    @Test fun exportedConstraintsRunOnRockysFile() = runBlocking {
        val root = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
            .first { File(it, "rust-toolchain.toml").isFile }
        val exported = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.ConstraintDatabase/1.json").readText()
        val schema = schemaFromRoom("constraints", exported)
        val directory = Files.createTempDirectory("rocky-room-constraints").toFile()
        try {
            val rocky = RockyDatabase.local(directory, schema)
            try {
                val room = Room.databaseBuilder<ConstraintDatabase>(File(directory, "room").path).setRockyDatabase(rocky).build()
                try {
                    val dao = room.dao()
                    val parent = dao.createParent("Groceries")
                    val optional = dao.createParent("Hardware")
                    dao.createChild("milk", "Milk", parent, optional)
                    assertEquals("milk", dao.children().single().code)
                    assertFailsWith<SQLiteException> { dao.createChild("milk", "Other", parent) }
                    assertFailsWith<SQLiteException> { dao.createChild("eggs", "Milk", parent) }
                    assertFailsWith<SQLiteException> { dao.createChild("eggs", null, optional + 100) }
                    assertEquals(1, dao.children().size)
                    dao.deleteParent(optional)
                    assertNull(dao.children().single().optional)
                    dao.update(dao.children().single().copy(label = "New label"))
                    assertNull(dao.children().single().optional)
                    assertEquals("New label", dao.children().single().label)
                    dao.deleteParent(parent)
                    assertTrue(dao.children().isEmpty())
                    dao.createParent("Groceries")
                    assertTrue(dao.children().isEmpty(), "old children reference the deleted incarnation")
                } finally {
                    room.close()
                }
            } finally {
                rocky.close()
            }
            val reopened = RockyDatabase.open(directory, schema)
            try {
                assertEquals("[]", reopened.read(schema.table("children").query()).getValue("rows").toString())
            } finally {
                reopened.close()
            }
        } finally {
            directory.deleteRecursively()
        }
    }
}
