package org.example.examples.shopping.qualification

import androidx.room.Room
import androidx.room.useReaderConnection
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.example.examples.shopping.data.ShoppingRepository
import org.example.examples.shopping.data.db.ShoppingDatabase
import org.example.examples.shopping.data.db.ShoppingSchema
import org.example.examples.shopping.data.db.list
import org.example.examples.shopping.data.household.Household
import org.example.examples.shopping.data.household.NodeKind
import org.example.examples.shopping.data.household.PairingCode
import org.example.examples.shopping.data.tips.HouseholdTips
import org.example.examples.shopping.data.tips.TipsState
import rocky.*
import rocky.room.ROOM_PROFILE
import rocky.room.setRockyDatabase
import rocky.sqlite.RockySQLiteDriver
import java.io.File

/** Marks a reply line; native logging shares stdout. */
internal const val REPLY = "@@rocky-device@@ "

/**
 * One shopping device in its own process: the app's Room repository on Rocky's file over isolated iroh. It reads one JSON
 * request per stdin line and answers each on a [REPLY] line. Closing stdin closes the device.
 */
fun main() = runBlocking {
    val device = DeviceProcess()
    try {
        while (true) {
            val line = readlnOrNull() ?: break
            val request = Json.parseToJsonElement(line).jsonObject
            val reply = try {
                buildJsonObject { put("ok", device.handle(request)) }
            } catch (error: Throwable) {
                buildJsonObject { put("error", "${error::class.simpleName}: ${error.message}") }
            }
            println(REPLY + reply)
            System.out.flush()
            if (request.text("op") == "close") break
        }
    } finally {
        device.close()
    }
}

private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.content
private fun JsonObject.long(name: String) = getValue(name).jsonPrimitive.long
private fun JsonObject.longOrNull(name: String) = get(name)?.jsonPrimitive?.longOrNull

private fun GenerationStatus.qualificationJson(): JsonObject = buildJsonObject {
    put("manifest", manifest)
    putJsonObject("current") { put("schema", current.schema.toLong()) }
    put(
        "pending",
        pending?.let { generation ->
            buildJsonObject {
                put("tip", generation.tip)
                put("manifest", generation.manifest)
            }
        } ?: JsonNull,
    )
    put("application", application.name.lowercase())
    put("waiting_for_issuer", waitingForIssuer)
}

private fun RetentionStatus.qualificationJson(): JsonObject = buildJsonObject {
    putJsonObject("policy") {
        put("required", JsonArray(policy.required.sorted().map(::JsonPrimitive)))
        put("behind", JsonArray(policy.behind.sorted().map(::JsonPrimitive)))
        put("copies", policy.copies)
        put("window", policy.window)
    }
    put("covered", covered)
    put("uncovered", uncovered)
    put("maintenance_error", maintenanceError)
}

private class DeviceProcess {
    private var file: File? = null
    private var runtime: RockyDatabase? = null
    private var room: ShoppingDatabase? = null
    private var directory: File? = null
    private var attached: RockyNetworkService? = null
    private val database get() = runtime ?: error("no open device")
    private val repository get() = ShoppingRepository(room ?: error("no Room on app version $app"), database)

    /** The app version this process runs; Room's entities are the current version's, so older apps write raw SQL. */
    private var app = CURRENT_APP
    private fun tips(sealAfter: ULong = HouseholdTips.SEAL_AFTER) = HouseholdTips(database, { Room.databaseBuilder<ShoppingDatabase>(it) }, directory!!.path, sealAfter)

    private suspend fun opened(directory: File, app: Int, open: suspend () -> RockyDatabase): JsonElement {
        val opened = open()
        runtime = opened
        this.app = app
        this.directory = directory
        file = File(directory, "rocky.sqlite")
        room = if (app == CURRENT_APP) Room.databaseBuilder<ShoppingDatabase>(File(directory, "shopping").absolutePath).setRockyDatabase(opened).build() else null
        tips().keepSeals()
        return buildJsonObject {
            put("node", opened.session().node)
            put("issuer", opened.isIssuer)
            put("generation", opened.generation().qualificationJson())
        }
    }

    suspend fun handle(request: JsonObject): JsonElement {
        // `default` reaches devices outside this host, such as a phone, through relays and discovery.
        fun loopback() = if (request["transport"]?.jsonPrimitive?.contentOrNull == "default") PeerTransport.Iroh() else PeerTransport.Iroh.isolated(request.text("listen"))
        fun directory() = File(request.text("directory"))
        val requested = request["app"]?.jsonPrimitive?.intOrNull ?: CURRENT_APP
        fun schema() = appSchema(requested)
        suspend fun opened(directory: File, open: suspend () -> RockyDatabase) = opened(directory, requested, open)
        fun coordinator() = request["coordinator"]?.jsonPrimitive?.contentOrNull?.let { ServiceCoordinator(File(it).readText()) }
        val list = { request.long("list") }
        return when (request.text("op")) {
            "schema" -> Json.parseToJsonElement(ShoppingSchema.json())

            "create" -> opened(directory()) {
                RockyDatabase.create(directory(), schema(), loopback(), automaticSync = false, coordinator = coordinator()).also {
                    it.tips.createBookmark("main")
                    it.tips.follow("main")
                    it.tips.setGenesisMinimum(1u)
                }
            }

            "join" -> opened(directory()) {
                RockyDatabase.join(directory(), schema(), request.text("invitation"), loopback(), automaticSync = false, coordinator = coordinator())
            }

            // Opens without a network: what opening publishes stays here until `attach`.
            "resumeOffline" -> opened(directory()) {
                RockyDatabase.open(directory(), schema(), null, automaticSync = false, coordinator = coordinator(), confirmation = request["confirmation"]?.jsonPrimitive?.contentOrNull)
            }

            "attach" -> {
                attached = database.attach(loopback())
                JsonNull
            }

            "reopen" -> {
                close()
                opened(directory()) {
                    RockyDatabase.resume(directory(), schema(), loopback(), automaticSync = false, coordinator = coordinator(), confirmation = request["confirmation"]?.jsonPrimitive?.contentOrNull)
                }
            }

            // Closes the database and keeps the process, for reopening under another app version.
            "shut" -> {
                close()
                JsonNull
            }

            // A read through Rocky's SQL, for columns an older app's Room entities lack; each cell as text.
            "query" -> JsonArray(rows(request.text("sql")).map { row -> JsonArray(row.map(::JsonPrimitive)) })

            // As app version 7 adds a category, without version 8's position.
            "addCategoryRaw" -> {
                val list = list()
                JsonPrimitive(database.write { nextId("categories", list).also { execute("INSERT INTO categories(list, name, id) VALUES(?, ?, ?)", list, request.text("name"), it) } })
            }

            "generation" -> database.generation().qualificationJson()

            "inspect" -> JsonPrimitive(database.tips.inspect().toString())

            // As the app's approvals do: the household's trusted identities register with the coordination service.
            "register" -> {
                val trusted = database.devices().filter { it.profile == GrantProfile.Issuer && !it.revoked }.map { it.user } + database.session().principal
                database.service(randomTenant()).register(RockyDatabase.newHandle(), trusted.distinct().sorted())
                JsonNull
            }

            "tips" -> tips().refresh().json()

            "maintain" -> {
                val round = tips(request["sealAfter"]?.jsonPrimitive?.longOrNull?.toULong() ?: HouseholdTips.SEAL_AFTER).maintain()
                buildJsonObject {
                    put("sealed", round.sealed)
                    put("compacted", round.compaction.compacted)
                    put("finalized", round.compaction.finalized)
                    put("pruned", round.compaction.pruned.toLong())
                    put("blocked", JsonArray(round.compaction.blocked.map { JsonPrimitive(it.reason) }.distinct()))
                    put("uncompacted", round.compaction.uncompacted.size)
                }
            }

            "retention" -> database.retention(request.text("collection"), maintain = request["maintain"]?.jsonPrimitive?.boolean ?: false).qualificationJson()

            "seal" -> JsonPrimitive(tips().seal().tip)

            "branch" -> JsonPrimitive(tips().branch(request.text("name")))

            "follow" -> JsonPrimitive(tips().follow(request.text("name")).name)

            "switched" -> JsonPrimitive(tips().switched().name)

            "leave" -> {
                tips().leave(request.text("name"), request["delete"]?.jsonPrimitive?.boolean ?: false)
                JsonNull
            }

            "drop" -> {
                database.tips.drop(request.text("tip"))
                JsonNull
            }

            "rollBack" -> JsonPrimitive(tips().rollBack(request.text("seal")))

            "snapshot" -> JsonArray(
                tips().snapshot(request.text("seal")).map { snapshot ->
                    buildJsonObject {
                        put("title", snapshot.title)
                        put("items", JsonArray(snapshot.items.map { JsonPrimitive(it.title + if (it.completed) " [x]" else "") }))
                    }
                },
            )

            // A kept seal's items through a read-only connection bound to it, whatever this app's Room version.
            "view" -> {
                val connection = RockySQLiteDriver(database, ROOM_PROFILE, binding = RockyBinding.Seal(request.text("seal"))).open("view")
                try {
                    connection.prepare("SELECT title, completed FROM items ORDER BY title").use { statement ->
                        val items = mutableListOf<JsonPrimitive>()
                        while (statement.step()) items += JsonPrimitive(statement.getText(0) + if (statement.getLong(1) != 0L) " [x]" else "")
                        JsonArray(items)
                    }
                } finally {
                    connection.close()
                }
            }

            "held" -> JsonArray(
                database.heldChanges().changes.map { change ->
                    buildJsonObject {
                        put("id", change.id)
                        put(
                            "rows",
                            JsonArray(
                                change.rows.map { row ->
                                    JsonPrimitive("${row.kind} ${row.table} ${row.fields.firstOrNull { it.name == "title" }?.value ?: ""}".trim())
                                },
                            ),
                        )
                    }
                },
            )

            "reauthor" -> {
                tips().reauthor(request.text("id"))
                JsonNull
            }

            // What compaction leaves in the file, read by another process: tombstones and operations of every scope.
            "storage" -> buildJsonObject {
                put("rows", scalar("SELECT count(*) FROM secure_rows"))
                put("tombstones", scalar("SELECT COALESCE(SUM(tombstones),0) FROM secure_scope_state") + scalar("SELECT count(*) FROM secure_rows WHERE fields IS NULL"))
                put("operations", scalar("SELECT count(*) FROM secure_operations"))
                put("stubs", scalar("SELECT count(*) FROM secure_stubs"))
                put("history", scalar("SELECT count(*) FROM sqlite_master WHERE type='table' AND name LIKE 'secure_history_%'"))
                val self = database.tips.inspect().nodes.firstOrNull { it.keptTips != null }
                put("tips", JsonArray(self?.keptTips.orEmpty().map(::JsonPrimitive)))
            }

            // Approvals as the app writes them: requests and decisions are ordinary rows.
            "ask" -> {
                val key = RockyDatabase.newHandle()
                val self = database.session().node
                database.write { execute("INSERT INTO requests(key,title,note,requester,id) VALUES(?,?,?,?,?)", key, request.text("title"), "", self, nextId("requests")) }
                JsonPrimitive(key)
            }

            "decide" -> {
                val key = request.text("key")
                val self = database.session().node
                check(rows("SELECT key FROM requests WHERE key='$key'").isNotEmpty()) { "request $key has not arrived" }
                database.write { execute("INSERT INTO decisions(key,approved,decider,id) VALUES(?,?,?,?)", key, true, self, nextId("decisions")) }
                JsonPrimitive(key)
            }

            "decisions" -> JsonArray(rows("SELECT key FROM decisions ORDER BY key").map { JsonPrimitive(it[0]) })

            "coordinated" -> JsonPrimitive(database.coordinatedStatus().tip)

            "prepare" -> Credentials.prepare(directory().path)

            "grantWriter" -> database.grant(
                request.getValue("device").jsonObject,
                NodeKind.Full.profile,
                authors = ShoppingSchema.tables.size,
            )

            "install" -> opened(directory()) {
                RockyDatabase.install(directory().path, ShoppingSchema, request.getValue("supplied").jsonObject, transport = loopback())
            }

            "resume" -> opened(directory()) { RockyDatabase.resume(directory(), schema(), loopback(), automaticSync = false, coordinator = coordinator()) }

            "pairing" -> JsonPrimitive(
                when (val profile = request.text("profile")) {
                    "writer" -> database.pairing(NodeKind.Full.profile)
                    "custody" -> database.pairing(GrantProfile.Custody(ShoppingSchema.tables.map { it.name }.toSet()))
                    "issuer" -> database.pairDevice()
                    else -> error("unknown profile $profile")
                }.uri,
            )

            // The app's own pairing link, as Devices → Add device shows it.
            "appPairing" -> JsonPrimitive(PairingCode(NodeKind.of(request.text("kind"))!!, request.text("name"), database.pairing(NodeKind.of(request.text("kind"))!!.profile).uri).toString())

            "registry" -> JsonArray(database.devices().filter { !it.revoked }.map { JsonPrimitive(it.node) })

            "contact" -> buildJsonObject {
                val contact = database.contact()
                put("uri", contact.uri)
                put("node", contact.node)
            }

            "addPeer" -> JsonPrimitive(database.addPeer(request.text("contact")))

            "removePeer" -> {
                database.removePeer(request.text("node"))
                JsonNull
            }

            "online" -> {
                database.setNetworkingEnabled(request.getValue("online").jsonPrimitive.boolean)
                JsonNull
            }

            "sync" -> {
                val report = database.syncOnce()
                buildJsonObject {
                    put("skip", report.skip?.name)
                    put(
                        "peers",
                        JsonArray(
                            report.peers.map { peer ->
                                buildJsonObject {
                                    put("node", peer.node)
                                    put("skip", peer.skip?.name)
                                    put(
                                        "attempts",
                                        JsonArray(
                                            peer.attempts.map { attempt ->
                                                buildJsonObject {
                                                    put("operation", attempt.operation.name)
                                                    put("stage", attempt.stage.name)
                                                    put("outcome", attempt.outcome?.name)
                                                    put("error", attempt.failure?.detail)
                                                }
                                            },
                                        ),
                                    )
                                }
                            },
                        ),
                    )
                }
            }

            "createList" -> JsonPrimitive(
                if (room != null) {
                    repository.createList(request.text("title"))
                } else {
                    val id = database.partitions.nextId("lists")
                    database.write {
                        check(nextId("lists") == id) { "list id $id was taken" }
                        execute("INSERT INTO lists(id, title) VALUES(?, ?)", id, request.text("title"))
                    }
                    id
                },
            )

            "addCategory" -> JsonPrimitive(repository.addCategory(list(), request.text("name")))

            "add" -> JsonPrimitive(
                if (room != null) {
                    repository.add(list(), request.text("title"), setOfNotNull(request.longOrNull("category")))
                } else {
                    val list = list()
                    database.write {
                        nextId("items", list).also { execute("INSERT INTO items(list, key, title, completed, id) VALUES(?, ?, ?, ?, ?)", list, java.util.UUID.randomUUID().toString(), request.text("title"), false, it) }
                    }
                },
            )

            "check" -> {
                val completed = request.getValue("completed").jsonPrimitive.boolean
                if (room != null) {
                    repository.check(list(), request.long("id"), completed)
                } else {
                    database.write { execute("UPDATE items SET completed = ? WHERE list = ? AND id = ?", completed, list(), request.long("id")) }
                }
                JsonNull
            }

            "delete" -> {
                if (room != null) {
                    repository.delete(list(), request.long("id"))
                } else {
                    database.write { execute("DELETE FROM items WHERE list = ? AND id = ?", list(), request.long("id")) }
                }
                JsonNull
            }

            "deleteCategory" -> {
                repository.deleteCategory(list(), request.long("category"))
                JsonNull
            }

            "deleteList" -> {
                repository.deleteList(list())
                JsonNull
            }

            "move" -> {
                repository.move(request.long("from"), request.long("id"), request.long("to"))?.let(::JsonPrimitive) ?: JsonNull
            }

            "share" -> {
                database.list(list()).share(request.getValue("recipients").jsonArray.map { it.jsonPrimitive.content })
                JsonNull
            }

            "shareWithDevices" -> JsonArray(repository.shareWithDevices(list()).map(::JsonPrimitive))

            // As the Devices tab names a device: its registry label and the trusted-only row.
            "label" -> {
                Household(room!!, database, database.session().node).record(request.text("device"), request.text("name"), NodeKind.Full)
                JsonNull
            }

            "deliveries" -> JsonObject(repository.deliveries(list()).associate { it.node to JsonPrimitive(it.state.name) })

            "absentTables" -> {
                val tables = if (database.isIssuer) listOf("keys", "identities") else listOf("devices", "keys", "identities")
                val checks = tables.associateWith { table ->
                    val error = runCatching {
                        room?.useReaderConnection { reader -> reader.usePrepared("SELECT * FROM $table") { it.step() } } ?: rows("SELECT * FROM $table")
                    }.exceptionOrNull()
                    JsonPrimitive(error?.message ?: "table exists")
                }
                val process = ProcessBuilder("sqlite3", "-readonly", file!!.path, "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('devices','keys','identities')").redirectErrorStream(true).start()
                val physical = process.inputStream.bufferedReader().readText()
                check(process.waitFor() == 0) { "SQLite inspection failed: $physical" }
                buildJsonObject {
                    put("sql", JsonObject(checks))
                    put("physical", JsonArray(physical.lines().filter { it.isNotBlank() }.map(::JsonPrimitive)))
                }
            }

            "lists" -> JsonArray(
                if (room != null) {
                    room!!.lists().observeAll().first().map { JsonPrimitive("${it.id}:${it.title}") }
                } else {
                    rows("SELECT id, title FROM lists ORDER BY id").map { JsonPrimitive("${it[0]}:${it[1]}") }
                },
            )

            "items" -> {
                val list = list()
                val links = rows("SELECT item, category FROM item_categories WHERE list = $list").groupBy({ it[0]!!.toLong() }, { it[1]!!.toLong() })
                JsonArray(
                    rows("SELECT id, title, completed FROM items WHERE list = $list ORDER BY title").map { (id, title, completed) ->
                        buildJsonObject {
                            put("id", id!!.toLong())
                            put("title", title)
                            put("completed", completed == "1" || completed == "true")
                            links[id.toLong()]?.sorted()?.let { put("categories", JsonArray(it.map(::JsonPrimitive))) }
                        }
                    },
                )
            }

            "status" -> database.partitions.status("list", database.list(list()).values)

            "revoke" -> {
                database.revoke(request.text("node"))
                JsonNull
            }

            "renew" -> JsonPrimitive(database.renew().revocations.statements)

            "close" -> JsonNull

            else -> error("unknown op ${request.text("op")}")
        }
    }

    /** Rows of a read through Rocky's SQL, each cell as text. */
    private suspend fun rows(sql: String): List<List<String?>> = database.read(
        buildJsonObject {
            put("sql", sql)
            put("values", JsonArray(emptyList()))
            put("max_rows", 1024)
        },
    ).getValue("rows").jsonArray.map { row -> row.jsonArray.map { cell -> (cell as? JsonObject)?.get("value")?.jsonPrimitive?.contentOrNull } }

    private fun scalar(sql: String): Long {
        val process = ProcessBuilder("sqlite3", "-readonly", file!!.path, sql).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText().trim()
        check(process.waitFor() == 0) { "SQLite inspection failed: $output" }
        return output.toLong()
    }

    suspend fun close() {
        try {
            room?.close()
        } finally {
            try {
                attached?.close()
            } finally {
                runtime?.close()
            }
        }
        attached = null
        room = null
        runtime = null
    }
}

private fun randomTenant() = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }

private fun TipsState.json() = buildJsonObject {
    put("bookmark", bookmark)
    put("tip", tip)
    put("operationsSinceSeal", operationsSinceSeal.toLong())
    put("bookmarks", JsonObject(bookmarks.associate { it.name to JsonPrimitive(it.tip) }))
    put("losers", JsonObject(losers.associate { it.name to JsonPrimitive(it.tip) }))
    put(
        "path",
        JsonArray(
            path.map {
                buildJsonObject {
                    put("id", it.id)
                    put("tip", it.tip)
                    put("held", it.held?.name)
                    put("closed", it.closed)
                }
            },
        ),
    )
    put("held", held.size)
    put("pendingFollow", pendingFollow)
}
