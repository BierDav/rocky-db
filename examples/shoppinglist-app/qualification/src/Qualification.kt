package org.example.examples.shopping.qualification

import kotlinx.serialization.json.*
import org.example.examples.shopping.data.db.ShoppingSchema
import java.io.File
import java.lang.management.ManagementFactory
import java.net.DatagramSocket
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/**
 * Multi-process shopping qualification. Every device is its own JVM running the app's Room repository on Rocky's
 * file over isolated iroh; the custody peer is the packaged `rocky-peer` launcher. The application contains no Rust source.
 *
 * `ROCKY_PEER` names the `rocky-peer` executable; `ROCKY_EVIDENCE` the directory for logs and `evidence.json`.
 * With `ROCKY_PHONES`, it drives two Android devices instead ([phones]); `live-links …` runs the live-link
 * qualification instead ([liveLinks]); `required-schema` runs the schema preflight ([requiredSchema]).
 * See docs/runtime/shopping-qualification.md.
 */
fun main(args: Array<String>) {
    if (args.firstOrNull() == "live-links") return liveLinks(args.drop(1))
    if (args.firstOrNull() == "required-schema") return requiredSchema()
    // One device process on stdin and stdout, for driving devices by hand next to a phone.
    if (args.firstOrNull() == "device") return main()
    val peer = File(System.getenv("ROCKY_PEER") ?: error("set ROCKY_PEER to the rocky-peer executable"))
    check(peer.canExecute()) { "$peer is not executable" }
    val evidence = File(System.getenv("ROCKY_EVIDENCE") ?: Files.createTempDirectory("shopping-qualification").toString())
    evidence.mkdirs()
    if (System.getenv("ROCKY_PHONES") != null) return phones(peer, evidence)
    val only = System.getenv("ROCKY_SCENARIOS")?.split(",")?.toSet()
    val results = mutableListOf<JsonObject>()
    var failed = false
    for ((name, scenario) in scenarios) {
        if (only != null && name !in only) continue
        val root = File(evidence, name).apply {
            deleteRecursively()
            mkdirs()
        }
        val started = System.nanoTime()
        val notes = mutableListOf<String>()
        val error = runCatching {
            Run(root, peer, notes).use {
                var failure = runCatching { scenario(it) }.exceptionOrNull()
                fun audit(block: () -> Unit) {
                    runCatching(block).exceptionOrNull()?.let { error ->
                        failure?.addSuppressed(error) ?: run { failure = error }
                    }
                }
                audit { it.absentTables() }
                if (name == "gate") {
                    audit {
                        val findings = it.auditMemberDirectory()
                        expect(findings.isEmpty()) { "Member directory names another device: $findings" }
                    }
                }
                failure?.let { throw it }
            }
        }.exceptionOrNull()
        val millis = (System.nanoTime() - started) / 1_000_000
        failed = failed || error != null
        println("${if (error == null) "PASS" else "FAIL"} $name ($millis ms)${error?.let { ": ${it.message}${it.cause?.let { cause -> " (${cause.message})" } ?: ""}" } ?: ""}")
        notes.forEach { println("  $it") }
        results += buildJsonObject {
            put("scenario", name)
            put("passed", error == null)
            put("milliseconds", millis)
            put("notes", JsonArray(notes.map(::JsonPrimitive)))
            error?.let { put("error", it.stackTraceToString()) }
        }
    }
    File(evidence, "evidence.json").writeText(JsonArray(results).toString())
    println("evidence: ${File(evidence, "evidence.json")}")
    if (failed) kotlin.system.exitProcess(1)
}

private val scenarios: List<Pair<String, (Run) -> Unit>> = listOf(
    "gate" to Run::gate,
    "exclusion-revocation" to Run::exclusionAndRevocation,
    "relink" to Run::relink,
    "creator-loss" to Run::creatorLoss,
    "seals" to Run::seals,
    "branch" to Run::branch,
    "publish" to Run::publish,
    "race-rollback" to Run::raceAndRollback,
)

// iroh binds UDP.
private fun freePort() = DatagramSocket(0).use { it.localPort }
private fun json(value: Any?): JsonElement = when (value) {
    null -> JsonNull
    is JsonElement -> value
    is String -> JsonPrimitive(value)
    is Number -> JsonPrimitive(value)
    is Boolean -> JsonPrimitive(value)
    is Collection<*> -> JsonArray(value.map(::json))
    else -> error("unsupported $value")
}
private val JsonElement.asLong: Long get() = jsonPrimitive.long
private fun expect(condition: Boolean, message: () -> String) {
    if (!condition) throw AssertionError(message())
}

private fun ByteArray.containsBytes(needle: ByteArray): Boolean = needle.isNotEmpty() &&
    indices.any { start -> start + needle.size <= size && needle.indices.all { this[start + it] == needle[it] } }

/** One device process. */
internal class Device(val name: String, private val root: File) : AutoCloseable {
    private val log = File(root, "$name.log")
    private val process = ProcessBuilder(
        listOf(ProcessHandle.current().info().command().get()) +
            ManagementFactory.getRuntimeMXBean().inputArguments.filterNot { it.startsWith("-agentlib") || it.startsWith("-javaagent") } +
            listOf("-cp", System.getProperty("java.class.path"), "org.example.examples.shopping.qualification.DeviceKt"),
    ).redirectError(ProcessBuilder.Redirect.appendTo(log)).start()
    private val input = process.outputStream.bufferedWriter()
    private val output = process.inputStream.bufferedReader()
    val directory = File(root, name)
    val listen = "127.0.0.1:0"
    lateinit var node: String
    val alive: Boolean get() = process.isAlive

    fun call(op: String, vararg args: Pair<String, Any?>): JsonElement {
        val request = buildJsonObject {
            put("op", op)
            args.forEach { (key, value) -> put(key, json(value)) }
        }
        input.write(request.toString())
        input.newLine()
        input.flush()
        while (true) {
            val line = output.readLine() ?: error("$name exited during $op; see $log")
            if (!line.startsWith(REPLY)) {
                log.appendText(line + "\n")
                continue
            }
            val reply = Json.parseToJsonElement(line.removePrefix(REPLY)).jsonObject
            reply["error"]?.let { throw IllegalStateException("$name $op: ${it.jsonPrimitive.content}") }
            return reply.getValue("ok")
        }
    }
    fun open(op: String, vararg args: Pair<String, Any?>) = apply {
        node = call(op, "directory" to directory.path, "listen" to listen, *args).jsonObject.getValue("node").jsonPrimitive.content
    }
    fun contact() = call("contact").jsonObject.getValue("uri").jsonPrimitive.content
    fun online(online: Boolean) = call("online", "online" to online)

    /** One sync pass that must reach a peer; returns each peer's state. */
    fun sync(): JsonObject = call("sync").jsonObject.also {
        expect(it.getValue("peers").jsonArray.any { peer -> peer.jsonObject.getValue("attempts").jsonArray.any { attempt -> attempt.jsonObject["operation"]?.jsonPrimitive?.content == "Reconcile" && attempt.jsonObject["outcome"]?.jsonPrimitive?.content == "Completed" } }) { "$name sync: $it" }
    }
    fun items(list: Long): List<String> = call("items", "list" to list).jsonArray.map { item ->
        val fields = item.jsonObject
        buildString {
            append(fields.getValue("title").jsonPrimitive.content)
            if (fields.getValue("completed").jsonPrimitive.boolean) append(" [x]")
            fields["categories"]?.jsonArray?.forEach { append(" #${it.jsonPrimitive.content}") }
        }
    }
    fun lists(): List<String> = call("lists").jsonArray.map { it.jsonPrimitive.content.substringAfter(':') }

    /** Shares [list] from this issuer; each reader's next sync delivers its envelope. */
    fun share(list: Long, vararg readers: Device) {
        call("share", "list" to list, "recipients" to readers.map { it.node })
    }

    fun absentTables() = call("absentTables")
    override fun close() {
        if (process.isAlive) runCatching { call("close") }
        if (!process.waitFor(30, TimeUnit.SECONDS)) process.destroyForcibly()
    }
}

/** The packaged custody launcher, configured as `docs/runtime/always-on-peer.md` describes. */
internal class Custody(private val root: File, private val binary: File, invitation: String, peers: List<String>) : AutoCloseable {
    private val config = File(root, "peer.json")
    private val log = File(root, "custody.log")
    private var process: Process? = null
    val listen = "127.0.0.1:${freePort()}"
    lateinit var contact: String
    init {
        config.writeText(
            buildJsonObject {
                put("directory", File(root, "custody").path)
                put("schema", Json.parseToJsonElement(ShoppingSchema.json()))
                put(
                    "transport",
                    buildJsonObject {
                        put("kind", "iroh")
                        put("relay", "disabled")
                        put("lookup", "disabled")
                        put("topic", false)
                        put("local", false)
                        put("bind", listen)
                    },
                )
                put("invitation", invitation)
                put("peers", JsonArray(peers.map(::JsonPrimitive)))
            }.toString(),
        )
        start()
    }
    fun start() {
        val started = ProcessBuilder(binary.path, config.path).redirectError(ProcessBuilder.Redirect.appendTo(log)).start()
        process = started
        contact = started.inputStream.bufferedReader().readLine() ?: error("rocky-peer exited; see $log")
        check(contact.startsWith("rocky://peer/")) { contact }
    }

    /** SIGTERM drains networking and flushes storage. */
    fun stop() {
        process?.let {
            it.destroy()
            check(it.waitFor(30, TimeUnit.SECONDS)) { "rocky-peer did not stop" }
        }
        process = null
    }

    /** Restarts with the persisted identity; the consumed invitation leaves the configuration. */
    fun restart() {
        stop()
        val stored = Json.parseToJsonElement(config.readText()).jsonObject
        config.writeText(JsonObject(stored - "invitation").toString())
        start()
    }
    override fun close() = stop()
}

internal class Run(val root: File, val peer: File, val notes: MutableList<String>) : AutoCloseable {
    private val opened = mutableListOf<AutoCloseable>()
    private val labels = mutableMapOf<String, String>()
    fun device(name: String) = Device(name, root).also { opened += it }
    fun custody(invitation: String, vararg devices: Device) = Custody(root, peer, invitation, devices.map { it.contact() }).also { opened += it }
    fun voters() = Voters(File(root, "voters").apply { mkdirs() }).also { opened += it }
    override fun close() {
        opened.asReversed().forEach { runCatching { it.close() } }
    }

    /** Records the literal directory audit even when an earlier functional step fails. */
    fun auditMemberDirectory(): List<String> {
        val member = opened.filterIsInstance<Device>().firstOrNull { it.name == "b" } ?: return emptyList()
        val foreign = opened.filterIsInstance<Device>().filter { it !== member }.map { it.node } +
            opened.filterIsInstance<Custody>().map {
                Json.parseToJsonElement(java.util.Base64.getUrlDecoder().decode(it.contact.substringAfter("rocky://peer/")).decodeToString()).jsonObject.getValue("node").jsonPrimitive.content
            }
        val names = labels.filterKeys { it != member.node }.flatMap { (_, name) ->
            listOf(
                name,
                buildJsonObject {
                    put("name", name)
                    put("kind", "full")
                }.toString(),
            )
        }
        val protocolKeys = mutableListOf<String>()
        val findings = member.directory.walkTopDown().filter { it.isFile }.flatMap { file ->
            val bytes = file.readBytes()
            val keys = foreign.filter { key ->
                key.length == 64 && (bytes.containsBytes(key.encodeToByteArray()) || bytes.containsBytes(key.chunked(2).map { it.toInt(16).toByte() }.toByteArray()))
            }.map { key -> "${file.relativeTo(member.directory)}: foreign node $key" }
            // Signed operations and credentials retain public signer keys. They are
            // protocol evidence, not the application's trusted device directory.
            protocolKeys += keys
            names.filter { bytes.containsBytes(it.encodeToByteArray()) }.map { "${file.relativeTo(member.directory)}: foreign label $it" }
        }.toList() +
            member.call("lists").jsonArray.flatMap { entry ->
                // Envelopes this member sent; it shared nothing, so it addresses no other device.
                val list = entry.jsonPrimitive.content.substringBefore(":").toLong()
                member.call("deliveries", "list" to list).jsonObject.keys.map { "list $list: envelope for $it" }
            }
        // The search must be able to see a name: the trusted device holds them in plaintext.
        val issuer = opened.filterIsInstance<Device>().first { it.name == "a" }
        val control = labels.values.filterNot { name ->
            issuer.directory.walkTopDown().filter { it.isFile }.any { it.readBytes().containsBytes(name.encodeToByteArray()) }
        }.map { "control: trusted device holds no $it" }
        File(root, "member-privacy.json").writeText(JsonArray((findings + control).map(::JsonPrimitive)).toString())
        File(root, "member-protocol-keys.json").writeText(JsonArray(protocolKeys.map(::JsonPrimitive)).toString())
        notes += "member-directory audit (${names.size / 2} foreign labels, sent envelopes): ${findings.size} matches; ${protocolKeys.size} files retain public protocol keys"
        return findings + control
    }

    /** Removed tables are absent; a member cannot query the trusted roster either. */
    fun absentTables() {
        val devices = opened.filterIsInstance<Device>().filter { it.alive }
        val checks = devices.associate { it.name to it.absentTables() }
        File(root, "member-tables.json").writeText(JsonObject(checks).toString())
        for ((name, value) in checks) {
            val check = value.jsonObject
            expect(check.getValue("sql").jsonObject.values.all { "no such table" in it.jsonPrimitive.content }) { "$name SQL table absence: $check" }
            expect(check.getValue("physical").jsonArray.none { it.jsonPrimitive.content in check.getValue("sql").jsonObject.keys }) { "$name still has physical roster tables: $check" }
        }
        notes += "removed tables absent on ${devices.size} devices"
    }

    /** An issuer and two enrolled writers that reach each other directly. */
    fun phones(): Triple<Device, Device, Device> {
        val a = device("a").open("create")
        val b = device("b").open("join", "invitation" to a.call("pairing", "profile" to "writer").jsonPrimitive.content)
        val c = device("c").open("join", "invitation" to a.call("pairing", "profile" to "writer").jsonPrimitive.content)
        for (writer in listOf(b, c)) {
            writer.sync()
        }
        return Triple(a, b, c)
    }

    /**
     * The release gate: phones A and B are never online together and meet only the custody process. A duplicate
     * title drops the transaction replayed later, a move drops an earlier offline tick, a deleted category deletes only its links,
     * a deleted list cascades, and an offline phone catches up after the deletes.
     */
    fun gate() {
        val a = device("a").open("create")
        fun writer(name: String): Device {
            val writer = device(name)
            val keys = writer.call("prepare", "directory" to writer.directory.path)
            writer.open("install", "supplied" to a.call("grantWriter", "device" to keys))

            return writer
        }
        val b = writer("b")
        val c = writer("c")
        // A names both writers as the Devices tab does; B must never hold C's name or label.
        for (writer in listOf(b, c)) {
            val label = "Gate phone ${writer.name}"
            a.call("label", "device" to writer.node, "name" to label, "kind" to "full")
            labels[writer.node] = label
        }
        c.call("addPeer", "contact" to a.contact())
        val custody = custody(a.call("pairing", "profile" to "custody").jsonPrimitive.content, a, b, c)
        for (phone in listOf(a, b, c)) phone.call("addPeer", "contact" to custody.contact)
        val weekly = a.call("createList", "title" to "Weekly").asLong
        val weekend = a.call("createList", "title" to "Weekend").asLong
        val party = a.call("createList", "title" to "Party").asLong
        val dairy = a.call("addCategory", "list" to weekly, "name" to "Dairy").asLong
        val milk = a.call("add", "list" to weekly, "title" to "Milk", "category" to dairy).asLong
        a.call("add", "list" to weekly, "title" to "Butter", "category" to dairy)
        a.call("add", "list" to party, "title" to "Cake")
        val lists = listOf(weekly, weekend, party)
        // The Share button: every enrolled reading device, never the custody peer; sync delivers the envelopes.
        for (list in lists) {
            val shared = a.call("shareWithDevices", "list" to list).jsonArray.map { it.jsonPrimitive.content }
            expect(shared.toSet() == setOf(b.node, c.node)) { "shared with $shared" }
        }

        // C joins every list from A's checkpoints, then stays offline.
        b.online(false)
        a.sync()
        c.sync()
        c.online(false)
        expect(lists.all { c.items(it) == a.items(it) }) { "C did not catch up" }
        notes += "C started 3 lists from checkpoints"

        fun relay(from: Device, to: Device) {
            to.online(false)
            from.online(true)
            from.sync()
            from.online(false)
            to.online(true)
            to.sync()
        }
        relay(a, b)
        expect(lists.all { b.items(it) == a.items(it) }) { "B differs after custody relay" }

        // Offline from each other: B ticks Milk and adds Bread; A adds Bread and moves Milk to the weekend.
        b.call("check", "list" to weekly, "id" to milk, "completed" to true)
        b.call("add", "list" to weekly, "title" to "Bread")
        b.sync()
        b.online(false)
        // The custody process restarts with its persisted identity and the lists it learned.
        custody.restart()
        for (phone in listOf(a, b)) phone.call("addPeer", "contact" to custody.contact)
        a.online(true)
        a.call("add", "list" to weekly, "title" to "Bread")
        a.call("move", "from" to weekly, "id" to milk, "to" to weekend)
        relay(a, b)
        relay(b, a)
        // The move inserted the values A read: B's tick, ordered before it, stays with the deleted row.
        val moved = mapOf(weekly to listOf("Bread", "Butter #$dairy"), weekend to listOf("Milk"), party to listOf("Cake"))
        for (phone in listOf(a, b)) expect(lists.associateWith { phone.items(it) } == moved) { "${phone.name}: ${lists.map { phone.items(it) }}" }
        notes += "duplicate title kept one Bread; the moved Milk left B's offline tick and its category behind"

        a.online(true)
        a.call("deleteCategory", "list" to weekly, "category" to dairy)
        a.call("deleteList", "list" to party)
        relay(a, b)
        val deleted = mapOf(weekly to listOf("Bread", "Butter"), weekend to listOf("Milk"), party to emptyList())
        expect(lists.associateWith { b.items(it) } == deleted) { "B after deletes: ${lists.map { b.items(it) }}" }
        expect(b.lists().sorted() == listOf("Weekend", "Weekly")) { "B lists: ${b.lists()}" }
        notes += "category delete removed only its links; deleting Party cascaded to its items"

        c.online(true)
        repeat(2) { c.sync() }
        expect(lists.associateWith { c.items(it) } == deleted) { "C after catch-up: ${lists.map { c.items(it) }}" }
        expect(c.lists().sorted() == listOf("Weekend", "Weekly")) { "C lists: ${c.lists()}" }
        notes += "long-offline C caught up to the deleted state"

        b.call("add", "list" to weekend, "title" to "Eggs")
        relay(b, a)
        expect(a.items(weekend) == listOf("Eggs", "Milk")) { "A after catch-up: ${a.items(weekend)}" }
    }

    /** Scenario 2: a list shared with B and not C never reaches C; revoking C rotates the list it held. */
    fun exclusionAndRevocation() {
        val (a, b, c) = phones()
        val private = a.call("createList", "title" to "Private").asLong
        val shared = a.call("createList", "title" to "Shared").asLong
        a.call("add", "list" to private, "title" to "Gift")
        a.call("add", "list" to shared, "title" to "Milk")
        a.share(private, b)
        a.share(shared, b, c)
        b.sync()
        c.sync()
        expect(b.lists().sorted() == listOf("Private", "Shared")) { "B lists ${b.lists()}" }
        expect(c.lists() == listOf("Shared")) { "C lists ${c.lists()}" }
        val unheld = c.call("status", "list" to private).jsonObject
        expect(
            unheld.getValue("tables").jsonArray.none { it.jsonObject["holding"]?.jsonPrimitive?.contentOrNull == "held" } &&
                unheld["epochs"].let { it == null || it is JsonNull || (it is JsonArray && it.isEmpty()) || (it is JsonObject && it.isEmpty()) },
        ) {
            "C holds Private: $unheld"
        }
        expect(c.items(private).isEmpty()) { "C reads Private" }
        notes += "C holds no table or secret epoch of Private"

        val before = a.call("status", "list" to shared).jsonObject.getValue("epochs")
        a.call("revoke", "node" to c.node)
        val after = a.call("status", "list" to shared).jsonObject.getValue("epochs")
        expect(before != after) { "revocation did not rotate Shared: $before -> $after" }
        notes += "revocation rotated Shared: epochs $before -> $after"
        // Revocation rotates every list C could read and seals each new epoch to the remaining readers itself.
        a.call("add", "list" to shared, "title" to "After revocation")
        b.sync()
        expect(b.items(shared) == listOf("After revocation", "Milk")) { "B ${b.items(shared)}" }
        expect(runCatching { c.call("sync") }.isFailure) { "a revoked device still syncs" }
        expect(c.items(shared) == listOf("Milk")) { "C read a row after its revocation: ${c.items(shared)}" }
        notes += "revoked C cannot sync and never reads rows written after revocation"
    }

    /** Scenario 3: an item deleted and added again while another device edits the old row offline. */
    fun relink() {
        val (a, b, _) = phones()
        val list = a.call("createList", "title" to "Weekly").asLong
        val milk = a.call("add", "list" to list, "title" to "Milk").asLong
        a.share(list, b)
        b.sync()
        b.online(false)
        b.call("check", "list" to list, "id" to milk, "completed" to true)
        a.call("delete", "list" to list, "id" to milk)
        a.call("add", "list" to list, "title" to "Milk")
        b.online(true)
        repeat(2) { b.sync() }
        expect(a.items(list) == listOf("Milk") && b.items(list) == a.items(list)) { "A ${a.items(list)} B ${b.items(list)}" }
        notes += "the relinked Milk converged unticked: the edit to the deleted row matches nothing"
    }

    /** Scenario 4: the creator device is lost; a second issuer revokes it, invites, shares and renews. */
    fun creatorLoss() {
        val a = device("a").open("create")
        val d = device("d").open("join", "invitation" to a.call("pairing", "profile" to "issuer").jsonPrimitive.content)
        d.sync()
        val list = a.call("createList", "title" to "Groceries").asLong
        a.call("add", "list" to list, "title" to "Milk")
        a.share(list, d)
        d.sync()
        a.close()
        expect(a.directory.deleteRecursively()) { "creator directory remains" }
        d.call("revoke", "node" to a.node)
        val e = device("e").open("join", "invitation" to d.call("pairing", "profile" to "writer").jsonPrimitive.content)
        e.sync()
        d.share(list, e)
        e.sync()
        expect(e.items(list) == listOf("Milk")) { "E ${e.items(list)}" }
        e.call("renew")
        e.call("add", "list" to list, "title" to "Eggs")
        e.sync()
        expect(d.items(list) == listOf("Eggs", "Milk")) { "D ${d.items(list)}" }
        notes += "second issuer D revoked the lost creator, invited E, shared the rotated list and renewed E"
    }
}
