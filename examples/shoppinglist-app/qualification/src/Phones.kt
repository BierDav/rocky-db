package org.example.examples.shopping.qualification

import kotlinx.serialization.json.*
import java.io.File
import java.net.URLEncoder
import java.util.concurrent.TimeUnit

private const val PACKAGE = "org.example.examples"
private const val TAG = "RockyShopping"

/** One Android device running the debug shopping app, driven by its `rocky-shopping://drive` links; results are read from logcat. */
internal class Phone(val name: String, val serial: String, private val log: File) {
    private var step = 0
    private val runId = java.util.UUID.randomUUID().toString()
    fun adb(vararg args: String, strict: Boolean = true): String {
        val process = ProcessBuilder(listOf("adb", "-s", serial) + args).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor(120, TimeUnit.SECONDS)) { "adb ${args.joinToString(" ")} timed out" }
        if (strict && process.exitValue() != 0) error("adb ${args.joinToString(" ")}: $output")
        return output
    }
    fun property(name: String) = adb("shell", "getprop", name).trim()

    /** Retried writes: each timed out (code 4) while background sync held the replica, and was rolled back. */
    val retries = mutableListOf<String>()

    /** Opens one drive link and waits for its `done` line; returns the app's log lines for it. */
    fun send(vararg parameters: Pair<String, String>, timeoutSeconds: Long = 120): List<String> {
        repeat(3) {
            try {
                return attempt(parameters, timeoutSeconds)
            } catch (busy: Busy) {
                retries += "${parameters.toList()}: ${busy.message}"
            }
        }
        return attempt(parameters, timeoutSeconds)
    }
    private class Busy(message: String) : Exception(message)
    private fun attempt(parameters: Array<out Pair<String, String>>, timeoutSeconds: Long): List<String> {
        val marker = "$name-$runId-${++step}"
        // `adb shell` passes one command line to the device shell: quote the link, whose values are URL-encoded.
        val query = (parameters.toList() + ("step" to marker)).joinToString("&") { (key, value) -> "$key=${URLEncoder.encode(value, "UTF-8")}" }
        adb("shell", "am", "start", "-a", "android.intent.action.VIEW", "-p", PACKAGE, "-d", "'rocky-shopping://drive?$query'")
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
        while (System.nanoTime() < deadline) {
            val lines = adb("logcat", "-d", "-v", "raw", "-s", "$TAG:I").lines()
                .dropWhile { it != "started $marker" }.drop(1)
            lines.firstOrNull { it.startsWith("failed $marker") }?.let {
                if ("Error code: 4," in it) throw Busy(it)
                error("$name: $it")
            }
            if (lines.any { it == "done $marker" }) {
                log.appendText(lines.joinToString("\n", postfix = "\n"))
                return lines
            }
            Thread.sleep(250)
        }
        error("$name: no reply to ${parameters.toList()} within $timeoutSeconds s")
    }

    /** `list title -> items`, each `title` or `title [x]`. */
    fun dump(): Map<String, List<String>> = send("dump" to "1").filter { it.startsWith("dump ") }.associate { line ->
        val (title, items) = line.removePrefix("dump ").split(": ", limit = 2)
        title to items.split(",").filter { it.isNotEmpty() }.sorted()
    }
}

/**
 * The release gate's sharing and move steps on two Android devices with a host issuer and the packaged custody
 * peer. `ROCKY_PHONES` names two adb serials and `ROCKY_APK` the app; both reach the host through `adb reverse`.
 */
internal fun phones(peer: File, evidence: File) {
    val serials = System.getenv("ROCKY_PHONES").split(",").map { it.trim() }
    require(serials.size == 2) { "ROCKY_PHONES names two adb serials" }
    val apk = File(System.getenv("ROCKY_APK") ?: error("set ROCKY_APK to the shopping app's APK"))
    val root = File(evidence, "phones").apply {
        deleteRecursively()
        mkdirs()
    }
    val notes = mutableListOf<String>()
    val started = System.nanoTime()
    fun elapsed() = (System.nanoTime() - started) / 1_000_000
    val (a, b) = serials.mapIndexed { index, serial -> Phone("phone-${'a' + index}", serial, File(root, "phone-${'a' + index}.log")) }
    val devices = listOf(a, b).associate { phone ->
        phone.name to buildJsonObject {
            put("serial", phone.serial)
            put("model", phone.property("ro.product.model"))
            put("sdk", phone.property("ro.build.version.sdk"))
            put("abi", phone.property("ro.product.cpu.abi"))
        }
    }
    val error = runCatching {
        Run(root, peer, notes).use { run ->
            val host = run.device("host").open("create")
            val hostPort = host.listen.substringAfterLast(':')
            for (phone in listOf(a, b)) {
                phone.adb("install", "-r", apk.path)
                phone.adb("shell", "pm", "clear", PACKAGE)
                phone.adb("shell", "pm", "grant", PACKAGE, "android.permission.ACCESS_LOCAL_NETWORK", strict = false)
                phone.adb("reverse", "tcp:$hostPort", "tcp:$hostPort")
                // A is trusted; B is a roster-free member.
                phone.send("invitation" to host.call("pairing", "profile" to if (phone == a) "issuer" else "writer").jsonPrimitive.content, "transport" to "tcp")
            }
            val contacts = listOf(a, b).associateWith { phone ->
                phone.send("contact" to "1").first { it.startsWith("contact ") }.split(" ").let { it[1] to it[2] }
            }
            val custody = run.custody(host.call("pairing", "profile" to "custody").jsonPrimitive.content, host)
            val custodyPort = custody.listen.substringAfterLast(':')
            for (phone in listOf(a, b)) {
                phone.adb("reverse", "tcp:$custodyPort", "tcp:$custodyPort")
                phone.send("peer" to custody.contact)
            }
            host.close()
            // The closed enrollment host is no longer a sync target.
            for (phone in listOf(a, b)) phone.send("forget" to host.node)
            notes += "${elapsed()} ms: both devices enrolled; the host issuer is closed"

            a.send("add" to "Milk", "list" to "Weekly")
            a.send("add" to "Eggs", "list" to "Weekend")
            val bNode = contacts.getValue(b).first
            for (list in listOf("Weekly", "Weekend")) {
                // A learns B from the replicated issuer registry, without a reciprocal contact.
                check(a.send("share" to list, "to" to bNode).any { it == "share $bNode" }) { "A did not share $list" }
            }
            fun relay(from: Phone, to: Phone) {
                to.send("online" to "false")
                from.send("online" to "true", "sync" to "1")
                from.send("online" to "false")
                to.send("online" to "true", "sync" to "1")
            }
            relay(a, b)
            val shared = mapOf("Weekend" to listOf("Eggs"), "Weekly" to listOf("Milk"))
            check(b.dump() == shared) { "B: ${b.dump()} ${b.send("status" to "1").filter { it.startsWith("status ") }}" }
            notes += "${elapsed()} ms: B received both lists through custody only"

            b.send("check" to "Milk", "add" to "Bread", "list" to "Weekly", "sync" to "1")
            b.send("online" to "false")
            a.send("online" to "true")
            a.send("add" to "Bread", "list" to "Weekly")
            a.send("move" to "Milk", "to" to "Weekend")
            relay(a, b)
            relay(b, a)
            val converged = mapOf("Weekend" to listOf("Eggs", "Milk"), "Weekly" to listOf("Bread"))
            check(a.dump() == converged) { "A: ${a.dump()}" }
            check(b.dump() == converged) { "B: ${b.dump()}" }
            notes += "${elapsed()} ms: one Bread survived; the moved Milk left B's earlier offline tick behind on both devices"
            // The member scans A's contact and delegates an already held list; no registry access is used.
            check(b.send("share" to "Weekly", "recipientContact" to contacts.getValue(a).second, "online" to "true", "sync" to "1").any { it == "share ${contacts.getValue(a).first}" })
            notes += "${elapsed()} ms: member B shared Weekly with scanned contact A"
            a.send("revoke" to bNode, "sync" to "1")
            val revoked = b.send("online" to "true", "sync" to "1")
            check(revoked.any { it.startsWith("sync Revoked") }) { "B did not report revocation: $revoked" }
            notes += "${elapsed()} ms: trusted A revoked member B through custody"
        }
    }.exceptionOrNull()
    val result = buildJsonObject {
        put("scenario", "phones")
        put("passed", error == null)
        put("milliseconds", elapsed())
        put("devices", JsonObject(devices))
        put("notes", JsonArray(notes.map(::JsonPrimitive)))
        put("retried", JsonArray((a.retries + b.retries).map(::JsonPrimitive)))
        error?.let { put("error", it.stackTraceToString()) }
    }
    File(evidence, "phones.json").writeText(result.toString())
    println("${if (error == null) "PASS" else "FAIL"} phones (${elapsed()} ms)${error?.let { ": ${it.message}" } ?: ""}")
    notes.forEach { println("  $it") }
    (a.retries + b.retries).forEach { println("  retried $it") }
    devices.forEach { (name, device) -> println("  $name: $device") }
    if (error != null) kotlin.system.exitProcess(1)
}
