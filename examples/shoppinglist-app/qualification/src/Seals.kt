package org.example.examples.shopping.qualification

import kotlinx.serialization.json.*

/*
 * Phase 20's seal scenarios: compaction and kept seals, a dev branch, a schema tried and published offline, and
 * concurrent publication with a rollback. See docs/features_09/20-seal-qualification.md.
 */

private val JsonElement.text: String get() = jsonPrimitive.content
private fun JsonObject.text(name: String): String? = get(name)?.jsonPrimitive?.contentOrNull
private fun expect(condition: Boolean, message: () -> String) {
    if (!condition) throw AssertionError(message())
}

/** Milliseconds [block] took, with its result. */
private inline fun <T> timed(block: () -> T): Pair<T, Long> {
    val started = System.nanoTime()
    val result = block()
    return result to (System.nanoTime() - started) / 1_000_000
}

internal fun Device.tips(): JsonObject = call("tips").jsonObject
internal fun Device.bookmark(): String? = tips().text("bookmark")
internal fun Device.tip(): String = tips().text("tip")!!
internal fun Device.storage(): JsonObject = call("storage").jsonObject
internal fun Device.maintain(sealAfter: Long? = null): JsonObject = call("maintain", "sealAfter" to sealAfter).jsonObject

/** Syncs [rounds] times, tolerating passes that reach no peer, as an offline or switching device does. */
internal fun Device.settle(rounds: Int = 2) = repeat(rounds) { runCatching { call("sync") } }

/** Retries [block] with sync passes on [devices] in between; fails with its last error. */
internal fun <T> retrying(what: String, vararg devices: Device, attempts: Int = 60, block: () -> T): T {
    var last: Throwable? = null
    repeat(attempts) {
        try {
            return block()
        } catch (error: Exception) {
            last = error
        }
        devices.forEach { it.settle(1) }
        Thread.sleep(250)
    }
    throw AssertionError("gave up on $what", last)
}

/** Polls [condition] with sync passes on [devices] in between; a timeout reports each device's tips and generation. */
internal fun eventually(what: String, vararg devices: Device, attempts: Int = 60, condition: () -> Boolean) {
    repeat(attempts) {
        if (condition()) return
        devices.forEach { it.settle(1) }
        Thread.sleep(250)
    }
    expect(condition()) {
        "timed out waiting for $what; " +
            devices.joinToString("; ") { device ->
                "${device.name}: ${runCatching { device.tips() }.getOrElse { it.message }} ${runCatching { device.call("generation") }.getOrElse { it.message }}"
            }
    }
}

/**
 * A trusted desktop that founds the household and full members that join it, each list shared with them, as the
 * app's Devices tab shares every list with full devices.
 */
internal fun Run.household(vararg members: String, coordinator: String? = null): List<Device> {
    val trusted = device("trusted").open("create", "coordinator" to coordinator)
    val joined = members.map { name ->
        // As the app does: only trusted devices compose the coordination service.
        device(name).open("join", "invitation" to trusted.call("pairing", "profile" to "writer").text)
    }
    joined.forEach { it.sync() }
    return listOf(trusted) + joined
}

internal fun Run.shareAll(trusted: Device, list: Long, vararg members: Device) {
    trusted.share(list, *members)
    members.forEach { it.settle() }
}

/**
 * Slice 1: the app's seal policy on the trusted desktop, compaction on every device, and kept seals. The phone is
 * offline across one seal and returns; the trusted desktop shows the list as it was two seals ago.
 */
internal fun Run.seals() {
    val (trusted, member, phone) = household("member", "phone")
    val weekly = trusted.call("createList", "title" to "Weekly").jsonPrimitive.long
    for (title in listOf("Milk", "Eggs", "Flour")) trusted.call("add", "list" to weekly, "title" to title)
    shareAll(trusted, weekly, member, phone)
    eventually("both members to hold Weekly", member, phone) { member.items(weekly).size == 3 && phone.items(weekly).size == 3 }

    val (first, sealing) = timed { trusted.call("seal").text }
    val eggs = trusted.call("items", "list" to weekly).jsonArray.single { it.jsonObject.getValue("title").text == "Eggs" }.jsonObject.getValue("id").jsonPrimitive.long
    trusted.call("delete", "list" to weekly, "id" to eggs)
    trusted.call("add", "list" to weekly, "title" to "Bread")
    // The policy, with a threshold this scenario reaches: a round seals once enough writes gathered.
    val second = trusted.maintain(sealAfter = 2).text("sealed") ?: throw AssertionError("the policy did not seal")
    expect(trusted.maintain(sealAfter = 2).text("sealed") == null) { "the policy sealed without new writes" }
    eventually("both members to adopt the second seal", member, phone) { member.tip() == trusted.tip() && phone.tip() == trusted.tip() }
    phone.online(false)
    trusted.call("add", "list" to weekly, "title" to "Jam")
    member.call("check", "list" to weekly, "id" to trusted.call("items", "list" to weekly).jsonArray.single { it.jsonObject.getValue("title").text == "Milk" }.jsonObject.getValue("id").jsonPrimitive.long, "completed" to true)
    member.settle()
    trusted.settle()
    val third = trusted.call("seal").text
    val (_, adoption) = timed { eventually("the member to adopt the third seal", member) { member.tip() == trusted.tip() } }
    notes += "seals: first $sealing ms to seal; the member adopted a seal in $adoption ms"

    // Compaction keeps one seal uncompacted: at the third seal, every device compacts at the second.
    notes += "member before compacting: ${member.storage()}"
    val (memberRound, memberCompaction) = timed { member.maintain() }
    notes += "member compaction round: $memberRound"
    expect(memberRound.text("compacted") == second) { "member compacted at ${memberRound.text("compacted")}, not $second" }
    expect(memberRound.getValue("pruned").jsonPrimitive.long > 0) { "the member released nothing: $memberRound" }
    phone.online(true)
    eventually("the phone to return to the third seal", phone, trusted) { phone.tip() == trusted.tip() }
    notes += "phone before compacting: ${phone.storage()}"
    val (phoneRound, phoneCompaction) = timed { phone.maintain() }
    expect(phoneRound.text("compacted") == second) { "phone compacted at ${phoneRound.text("compacted")}, not $second" }
    expect(phoneRound.getValue("pruned").jsonPrimitive.long > 0) { "the phone released nothing: $phoneRound" }
    val trustedRound = trusted.maintain()
    notes += "compaction: member $memberCompaction ms, phone $phoneCompaction ms; trusted $trustedRound"

    val expected = listOf("Bread", "Flour", "Jam", "Milk [x]")
    for (device in listOf(trusted, member, phone)) {
        eventually("${device.name} to read the sealed lists", device, trusted) { device.items(weekly) == expected }
    }
    for (device in listOf(member, phone)) {
        val storage = device.storage()
        expect(storage.getValue("tombstones").jsonPrimitive.long == 0L) { "${device.name} keeps tombstones after compacting: $storage" }
        notes += "${device.name} after compaction: $storage"
    }
    notes += "trusted keeps every seal: ${trusted.storage()}"

    // The trusted desktop keeps every seal and reads earlier ones through read-only views.
    val held = trusted.tips().getValue("path").jsonArray.associate { it.jsonObject.text("id")!! to it.jsonObject.text("held") }
    expect(listOf(first, second, third).all { held[it] == "KEPT" }) { "trusted holds $held" }
    fun view(seal: String) = timed { trusted.call("snapshot", "seal" to seal).jsonArray.single().jsonObject.getValue("items").jsonArray.map { it.text }.sorted() }
    val (twoAgo, viewing) = view(second)
    expect(twoAgo == listOf("Bread", "Flour", "Milk")) { "two seals ago read $twoAgo" }
    val (threeAgo, _) = view(first)
    expect(threeAgo == listOf("Eggs", "Flour", "Milk")) { "three seals ago read $threeAgo" }
    notes += "kept seals: two seals ago read $twoAgo through a view in $viewing ms; three seals ago $threeAgo"
}

/**
 * Slice 2: the trusted desktop opens `dev` on main's latest seal, the member follows it, and both write. The phone on `main` receives nothing of dev; the member returns and
 * drops it.
 */
internal fun Run.branch() {
    val (trusted, member, phone) = household("member", "phone", coordinator = voters().bundle.path)
    trusted.call("register")
    val weekly = trusted.call("createList", "title" to "Weekly").jsonPrimitive.long
    trusted.call("add", "list" to weekly, "title" to "Milk")
    shareAll(trusted, weekly, member, phone)
    // Sealed first, so dev opens on main's latest seal while main's tip and its log stay open.
    trusted.call("seal")
    // A decision on main, which dev never shows to main's devices.
    val onMain = member.call("ask", "title" to "Paint").text
    retrying("a decision on main", trusted, member) { trusted.call("decide", "key" to onMain) }
    val mainLog = trusted.call("coordinated").text
    eventually("both members to hold Weekly and main's decision", member, phone, trusted) {
        listOf(member, phone).all { it.items(weekly) == listOf("Milk") && it.call("decisions").jsonArray.map { key -> key.text } == listOf(onMain) }
    }

    val (dev, opening) = timed { trusted.call("branch", "name" to "dev").text }
    expect(trusted.bookmark() == "dev") { "trusted follows ${trusted.bookmark()}" }
    eventually("the member to learn dev", member, trusted) { member.tips().getValue("bookmarks").jsonObject.containsKey("dev") }
    val (_, switching) = timed {
        member.call("follow", "name" to "dev")
        eventually("the member to switch to dev", member, trusted) {
            member.maintain()
            member.bookmark() == "dev"
        }
    }
    notes += "branch: opened dev in $opening ms; the member switched in $switching ms"
    trusted.call("add", "list" to weekly, "title" to "Trusted on dev")
    member.call("add", "list" to weekly, "title" to "Member on dev")
    eventually("both dev writes on both devices", trusted, member) {
        trusted.items(weekly) == listOf("Member on dev", "Milk", "Trusted on dev") && member.items(weekly) == trusted.items(weekly)
    }
    val onDev = member.call("ask", "title" to "Ladder").text
    retrying("a decision on dev", trusted, member) { trusted.call("decide", "key" to onDev) }
    val devLog = trusted.call("coordinated").text
    expect(devLog != mainLog) { "dev follows main's log $mainLog" }

    phone.call("add", "list" to weekly, "title" to "Phone on main")
    phone.settle(3)
    expect(phone.items(weekly) == listOf("Milk", "Phone on main")) { "the phone read ${phone.items(weekly)}" }
    val phoneTips = phone.storage().getValue("tips").jsonArray.map { it.text }
    expect(dev !in phoneTips) { "the phone holds frames of dev: $phoneTips" }
    expect(phone.call("decisions").jsonArray.map { it.text } == listOf(onMain)) { "the phone read decisions ${phone.call("decisions")}" }
    notes += "the phone on main holds frames of ${phoneTips.size} tips, none of dev, and only main's decision"

    member.settle()
    member.call("leave", "name" to "dev")
    trusted.call("leave", "name" to "dev", "delete" to true)
    expect(trusted.call("coordinated").text == mainLog) { "the trusted node follows ${trusted.call("coordinated")}, not main's log $mainLog" }
    for (device in listOf(trusted, member, phone)) {
        eventually("${device.name} to read main", device, trusted, phone) { device.items(weekly) == listOf("Milk", "Phone on main") }
        expect(device.call("decisions").jsonArray.map { it.text } == listOf(onMain)) { "${device.name} on main read decisions ${device.call("decisions")}" }
    }
    expect(dev !in member.storage().getValue("tips").jsonArray.map { it.text }) { "the member kept dev's frames after dropping it" }
    eventually("dev's deletion to reach the member", member, trusted) { !member.tips().getValue("bookmarks").jsonObject.containsKey("dev") }
    notes += "the trusted node follows main's log again; the member dropped dev and every device reads main"
}

/** Reopens under app version [app]; a new endpoint, so [peers] learn its contact again. */
internal fun Device.reopen(app: Int, vararg peers: Device, coordinator: String? = null) = apply {
    open("reopen", "app" to app, "coordinator" to coordinator)
    introduce(this, *peers)
}

/** Reopens under app version [app] without a network: what opening publishes stays here until [attach]. */
internal fun Device.reopenOffline(app: Int, coordinator: String? = null) = apply {
    call("shut")
    open("resumeOffline", "app" to app, "coordinator" to coordinator)
}

internal fun Device.attach(vararg peers: Device) = apply {
    call("attach", "listen" to listen)
    introduce(this, *peers)
}

internal fun introduce(device: Device, vararg peers: Device) {
    for (peer in peers) {
        peer.call("addPeer", "contact" to device.contact())
        device.call("addPeer", "contact" to peer.contact())
    }
}

internal fun Device.schemaVersion(): Long = call("generation").jsonObject.getValue("current").jsonObject.getValue("schema").jsonPrimitive.long
internal fun Device.categories(list: Long): List<String> = call("query", "sql" to "SELECT name FROM categories WHERE list = $list ORDER BY ${if (schemaVersion() >= 8) "position, " else ""}name, id").jsonArray.map { it.jsonArray[0].text }
internal fun Device.held(): JsonArray = call("held").jsonArray

/** An app version 7 household: a trusted desktop and full members, each list shared with them. */
internal fun Run.household7(vararg members: String, issuers: List<String> = emptyList()): List<Device> {
    val trusted = device("trusted").open("create", "app" to 7)
    val joined = issuers.map { name ->
        device(name).open("join", "invitation" to trusted.call("pairing", "profile" to "issuer").text, "app" to 7)
    } +
        members.map { name ->
            device(name).open("join", "invitation" to trusted.call("pairing", "profile" to "writer").text, "app" to 7)
        }
    joined.forEach { it.sync() }
    return listOf(trusted) + joined
}

/**
 * Slice 3: the trusted desktop tries app version 8's schema and migration on `dev`, then seals `main` and migrates it
 * with networking off, and publishes on reconnecting. The member, on app version 7, wrote `main` meanwhile: its write
 * comes back as a held change, which its app re-authors. The phone never fetched dev's schema.
 */
internal fun Run.publish() {
    val (trusted, member, phone) = household7("member", "phone")
    // Members find each other by discovery in the app; here, by contact.
    introduce(member, phone)
    val weekly = trusted.call("createList", "title" to "Weekly").jsonPrimitive.long
    for (name in listOf("Fruit", "Dairy", "Bakery")) trusted.call("addCategoryRaw", "list" to weekly, "name" to name)
    for (title in listOf("Milk", "Bread")) trusted.call("add", "list" to weekly, "title" to title)
    shareAll(trusted, weekly, member, phone)
    eventually("both members to hold Weekly", member, phone, trusted) { member.items(weekly).size == 2 && phone.items(weekly).size == 2 }

    // Tried on dev: app version 8 publishes its schema there, and its migration runs on dev's state.
    trusted.call("seal")
    trusted.call("branch", "name" to "dev")
    trusted.reopen(8, member, phone)
    expect(trusted.bookmark() == "dev" && trusted.schemaVersion() == 8L) { "dev did not migrate: ${trusted.call("generation")}" }
    val ordered = listOf("Bakery", "Dairy", "Fruit")
    expect(trusted.categories(weekly) == ordered) { "dev ordered ${trusted.categories(weekly)}" }
    member.settle(3)
    phone.settle(3)
    for (device in listOf(member, phone)) {
        val generation = device.call("generation").jsonObject
        expect(device.schemaVersion() == 7L && generation["pending"] == JsonNull) { "${device.name} on main saw dev's schema: $generation" }
    }
    notes += "tried: app version 8 migrated dev on the trusted desktop; main's devices stayed on schema 7 with nothing pending"

    // Published: main sealed, then migrated offline; the member writes main meanwhile.
    // Main's older schema replaces dev's at the end of the next sync pass; app version 8 is then ahead of it.
    expect(trusted.call("follow", "name" to "main").text == "Pending") { "following main: ${trusted.call("generation")}" }
    eventually("main's schema to replace dev's", trusted) { trusted.call("switched").text != "Pending" }
    expect(trusted.call("switched").text == "Ahead") { "after switching: ${trusted.call("generation")}" }
    trusted.call("seal")
    val (_, migrating) = timed { trusted.reopenOffline(8) }
    expect(trusted.bookmark() == "main" && trusted.schemaVersion() == 8L) { "main did not migrate offline: ${trusted.call("generation")}" }
    member.call("add", "list" to weekly, "title" to "Butter")
    eventually("the member's write to reach the phone on main", member, phone) { "Butter" in phone.items(weekly) }
    expect(phone.schemaVersion() == 7L && member.schemaVersion() == 7L) { "the offline migration left the trusted desktop" }
    notes += "published offline: the migration ran in $migrating ms with networking off; main's devices still on 7"

    val (_, adoption) = timed {
        trusted.attach(member, phone)
        eventually("the member and phone to follow schema 8", member, phone, trusted) { member.schemaVersion() == 8L && phone.schemaVersion() == 8L }
    }
    notes += "on reconnecting, the member and phone adopted schema 8 in $adoption ms"
    val held = member.held()
    expect(held.size == 1 && held.single().jsonObject.getValue("rows").jsonArray.any { "Butter" in it.text }) { "member held $held" }
    // The member's app is still version 7 and re-authors its write as a new one.
    member.call("reauthor", "id" to held.single().jsonObject.text("id"))
    expect(member.held().isEmpty()) { "the held change stayed" }
    val expected = listOf("Bread", "Butter", "Milk")
    for (device in listOf(trusted, member, phone)) {
        eventually("${device.name} to read the re-authored write", device, trusted, member) { device.items(weekly) == expected }
        expect(device.categories(weekly) == ordered) { "${device.name} ordered ${device.categories(weekly)}" }
    }
    trusted.call("leave", "name" to "dev", "delete" to true)
    notes += "held: the member's offline Butter came back held and its version 7 app re-authored it; every device reads $expected"
}

/**
 * Slice 4: two issuers publish different schemas at once and the household ends on one, the other listed as
 * `main/1`. Then an issuer seals `main` forward while the owner moves it back to the latest seal; every device
 * follows the owner.
 */
internal fun Run.raceAndRollback() {
    val (owner, left, right, member) = household7("member", issuers = listOf("left", "right"))
    val weekly = owner.call("createList", "title" to "Weekly").jsonPrimitive.long
    owner.call("add", "list" to weekly, "title" to "Milk")
    shareAll(owner, weekly, left, right, member)
    val everyone = listOf(owner, left, right, member)
    eventually("everyone to hold Weekly", *everyone.toTypedArray()) { everyone.all { it.items(weekly) == listOf("Milk") } }

    // Concurrent publication: each issuer migrates main offline to its own version 8.
    left.reopenOffline(CURRENT_APP)
    right.reopenOffline(RIVAL_APP)
    expect(left.tip() != right.tip()) { "both issuers published one tip" }
    left.attach(owner, member)
    right.attach(owner, member, left)
    eventually("every device to end on one tip", *everyone.toTypedArray()) { everyone.map { it.tip() }.distinct().size == 1 }
    val losers = owner.tips().getValue("losers").jsonObject
    expect(losers.keys == setOf("main/1")) { "losers $losers" }
    val winner = owner.tip()
    notes += "race: the household ended on ${winner.take(8)}; inspection lists main/1 → ${losers["main/1"]?.jsonPrimitive?.contentOrNull?.take(8)}"
    for (device in everyone) eventually("${device.name} to read Weekly on the winner", device, owner) { device.items(weekly) == listOf("Milk") }

    // Rollback: the owner keeps every seal and moves main back to the latest; an issuer seals forward meanwhile.
    val back = owner.call("seal").text
    eventually("every device to follow the seal", *everyone.toTypedArray()) { everyone.all { it.tip() == back } }
    member.call("add", "list" to weekly, "title" to "Late")
    member.settle(2)
    owner.maintain()
    owner.online(false)
    left.call("seal")
    val rolled = owner.call("rollBack", "seal" to back).text
    owner.online(true)
    eventually("every device to follow the owner's rollback", *everyone.toTypedArray()) { everyone.all { it.tip() == rolled } }
    notes += "rollback: an issuer sealed main forward while the owner moved it back; all ${everyone.size} devices follow ${rolled.take(8)}"
    for (device in everyone) eventually("${device.name} to read Weekly at the rollback", device, owner) { device.items(weekly) == listOf("Milk") }
    val held = member.held()
    expect(held.size == 1) { "the member's write past the seal: $held" }
    notes += "the member's write past the seal came back held: ${held.single().jsonObject.getValue("rows")}"
}
