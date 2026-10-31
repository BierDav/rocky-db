package org.example.examples.shopping

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import org.example.examples.shopping.data.coordination.Approvals
import org.example.examples.shopping.data.db.ShoppingDatabase
import org.example.examples.shopping.data.db.ShoppingSchema
import org.example.examples.shopping.data.household.Household
import org.example.examples.shopping.data.household.NodeKind
import rocky.*
import rocky.room.followRocky
import java.io.File
import java.nio.file.Files
import kotlin.test.*

/** A trusted device decides; every reader sees the decision, and members only ask. */
class ApprovalsTest {
    @Test fun aDecisionReachesEveryDeviceAndMembersOnlyAsk() = runBlocking<Unit> {
        val root = Files.createTempDirectory("rocky-approvals").toFile()
        val databases = mutableListOf<RockyDatabase>()
        val rooms = mutableListOf<ShoppingDatabase>()
        val observers = mutableListOf<Job>()
        val log = DevelopmentLog()
        try {
            fun network() = PeerTransport.Iroh.isolated()
            val a = RockyDatabase.create(File(root, "a"), ShoppingSchema, network()).also(databases::add)
            val b = RockyDatabase.join(File(root, "b"), ShoppingSchema, a.pairing(GrantProfile.Issuer).uri, network()).also(databases::add)
            val m = RockyDatabase.join(File(root, "m"), ShoppingSchema, a.pairing(NodeKind.Full.profile).uri, network()).also(databases::add)
            val approvals = databases.mapIndexed { index, database ->
                val room = openShoppingDatabase(File(root, listOf("a", "b", "m")[index]), database).also(rooms::add)
                observers += launch(Dispatchers.IO) { room.followRocky(database) }
                val self = database.session().node
                Approvals(room, database, Household(room, database, self), self, true)
            }
            for (left in databases) {
                for (right in databases) {
                    if (left !== right) left.addPeer(right.contact().uri)
                }
            }
            log.configure(a, 2)
            a.coordinate(log)
            b.coordinate(log)
            assertNull(approvals[2].ask("Coffee machine", "Replacement"))
            for (database in databases) database.syncOnce()
            val aKey = a.session().node
            val bKey = b.session().node
            withTimeout(30_000) { a.observeStatus().first { status -> status.network.peers.any { it.node == bKey && it.link.state == LinkState.Open } } }
            withTimeout(30_000) { b.observeStatus().first { status -> status.network.peers.any { it.node == aKey && it.link.state == LinkState.Open } } }
            val asked = withTimeout(30_000) { approvals[0].requests().first { it.isNotEmpty() } }.single()
            withTimeout(30_000) { approvals[1].requests().first { it.isNotEmpty() } }
            assertNull(approvals[0].decide(asked.key, true))
            val decisions = approvals.map { view ->
                withTimeout(30_000) { view.requests().first { it.singleOrNull()?.approved != null } }.single().approved
            }
            assertEquals(listOf(true, true, true), decisions)
            // A device that holds the decision does not decide again.
            assertEquals("Another device already approved it", approvals[1].decide(asked.key, false))
            assertFails { approvals[2].decide(asked.key, true) }
        } finally {
            observers.forEach { it.cancelAndJoin() }
            rooms.asReversed().forEach { it.close() }
            databases.asReversed().forEach { it.close() }
            log.close()
            root.deleteRecursively()
        }
    }
}
