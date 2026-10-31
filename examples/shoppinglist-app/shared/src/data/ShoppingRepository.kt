package org.example.examples.shopping.data

import kotlinx.coroutines.flow.Flow
import org.example.examples.shopping.data.db.ShoppingDatabase
import org.example.examples.shopping.data.db.entity.Category
import org.example.examples.shopping.data.db.entity.ItemCategory
import org.example.examples.shopping.data.db.entity.ShoppingItem
import org.example.examples.shopping.data.db.entity.ShoppingList
import org.example.examples.shopping.data.db.list
import rocky.GrantProfile
import rocky.RecipientDelivery
import rocky.RockyDatabase
import rocky.room.createRockyPartition
import rocky.room.settledOnRocky
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Lists, categories and items as plain DAO reads and writes on Rocky's file: each write is one commit and one signed
 * bundle. Trusted and full devices create lists; trusted devices rename or delete them. Any device edits the lists it holds.
 */
class ShoppingRepository(private val database: ShoppingDatabase, private val rocky: RockyDatabase) {
    fun lists(): Flow<List<ShoppingList>> = database.lists().observeAll().settledOnRocky()

    /** Prepares the new list's group secret, then inserts it; returns the id Rocky issued. */
    suspend fun createList(title: String): Long {
        require(title.isNotBlank())
        return database.createRockyPartition(rocky, "lists") { id ->
            database.lists().insert(ShoppingList(id, title))
            id
        }
    }
    suspend fun renameList(list: Long, title: String) {
        require(title.isNotBlank())
        database.lists().rename(list, title)
    }

    /** Deletes the list's categories and items too. */
    suspend fun deleteList(list: Long) {
        database.lists().delete(list)
    }

    fun categories(list: Long): Flow<List<Category>> = database.categories().observe(list).settledOnRocky()
    suspend fun addCategory(list: Long, name: String): Long {
        require(name.isNotBlank())
        return database.categories().add(list, name).id
    }

    /** Items of the category keep their place in the list; only their links to it are deleted. */
    suspend fun deleteCategory(list: Long, category: Long) {
        database.categories().delete(list, category)
    }

    /** Items in list order. */
    fun observe(list: Long, search: String = "", includeCompleted: Boolean = true): Flow<List<ShoppingItem>> = database.items().observeAll(list, search.lowercase(), includeCompleted).settledOnRocky()

    /** Which items of [list] are in which categories. */
    fun itemCategories(list: Long): Flow<List<ItemCategory>> = database.itemCategories().observe(list).settledOnRocky()

    /** Adds the item at the end of [list], in [categories]; returns the id Rocky issued. */
    @OptIn(ExperimentalUuidApi::class)
    suspend fun add(list: Long, title: String, categories: Set<Long> = emptySet()): Long {
        require(title.isNotBlank())
        return database.items().add(list, Uuid.random().toString(), title, categories).id
    }

    /** Puts the item in [category], or takes it out. */
    suspend fun categorize(list: Long, id: Long, category: Long, member: Boolean) {
        if (member) database.itemCategories().link(list, id, category) else database.itemCategories().unlink(list, id, category)
    }

    /**
     * Moves the item to [index] of [items], the list in its current order: one write, or, when its new neighbours
     * share a key after concurrent places, one transaction placing every item.
     */
    suspend fun place(list: Long, items: List<ShoppingItem>, id: Long, index: Int) {
        val others = items.filter { it.id != id }
        val after = others.getOrNull(index - 1)
        val before = others.getOrNull(index)
        if (Positions.fits(after?.position, before?.position)) {
            database.items().place(list, id, Positions.between(after?.position, before?.position))
        } else {
            val ordered = others.map { it.id }.toMutableList().apply { add(index.coerceIn(0, size), id) }
            database.items().placeAll(list, ordered)
        }
    }
    suspend fun rename(list: Long, id: Long, title: String) {
        require(title.isNotBlank())
        database.items().rename(list, id, title)
    }
    suspend fun check(list: Long, id: Long, completed: Boolean) {
        database.items().check(list, id, completed)
    }
    suspend fun delete(list: Long, id: Long) {
        database.items().delete(list, id)
    }

    /**
     * Moves an item to another held list in one write: it is deleted from [from], leaving its categories, which stay in
     * their list, and inserted at the end of [to] under a new id, which this returns; null when [from] no longer holds
     * it, so a retry moves nothing twice. The insert binds the values this device read: a tick another device made
     * offline, ordered before the move, does not follow the item.
     */
    suspend fun move(from: Long, id: Long, to: Long): Long? = database.items().move(from, id, to)

    /**
     * Shares a held list with [recipients] by node; members choose a discovered peer. Sync carries each envelope to its device
     * alone, directly or through the custody peer, which installs it and starts a list new to it from a checkpoint.
     */
    suspend fun share(list: Long, recipients: List<String>) {
        rocky.list(list).share(recipients)
    }

    /** Shares [list] with every other reading device in the issuer registry, and returns them; custody holds no key. */
    suspend fun shareWithDevices(list: Long): List<String> {
        val own = rocky.session().node
        val devices = rocky.devices().filter { !it.revoked && it.node != own && it.profile !is GrantProfile.Custody }.map { it.node }
        share(list, devices)
        return devices
    }

    /** How far each envelope of [list] this device shared travelled; no other device knows. */
    suspend fun deliveries(list: Long): List<RecipientDelivery> = rocky.list(list).status().recipients
}
