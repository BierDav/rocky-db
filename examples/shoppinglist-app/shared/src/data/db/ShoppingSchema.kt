package org.example.examples.shopping.data.db

import kotlinx.coroutines.runBlocking
import org.example.examples.shopping.resources.Res
import rocky.*

/** The packaged Room export supplies columns, keys, references and indexes; the overlay adds what Rocky needs. Every table is replayed. */
val ShoppingSchema: Schema by lazy {
    runBlocking {
        schemaFromRoom("shopping", Res.readBytes("files/ShoppingDatabase.json").decodeToString(), shoppingRoomOverlay)
    }
}

/** What a Room export cannot hold: the group, the coordinator and the trusted-only tables. */
val shoppingRoomOverlay: SchemaBuilder.() -> Unit = {
    table("lists") { partitionBy("id", group = "list") }
    table("categories") { partitionBy("list", group = "list") }
    table("items") { partitionBy("list", group = "list") }
    table("item_categories") {
        partitionBy("list", group = "list")
        grantedLike = "items"
    }
    itemsMigration()
    categoriesMigration()
    trustedTables()
}

/**
 * Version 7, run once by the trusted device that upgrades first: each list's items are placed in their creation
 * order, and each item's one category becomes a link. `items.category` stays, unwritten, until a cut can drop it.
 */
private fun SchemaBuilder.itemsMigration() = migration(7) {
    sql("UPDATE items SET position = printf('%09d5', (SELECT count(*) FROM items AS earlier WHERE earlier.list = items.list AND earlier.id < items.id))")
    insert("item_categories", "SELECT list, id AS item, category FROM items WHERE category IS NOT NULL")
    sql("UPDATE items SET category = NULL WHERE category IS NOT NULL")
}

/**
 * Version 8, run once by the trusted device that publishes it: each list's categories are placed by name. A
 * migration closes the tip it leaves, so writes made on it meanwhile come back as held changes.
 */
private fun SchemaBuilder.categoriesMigration() = migration(8) {
    sql("UPDATE categories SET position = printf('%09d5', (SELECT count(*) FROM categories AS earlier WHERE earlier.list = categories.list AND (earlier.name < categories.name OR (earlier.name = categories.name AND earlier.id < categories.id))))")
}

/** The tables of a list's group. */
val ShoppingTables = listOf("lists", "categories", "items", "item_categories")

/** The `list` group partition of [list]: its key, sharing and holding. */
fun RockyDatabase.list(list: Long): GroupPartition = partitions.group("list", list)
