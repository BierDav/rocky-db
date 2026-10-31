package org.example.examples.shopping.qualification

import org.example.examples.shopping.data.db.ShoppingSchema
import org.example.examples.shopping.data.db.trustedTables
import rocky.*

/** The app version this build ships; a device process may also run an older or a rival app's schema. */
internal const val CURRENT_APP = 8

/** A rival version 8 for concurrent publication: it adds a list note instead of ordering categories. */
internal const val RIVAL_APP = 80

internal fun appSchema(app: Int): Schema = when (app) {
    CURRENT_APP -> ShoppingSchema
    7 -> ShoppingSchemaV7
    RIVAL_APP -> ShoppingSchemaRival
    else -> error("no app version $app")
}

/** The shopping schema as app version 7 shipped it: items ordered, categories by name. */
private val ShoppingSchemaV7 = schema("shopping", version = 7) {
    lists()
    table("categories") {
        integer("list")
        text("name")
        primaryKey("list", "id")
        partitionBy("list", group = "list")
        reference("list", "lists", onDelete = Delete.Cascade)
    }
    items()
    approvals()
    trustedTables()
}

/** Another version 8 an issuer may publish at the same time: a required note on lists, filled by a migration. */
private val ShoppingSchemaRival = schema("shopping", version = 8) {
    table("lists") {
        text("title")
        text("note", default = "")
        primaryKey("id")
        partitionBy("id", group = "list")
    }
    table("categories") {
        integer("list")
        text("name")
        primaryKey("list", "id")
        partitionBy("list", group = "list")
        reference("list", "lists", onDelete = Delete.Cascade)
    }
    items()
    migration(8) { sql("UPDATE lists SET note = 'rival' WHERE note = ''") }
    approvals()
    trustedTables()
}

private fun SchemaBuilder.lists() = table("lists") {
    text("title")
    primaryKey("id")
    partitionBy("id", group = "list")
}

/** Items and their category links, with version 7's migration, as both version 7 and the rival declare them. */
private fun SchemaBuilder.items() {
    table("items") {
        integer("list")
        text("key")
        text("title")
        boolean("completed")
        integer("category", nullable = true)
        text("position", default = "")
        primaryKey("list", "key")
        partitionBy("list", group = "list")
        unique("list", "title")
        index("index_items_list_category", "list", "category")
        index("index_items_list_position", "list", "position")
        reference("list", "lists", onDelete = Delete.Cascade)
        reference(listOf("list", "category"), "categories", onDelete = Delete.SetNull)
    }
    table("item_categories") {
        integer("list")
        integer("item")
        integer("category")
        primaryKey("list", "item", "category")
        partitionBy("list", group = "list")
        index("index_item_categories_list_category", "list", "category")
        reference(listOf("list", "item"), "items", onDelete = Delete.Cascade)
        reference(listOf("list", "category"), "categories", onDelete = Delete.Cascade)
        grantedLike = "items"
    }
    migration(7) {
        sql("UPDATE items SET position = printf('%09d5', (SELECT count(*) FROM items AS earlier WHERE earlier.list = items.list AND earlier.id < items.id))")
        insert("item_categories", "SELECT list, id AS item, category FROM items WHERE category IS NOT NULL")
        sql("UPDATE items SET category = NULL WHERE category IS NOT NULL")
    }
}

private fun SchemaBuilder.approvals() {
    table("requests") {
        text("key")
        text("title")
        text("note")
        text("requester")
        primaryKey("key")
    }
    table("decisions") {
        text("key")
        boolean("approved")
        text("decider")
        primaryKey("key")
    }
}
