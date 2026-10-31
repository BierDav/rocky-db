package org.example.examples.shopping.data.db.entity

import androidx.room.*

/**
 * An item of [list], keyed by the [key] the writer chooses. A title is unique per list: of two devices adding one
 * offline, the transaction replayed later drops. Deleting the list deletes the item. Items sort by [position], then [id]; its categories are [ItemCategory] links.
 * [category] is the single category of version 6, which the version 7 migration turned into a link.
 */
@Entity(
    tableName = "items",
    primaryKeys = ["list", "key"],
    indices = [
        Index(value = ["list", "id"], unique = true, name = "items_identity"),
        Index(value = ["list", "title"], unique = true),
        Index(value = ["list", "category"]),
        Index(value = ["list", "position"]),
    ],
    foreignKeys = [
        ForeignKey(entity = ShoppingList::class, parentColumns = ["id"], childColumns = ["list"], onDelete = ForeignKey.CASCADE, deferred = true),
        ForeignKey(entity = Category::class, parentColumns = ["list", "id"], childColumns = ["list", "category"], onDelete = ForeignKey.SET_NULL, deferred = true),
    ],
)
data class ShoppingItem(
    val list: Long,
    val key: String,
    val title: String,
    val completed: Boolean,
    val category: Long? = null,
    val id: Long,
    @ColumnInfo(defaultValue = "''") val position: String = "",
)
