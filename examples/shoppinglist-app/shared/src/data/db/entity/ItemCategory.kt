package org.example.examples.shopping.data.db.entity

import androidx.room.*

/** Item [item] of [list] is in [category]; deleting either deletes the link. */
@Entity(
    tableName = "item_categories",
    primaryKeys = ["list", "item", "category"],
    indices = [
        Index(value = ["list", "id"], unique = true, name = "item_categories_identity"),
        Index(value = ["list", "category"]),
    ],
    foreignKeys = [
        ForeignKey(entity = ShoppingItem::class, parentColumns = ["list", "id"], childColumns = ["list", "item"], onDelete = ForeignKey.CASCADE, deferred = true),
        ForeignKey(entity = Category::class, parentColumns = ["list", "id"], childColumns = ["list", "category"], onDelete = ForeignKey.CASCADE, deferred = true),
    ],
)
data class ItemCategory(
    val list: Long,
    val item: Long,
    val category: Long,
    val id: Long,
)
