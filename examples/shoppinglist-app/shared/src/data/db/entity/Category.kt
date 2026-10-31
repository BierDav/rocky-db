package org.example.examples.shopping.data.db.entity

import androidx.room.*

/**
 * A category of one list; its identity is the list and the [id] Rocky issues in that list. Categories sort by
 * [position], then name; version 8 added it.
 */
@Entity(
    tableName = "categories",
    primaryKeys = ["list", "id"],
    indices = [Index(value = ["list", "position"], name = "index_categories_list_position")],
    foreignKeys = [ForeignKey(entity = ShoppingList::class, parentColumns = ["id"], childColumns = ["list"], onDelete = ForeignKey.CASCADE, deferred = true)],
)
data class Category(
    val list: Long,
    val id: Long,
    val name: String,
    @ColumnInfo(defaultValue = "''") val position: String = "",
)
