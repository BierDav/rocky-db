package org.example.examples.shopping.data.db.entity

import androidx.room.*

/** A list is its own partition of the `list` group; Rocky issues [id]. */
@Entity(tableName = "lists")
data class ShoppingList(
    @PrimaryKey val id: Long,
    val title: String,
)
