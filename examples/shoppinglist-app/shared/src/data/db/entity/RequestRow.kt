package org.example.examples.shopping.data.db.entity

import androidx.room.*

/** An ordinary request row; [requester] is the asking device key. */
@Entity(tableName = "requests", indices = [Index(value = ["id"], unique = true, name = "requests_identity")])
data class RequestRow(
    @PrimaryKey val key: String,
    val title: String,
    val note: String,
    val requester: String,
    val id: Long,
)
