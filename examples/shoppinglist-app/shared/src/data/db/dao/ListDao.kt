package org.example.examples.shopping.data.db.dao

import androidx.room.*
import kotlinx.coroutines.flow.Flow
import org.example.examples.shopping.data.db.entity.ShoppingList

@Dao
interface ListDao {
    /** The held lists; a device need not hold every list. */
    @Query("SELECT * FROM lists ORDER BY id")
    fun observeAll(): Flow<List<ShoppingList>>

    /** The held lists once, for a read-only view of a seal. */
    @Query("SELECT * FROM lists ORDER BY id")
    suspend fun all(): List<ShoppingList>

    @Insert suspend fun insert(list: ShoppingList)

    @Query("UPDATE lists SET title = :title WHERE id = :id")
    suspend fun rename(id: Long, title: String): Int

    @Query("DELETE FROM lists WHERE id = :id")
    suspend fun delete(id: Long): Int
}
