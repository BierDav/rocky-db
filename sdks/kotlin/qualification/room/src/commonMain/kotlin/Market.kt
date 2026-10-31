package rocky.room.qualification

import androidx.room.*
import kotlinx.coroutines.flow.Flow

/** Ordinary stock rows. */
@Entity(tableName = "stock", indices = [Index(value = ["id"], unique = true, name = "stock_identity")])
data class Stock(@PrimaryKey val item: String, val remaining: Long, val id: Long = 0)

@Entity(tableName = "holds", indices = [Index(value = ["id"], unique = true, name = "holds_identity")])
data class Hold(@PrimaryKey val key: String, val item: String, val id: Long = 0)

@Dao
interface MarketDao {
    @Query("SELECT * FROM stock ORDER BY item")
    suspend fun stock(): List<Stock>

    @Query("SELECT * FROM stock ORDER BY item")
    fun observeStock(): Flow<List<Stock>>

    @Query("SELECT * FROM holds ORDER BY `key`")
    suspend fun holds(): List<Hold>

    @Insert suspend fun insertStock(stock: Stock)

    @Update suspend fun updateStock(stock: Stock): Int

    @Query("DELETE FROM stock")
    suspend fun clearStock(): Int

    @Insert suspend fun insertHold(hold: Hold)

    @SkipQueryVerification
    @Query("SELECT rocky_next_id(:table)")
    suspend fun nextId(table: String): Long

    /** An ordinary local transaction; the application coordinates a stock transition that must not race. */
    @Transaction suspend fun holdAndSetStock(hold: Hold, stock: Stock) {
        insertHold(hold.copy(id = nextId("holds")))
        updateStock(stock)
    }
}

@Database(entities = [Stock::class, Hold::class], version = 1, exportSchema = true)
@ConstructedBy(MarketDatabaseConstructor::class)
abstract class MarketDatabase : RoomDatabase() {
    abstract fun market(): MarketDao
}

@Suppress("KotlinNoActualForExpect")
expect object MarketDatabaseConstructor : RoomDatabaseConstructor<MarketDatabase> {
    override fun initialize(): MarketDatabase
}
