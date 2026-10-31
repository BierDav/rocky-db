package rocky.room.qualification

import androidx.room.*
import kotlinx.coroutines.flow.Flow

/**
 * The ordinary Room surface the driver is qualified on: entities, a relation and every DAO write kind. Each entity
 * carries Rocky's `id`; with a natural key it also declares the identity index Rocky creates.
 */
@Entity(tableName = "lists", indices = [Index(value = ["id"], unique = true, name = "lists_identity")])
data class ShopList(@PrimaryKey val key: String, val title: String, val id: Long = 0)

@Entity(
    tableName = "items",
    indices = [Index(value = ["list", "title"], name = "items_by_list"), Index(value = ["id"], unique = true, name = "items_identity")],
)
data class ShopItem(
    @PrimaryKey val key: String,
    val list: String,
    val title: String,
    val completed: Boolean = false,
    val quantity: Long = 1,
    val price: Double? = null,
    val photo: ByteArray? = null,
    val id: Long = 0,
) {
    override fun equals(other: Any?): Boolean = other is ShopItem &&
        key == other.key &&
        list == other.list &&
        title == other.title &&
        completed == other.completed &&
        quantity == other.quantity &&
        price == other.price &&
        photo.contentEquals(other.photo) &&
        id == other.id
    override fun hashCode(): Int = key.hashCode()
}

data class ListWithItems(
    @Embedded val list: ShopList,
    @Relation(parentColumn = "key", entityColumn = "list") val items: List<ShopItem>,
)
data class Summary(val list: String, val items: Long, val done: Long)

@Dao
interface ShopDao {
    @Insert suspend fun insertList(list: ShopList)

    @Insert suspend fun insertItems(items: List<ShopItem>): List<Long>

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertIgnore(item: ShopItem): Long

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReplace(item: ShopItem): Long

    @Update suspend fun update(item: ShopItem): Int

    @Delete suspend fun delete(item: ShopItem): Int

    @Upsert suspend fun upsert(item: ShopItem)

    @Query("UPDATE items SET completed = :completed WHERE list = :list")
    suspend fun complete(list: String, completed: Boolean): Int

    @Query("DELETE FROM items WHERE completed = 1 AND list = :list")
    suspend fun clearCompleted(list: String): Int

    @Query("SELECT * FROM items WHERE list = :list ORDER BY title")
    suspend fun items(list: String): List<ShopItem>

    @Query("SELECT * FROM items WHERE list = :list ORDER BY title")
    fun observe(list: String): Flow<List<ShopItem>>

    @Transaction
    @Query("SELECT * FROM lists WHERE `key` = :key")
    suspend fun withItems(key: String): ListWithItems?

    @Query("SELECT list, count(*) AS items, sum(completed) AS done FROM items GROUP BY list ORDER BY list")
    suspend fun summary(): List<Summary>

    @Query("SELECT * FROM lists ORDER BY `key`")
    suspend fun lists(): List<ShopList>

    /** Names `price`, which a later generation of the database may have removed. */
    @Query("SELECT price FROM items WHERE list = :list")
    suspend fun prices(list: String): List<Double?>

    /** Rows whose ids the caller already holds. */
    @Transaction suspend fun addList(list: ShopList, items: List<ShopItem>) {
        insertList(list)
        insertItems(items)
    }

    /** Rocky reserves the next row id of a table inside the caller's write transaction; a rollback releases it. */
    @SkipQueryVerification
    @Query("SELECT rocky_next_id('lists')")
    suspend fun nextListId(): Long

    @SkipQueryVerification
    @Query("SELECT rocky_next_id(:table)")
    suspend fun nextId(table: String): Long

    /** Obtains every new row's id before its insert, in the one transaction that inserts them. */
    @Transaction suspend fun createList(list: ShopList, items: List<ShopItem>): ListWithItems? {
        insertList(list.copy(id = nextListId()))
        createItems(items)
        return withItems(list.key)
    }

    @Transaction suspend fun createItems(items: List<ShopItem>): List<ShopItem> = items.map { it.copy(id = nextId("items")) }.also { insertItems(it) }

    /** A list without items, its id reserved in the transaction that inserts it. */
    @Transaction suspend fun createEmptyList(list: ShopList) = insertList(list.copy(id = nextListId()))
}

@Database(entities = [ShopList::class, ShopItem::class], version = 1, exportSchema = true)
@ConstructedBy(ShopDatabaseConstructor::class)
abstract class ShopDatabase : RoomDatabase() {
    abstract fun shop(): ShopDao
}

@Suppress("KotlinNoActualForExpect")
expect object ShopDatabaseConstructor : RoomDatabaseConstructor<ShopDatabase> {
    override fun initialize(): ShopDatabase
}
