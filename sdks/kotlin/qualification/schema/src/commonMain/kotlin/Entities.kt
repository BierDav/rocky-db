package rocky.qualification

import androidx.room.*

// Every entity carries Rocky's id; natural keys add the identity index Rocky creates.
@Entity(tableName = "listings", indices = [Index(value = ["id"], unique = true, name = "listings_identity")])
data class Listing(@PrimaryKey val key: String, val title: String, val note: String, val price: Long?, val id: Long)

@Entity(tableName = "memos", indices = [Index(value = ["id"], unique = true, name = "memos_identity")])
data class Memo(@PrimaryKey val key: String, val memo: String, val id: Long)

@Entity(tableName = "stock", indices = [Index(value = ["id"], unique = true, name = "stock_identity")])
data class Stock(@PrimaryKey val key: String, val remaining: Long, val id: Long)

@Entity(tableName = "holds", indices = [Index(value = ["id"], unique = true, name = "holds_identity")])
data class Hold(@PrimaryKey val key: String, val reserved: Long, val id: Long)

@Dao
interface MarketDao {
    @Query("SELECT * FROM listings")
    suspend fun listings(): List<Listing>
}

@Database(entities = [Listing::class, Memo::class, Stock::class, Hold::class], version = 2, exportSchema = true)
@ConstructedBy(MarketDatabaseConstructor::class)
abstract class MarketDatabase : RoomDatabase() {
    abstract fun dao(): MarketDao
}
expect object MarketDatabaseConstructor : RoomDatabaseConstructor<MarketDatabase> {
    override fun initialize(): MarketDatabase
}

@Entity(
    tableName = "samples",
    primaryKeys = ["sensor", "sequence"],
    indices = [Index(value = ["reading"], orders = [Index.Order.DESC], name = "samples_by_reading"), Index(value = ["id"], unique = true, name = "samples_identity")],
)
data class Sample(val sensor: String, val sequence: Long, val reading: Double?, val raw: ByteArray?, val id: Long)

@Dao
interface SampleDao {
    @Insert suspend fun insert(sample: Sample)

    @Query("SELECT * FROM samples ORDER BY sensor,sequence")
    suspend fun all(): List<Sample>
}

@Database(entities = [Sample::class], version = 1, exportSchema = true)
@ConstructedBy(SampleDatabaseConstructor::class)
abstract class SampleDatabase : RoomDatabase() {
    abstract fun dao(): SampleDao
}
expect object SampleDatabaseConstructor : RoomDatabaseConstructor<SampleDatabase> {
    override fun initialize(): SampleDatabase
}

@Entity(tableName = "parents")
data class Parent(@PrimaryKey val id: Long, val title: String)

@Entity(
    tableName = "children",
    indices = [Index(value = ["code"], unique = true), Index(value = ["label"], unique = true), Index(value = ["parent"]), Index(value = ["optional"])],
    foreignKeys = [
        ForeignKey(entity = Parent::class, parentColumns = ["id"], childColumns = ["parent"], onDelete = ForeignKey.CASCADE, deferred = true),
        ForeignKey(entity = Parent::class, parentColumns = ["id"], childColumns = ["optional"], onDelete = ForeignKey.SET_NULL, deferred = true),
    ],
)
data class Child(@PrimaryKey val id: Long, val code: String, val label: String?, val parent: Long, val optional: Long?)

@Dao
interface ConstraintDao {
    @Insert suspend fun parent(row: Parent)

    @Insert suspend fun child(row: Child)

    @Update suspend fun update(row: Child)

    @Query("SELECT * FROM children")
    suspend fun children(): List<Child>

    @SkipQueryVerification
    @Query("SELECT rocky_next_id(:table)")
    suspend fun nextId(table: String): Long

    @Transaction suspend fun createParent(title: String): Long = nextId("parents").also { parent(Parent(it, title)) }

    @Transaction suspend fun createChild(code: String, label: String?, parent: Long, optional: Long? = null): Long = nextId("children").also { child(Child(it, code, label, parent, optional)) }

    @Query("DELETE FROM parents WHERE id = :id")
    suspend fun deleteParent(id: Long)
}

@Database(entities = [Parent::class, Child::class], version = 1, exportSchema = true)
@ConstructedBy(ConstraintDatabaseConstructor::class)
abstract class ConstraintDatabase : RoomDatabase() {
    abstract fun dao(): ConstraintDao
}
expect object ConstraintDatabaseConstructor : RoomDatabaseConstructor<ConstraintDatabase> {
    override fun initialize(): ConstraintDatabase
}

@Entity(
    tableName = "partition_samples",
    primaryKeys = ["sensor", "sequence"],
    indices = [Index(value = ["sensor", "id"], unique = true, name = "partition_samples_identity")],
)
data class PartitionSample(val sensor: String, val sequence: Long, val reading: Long, val id: Long)

@DatabaseView(value = "SELECT * FROM partition_samples", viewName = "partial_partition_samples")
data class PartialPartitionSample(val sensor: String, val sequence: Long, val reading: Long, val id: Long)

@Database(entities = [PartitionSample::class], views = [PartialPartitionSample::class], version = 1, exportSchema = true)
@ConstructedBy(PartitionDatabaseConstructor::class)
abstract class PartitionDatabase : RoomDatabase()
expect object PartitionDatabaseConstructor : RoomDatabaseConstructor<PartitionDatabase> {
    override fun initialize(): PartitionDatabase
}

@Entity(tableName = "lists")
data class GroupList(@PrimaryKey val id: Long, val title: String)

@Entity(
    tableName = "items",
    primaryKeys = ["list", "key"],
    indices = [Index(value = ["list", "id"], unique = true, name = "items_identity")],
)
data class GroupItem(val list: Long, val key: String, val title: String, val id: Long)

@Database(entities = [GroupList::class, GroupItem::class], version = 1, exportSchema = true)
@ConstructedBy(GroupDatabaseConstructor::class)
abstract class GroupDatabase : RoomDatabase()
expect object GroupDatabaseConstructor : RoomDatabaseConstructor<GroupDatabase> {
    override fun initialize(): GroupDatabase
}

// The single-table shopping entity of the unpartitioned walkthrough; the import refusals edit its export.
@Entity(tableName = "shopping_items", indices = [Index(value = ["completed", "title"])])
data class FlatItem(@PrimaryKey val id: Long, val title: String, val completed: Boolean, @ColumnInfo(defaultValue = "''") val searchTitle: String = title.lowercase())

@Database(entities = [FlatItem::class], version = 2, exportSchema = true)
@ConstructedBy(FlatDatabaseConstructor::class)
abstract class FlatDatabase : RoomDatabase()
expect object FlatDatabaseConstructor : RoomDatabaseConstructor<FlatDatabase> {
    override fun initialize(): FlatDatabase
}
