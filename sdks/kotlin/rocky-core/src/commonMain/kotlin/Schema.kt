package rocky

import kotlinx.serialization.json.*

/** A format-6 definition: every table has an implicit `id` column and is written with SQL. */
data class Schema(
    val application: String,
    val version: Int = 1,
    val tables: List<Table>,
    val views: Map<String, String> = emptyMap(),
    val migrations: List<Migration> = emptyList(),
    val assertions: List<Assertion> = emptyList(),
) {
    init {
        require(migrations.zipWithNext().all { (a, b) -> a.version < b.version } && migrations.all { it.version <= version }) { "migrations name ascending versions up to $version" }
        require(application.matches(IDENTIFIER) && version > 0 && tables.isNotEmpty() && tables.size <= 64)
        require(tables.map { it.name }.distinct().size == tables.size)
        require(assertions.map { it.name }.distinct().size == assertions.size) { "duplicate assertion" }
        validatePartitionGroups(tables)
        validateReferences(tables)
        for (table in tables) {
            table.grantedLike?.let { like ->
                require(tables.any { it.name == like && it.grantedLike == null }) { "${table.name} is granted like $like, which must be a table granted like none" }
            }
        }
        require(tables.all { it.primaryKey.isNotEmpty() }) { "every table declares a primary key; use the schema builder" }
    }

    /** The definition the runtime installs; equivalent declarations produce equal JSON. */
    fun json(): String = buildJsonObject {
        put("application", application)
        put("version", version)
        put("format", 6)
        put("tables", JsonArray(tables.sortedBy { it.name }.map { it.definition() }))
        if (views.isNotEmpty()) put("views", viewsJson())
        if (assertions.isNotEmpty()) put("assertions", assertionsJson())
        if (migrations.isNotEmpty()) put("migrations", JsonArray(migrations.map { it.json() }))
    }.toString()

    /** Portable definition data, bound to the application's publisher. */
    fun definitionJson(publisher: String): String {
        require(publisher.matches(Regex("[0-9a-fA-F]{64}"))) { "publisher must be 64 hexadecimal digits" }
        return buildJsonObject {
            put("format", 6)
            put("publisher", publisher.lowercase())
            put("application", application)
            if (views.isNotEmpty()) put("views", viewsJson())
            if (assertions.isNotEmpty()) put("assertions", assertionsJson())
            put("tables", JsonArray(tables.sortedBy { it.name }.map { it.definition() }))
        }.toString()
    }
    private fun assertionsJson() = JsonArray(assertions.sortedBy { it.name }.map { it.json() })
    private fun viewsJson(): JsonArray = JsonArray(
        views.entries.sortedBy { it.key }.map { (name, select) ->
            buildJsonObject {
                put("name", name)
                put("create_sql", "CREATE VIEW \"$name\" AS $select")
            }
        },
    )
    fun table(name: String): Table = tables.firstOrNull { it.name == name } ?: error("unknown table $name")
}

/**
 * What the first issuer to sign the schema's generation runs once, after signing, in one transaction of any size;
 * see `docs/runtime/generations.md#migrations`.
 */
data class Migration(val version: Int, val steps: List<MigrationStep>) {
    init {
        require(version > 0 && steps.isNotEmpty() && steps.size <= 64) { "migration $version needs 1 to 64 steps" }
    }
    internal fun json(): JsonObject = buildJsonObject {
        put("version", version)
        put("statements", JsonArray(steps.map { it.json() }))
    }
}

/** One step of a [Migration]. */
sealed interface MigrationStep {
    /** SQL run as it is. */
    data class Sql(val sql: String) : MigrationStep

    /** A row of [table] for each row [select] returns, its columns named like the table's, with an `id` Rocky issues. */
    data class Insert(val table: String, val select: String) : MigrationStep

    fun json(): JsonElement = when (this) {
        is Sql -> JsonPrimitive(sql)

        is Insert -> buildJsonObject {
            put("insert", table)
            put("select", select)
        }
    }
}

/** Builds the steps of one [Migration]. */
class MigrationBuilder internal constructor() {
    internal val steps = mutableListOf<MigrationStep>()
    fun sql(statement: String) {
        steps += MigrationStep.Sql(statement)
    }
    fun insert(table: String, select: String) {
        steps += MigrationStep.Insert(table, select)
    }
}
internal val IDENTIFIER = Regex("[A-Za-z][A-Za-z0-9_]{0,63}")

/** A table; its [name], like each column's, is its identity forever (decision 0067). */
data class Table(
    val name: String,
    val columns: List<Column>,
    val primaryKey: List<String> = emptyList(),
    val indexes: List<Index> = emptyList(),
    val tableClass: TableClass = TableClass.Replayed,
    val foreignKeys: List<ForeignKey> = emptyList(),
    val partitionBy: List<String> = emptyList(),
    internal val roomIdentityIndex: List<String>? = null,
    val partitionGroup: String? = null,
    /** The table whose grants this one follows; see [TableBuilder.grantedLike]. */
    val grantedLike: String? = null,
    /** See [TableBuilder.check]. */
    val checks: List<String> = emptyList(),
) {
    init {
        require(name.matches(IDENTIFIER) && columns.isNotEmpty() && columns.size <= 128)
        require(grantedLike == null || (grantedLike != name && grantedLike.matches(IDENTIFIER))) { "$name: invalid grantedLike $grantedLike" }
        require(columns.map { it.name }.distinct().size == columns.size)
    }
    internal fun definition(): JsonObject = buildJsonObject {
        put("name", name)
        grantedLike?.let { put("granted_like", it) }
        put("class", tableClass.wire)
        put("columns", JsonArray(columns.map { it.definition() }))
        if (checks.isNotEmpty()) put("checks", JsonArray(checks.map(::JsonPrimitive)))
        put("primary_key", JsonArray(primaryKey.map(::JsonPrimitive)))
        put("indexes", JsonArray(indexes.sortedBy { it.name }.map { it.json() }))
        if (foreignKeys.isNotEmpty()) put("foreign_keys", JsonArray(foreignKeys.sortedBy { it.columns.joinToString(",") }.map { it.json() }))
        if (partitionBy.isNotEmpty()) put("partition_by", JsonArray(partitionBy.map(::JsonPrimitive)))
        partitionGroup?.let { put("partition_group", it) }
    }

    /** Rows in primary-key order, the `id` first, as [Row.decode] reads them. */
    fun query(pageSize: Int = 128): JsonObject = query("SELECT id, ${columns.joinToString { it.name }} FROM $name ORDER BY ${primaryKey.joinToString()}", maxRows = pageSize)
}

data class Column(
    val name: String,
    internal val kind: String,
    val nullable: Boolean,
    val default: JsonElement? = null,
    val collation: Collation = Collation.Binary,
    val derived: String? = null,
    val localOnly: Boolean = false,
) {
    init {
        require(name.matches(IDENTIFIER))
        require(kind in setOf("text", "integer", "boolean", "real", "blob"))
    }
    internal fun definition(): JsonObject = buildJsonObject {
        put("name", name)
        put("type", if (kind == "boolean") "integer" else kind)
        put("not_null", !nullable)
        default?.takeUnless { it is JsonNull }?.let {
            val boolean = (it as? JsonPrimitive)?.takeUnless { primitive -> primitive.isString }?.booleanOrNull
            put("default", if (boolean == null) it else JsonPrimitive(if (boolean) 1 else 0))
        }
        put("collation", collation.wire)
        derived?.let { put("derived", it) }
        put("local_only", localOnly)
    }
    companion object {
        fun text(name: String, nullable: Boolean = false) = Column(name, "text", nullable)
        fun boolean(name: String, nullable: Boolean = false) = Column(name, "boolean", nullable)
        fun integer(name: String, nullable: Boolean = false) = Column(name, "integer", nullable)
        fun real(name: String, nullable: Boolean = false) = Column(name, "real", nullable)
        fun blob(name: String, nullable: Boolean = false) = Column(name, "blob", nullable)
    }
}

/** Typed access to a committed row; transport encodings stay inside the SDK. */
class Row internal constructor(val id: String, private val values: Map<String, JsonObject>) {
    private fun value(column: String): JsonPrimitive = cell(column).getValue("value").jsonPrimitive
    private fun cell(column: String): JsonObject = values[column] ?: error("unknown column $column")
    fun text(column: String): String = value(column).content
    fun boolean(column: String): Boolean = value(column).content != "0"
    fun integer(column: String): Long = value(column).content.toLong()
    fun real(column: String): Double = Double.fromBits(value(column).content.toULong(16).toLong())
    fun blob(column: String): ByteArray = cell(column).getValue("value").jsonArray.map { it.jsonPrimitive.int.toByte() }.toByteArray()
    fun isNull(column: String): Boolean = cell(column).getValue("type").jsonPrimitive.content == "null"
    companion object {
        /** Rows of a `Table.query` snapshot; the first column is the row's `id`. */
        fun decode(snapshot: JsonObject): List<Row> {
            val columns = snapshot.getValue("columns").jsonArray.map { it.jsonPrimitive.content }
            return snapshot.getValue("rows").jsonArray.map { element ->
                val cells = element.jsonArray.map { it.jsonObject }
                Row(cells[0].getValue("value").jsonPrimitive.content, columns.zip(cells).toMap())
            }
        }
    }
}
