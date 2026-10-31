package rocky

import kotlinx.serialization.json.*

/** Room 2.8.4's format-1 export supplies declarations; the block adds Rocky attributes. */
fun schemaFromRoom(application: String, exportedJson: String, block: SchemaBuilder.() -> Unit = {}): Schema {
    val export = roomExport(exportedJson)
    return schema(application, export.getValue("database").jsonObject.getValue("version").jsonPrimitive.int) {
        fromRoom(exportedJson)
        block()
    }
}

private fun roomExport(json: String): JsonObject {
    require(json.encodeToByteArray().size <= 1024 * 1024) { "Room schema source quota" }
    val export = Json.parseToJsonElement(json).jsonObject
    require(export.keys.all { it in setOf("formatVersion", "database") }) { "unsupported Room export feature" }
    require(export.getValue("database").jsonObject.keys.all { it in setOf("version", "identityHash", "entities", "views", "setupQueries") }) { "unsupported Room database feature" }
    require(export.getValue("formatVersion").jsonPrimitive.int == 1) { "unsupported Room schema format" }
    return export
}

internal fun importRoom(json: String): List<Table> {
    val database = roomExport(json).getValue("database").jsonObject
    val identity = database.getValue("identityHash").jsonPrimitive.content
    val setup = database["setupQueries"]?.jsonArray.orEmpty()
    require(setup.isEmpty() || setup.any { identity in it.jsonPrimitive.content }) { "Room identity hash differs from setup queries" }
    return database.getValue("entities").jsonArray.mapNotNull { raw ->
        val entity = raw.jsonObject
        val name = entity.getValue("tableName").jsonPrimitive.content
        if (name.lowercase().let { it == "android_metadata" || listOf("rocky_", "room_", "sqlite_").any(it::startsWith) }) return@mapNotNull null
        try {
            importEntity(name, entity)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Room entity $name: ${error.message}", error)
        } catch (error: IllegalStateException) {
            throw IllegalArgumentException("Room entity $name: ${error.message}", error)
        } catch (error: NoSuchElementException) {
            throw IllegalArgumentException("Room entity $name: ${error.message}", error)
        }
    }.also { tables ->
        val duplicate = tables.groupBy { it.name.lowercase() }.values.firstOrNull { it.size > 1 }
        require(duplicate == null) { "Room entity ${duplicate?.first()?.name}: duplicate entity" }
    }
}

private fun importEntity(name: String, entity: JsonObject): Table {
    require(entity.keys.all { it in setOf("tableName", "createSql", "fields", "primaryKey", "indices", "foreignKeys") }) { "unsupported entity feature" }
    val primary = entity.getValue("primaryKey").jsonObject
    require(primary.keys.all { it in setOf("autoGenerate", "columnNames") }) { "unsupported primary key feature" }
    require(primary["autoGenerate"]?.jsonPrimitive?.boolean != true) { "autoGenerate = true is refused; Rocky issues row ids, reserve one with rocky_next_id" }
    val key = primary.getValue("columnNames").jsonArray.map { it.jsonPrimitive.content }
    val sql = RoomSql(entity.getValue("createSql").jsonPrimitive.content)
    sql.expect("CREATE", "TABLE")
    sql.ifNotExists()
    sql.table(name)
    sql.expect("(")
    val fields = entity.getValue("fields").jsonArray
    val columns = fields.map { raw ->
        val field = raw.jsonObject
        require(field.keys.all { it in setOf("fieldPath", "columnName", "affinity", "notNull", "defaultValue") }) { "unsupported field feature" }
        val columnName = field.getValue("columnName").jsonPrimitive.content
        val affinity = field.getValue("affinity").jsonPrimitive.content
        sql.identifier(columnName)
        sql.expect(affinity)
        val notNull = field["notNull"]?.jsonPrimitive?.boolean ?: false
        var declaredNotNull = false
        var default: JsonElement? = null
        var collation = Collation.Binary
        var declaredCollation = false
        while (!sql.at(",") && !sql.at(")")) {
            when {
                sql.take("NOT") -> {
                    require(!declaredNotNull) { "duplicate NOT NULL" }
                    sql.expect("NULL")
                    declaredNotNull = true
                }

                sql.take("DEFAULT") -> {
                    require(default == null) { "duplicate default" }
                    default = sql.default()
                }

                sql.take("COLLATE") -> {
                    require(!declaredCollation) { "duplicate collation" }
                    declaredCollation = true
                    collation = when (sql.next().uppercase()) {
                        "BINARY" -> Collation.Binary
                        "NOCASE" -> Collation.Nocase
                        "RTRIM" -> Collation.Rtrim
                        else -> error("unsupported collation on $columnName")
                    }
                }

                else -> error("unsupported SQL column clause on $columnName: ${sql.next()}")
            }
        }
        require(declaredNotNull == notNull) { "$columnName: SQL nullability differs from export" }
        val exportedDefault = field["defaultValue"]?.takeUnless { it is JsonNull }?.jsonPrimitive?.content?.let { RoomSql(it).scalar() }
        require(default == exportedDefault) { "$columnName: SQL default differs from export" }
        sql.expect(",")
        val column = when (affinity) {
            "TEXT" -> Column.text(columnName, !notNull)
            "INTEGER" -> Column.integer(columnName, !notNull)
            "REAL" -> Column.real(columnName, !notNull)
            "BLOB" -> Column.blob(columnName, !notNull)
            else -> error("unsupported affinity $affinity on $columnName")
        }
        column.copy(default = default, collation = collation)
    }
    sql.expect("PRIMARY", "KEY", "(")
    key.forEachIndexed { i, column ->
        if (i > 0) sql.expect(",")
        sql.identifier(column)
    }
    sql.expect(")")
    val foreignKeys = entity["foreignKeys"]?.jsonArray.orEmpty().map { raw -> importForeignKey(raw.jsonObject, sql) }
    sql.expect(")")
    sql.end()
    var identityIndex: List<String>? = null
    val indexes = entity["indices"]?.jsonArray.orEmpty().mapNotNull { raw ->
        val index = raw.jsonObject
        require(index.keys.all { it in setOf("name", "unique", "columnNames", "orders", "createSql") }) { "unsupported index feature" }
        val indexName = index.getValue("name").jsonPrimitive.content
        val names = index.getValue("columnNames").jsonArray.map { it.jsonPrimitive.content }
        val unique = index.getValue("unique").jsonPrimitive.boolean
        if (unique && names == listOf("id")) {
            require(key != listOf("id")) { "$indexName: the primary key id needs no identity index" }
            require(indexName == "${name}_identity") { "$indexName: name the identity index ${name}_identity" }
        }
        // Rocky supplies the identity index: partition columns followed by id.
        val identity = unique && indexName == "${name}_identity"
        if (identity) {
            require(names.lastOrNull() == "id" && names.distinct().size == names.size && names.dropLast(1).all { it in key }) { "$indexName: the identity index names partition columns followed by id" }
            require(identityIndex == null) { "duplicate identity index" }
            identityIndex = names
        }
        val orders = index["orders"]?.jsonArray.orEmpty().map { it.jsonPrimitive.content.uppercase() }
        require(orders.isEmpty() || orders.size == names.size) { "$indexName: index order count" }
        require(orders.all { it == "ASC" || it == "DESC" }) { "$indexName: unsupported index order" }
        val terms = names.mapIndexed { i, column -> IndexColumn(column, orders.getOrNull(i) == "DESC") }
        val statement = RoomSql(index.getValue("createSql").jsonPrimitive.content)
        statement.expect("CREATE")
        if (unique) statement.expect("UNIQUE")
        statement.expect("INDEX")
        statement.ifNotExists()
        statement.identifier(indexName)
        statement.expect("ON")
        statement.table(name)
        statement.expect("(")
        terms.forEachIndexed { i, column ->
            if (i > 0) statement.expect(",")
            statement.identifier(column.name)
            val descending = if (statement.take("DESC")) {
                true
            } else {
                statement.take("ASC")
                false
            }
            require(descending == column.descending) { "$indexName: SQL order differs from export" }
        }
        statement.expect(")")
        statement.end()
        if (identity) {
            require(terms.none { it.descending }) { "identity index must be ascending" }
            null
        } else {
            Index(indexName, terms, unique = unique)
        }
    }
    val builder = TableBuilder(name)
    columns.filterNot { it.name == "id" }.forEach(builder::column)
    // Every entity carries Rocky's identity as its `id` field.
    val id = columns.firstOrNull { it.name == "id" } ?: error("declare Rocky's id field")
    require(id.kind == "integer" && !id.nullable && id.collation == Collation.Binary) { "id must be a non-null integer identity field" }
    require(id.default == null) { "id: unsupported default" }
    require("id" in key || identityIndex != null) {
        "declare the identity index @Index(value = [\"id\"], unique = true, name = \"${name}_identity\")"
    }
    builder.primaryKey(*key.toTypedArray())
    indexes.forEach(builder::index)
    foreignKeys.forEach(builder::foreignKey)
    // Policies are Rocky attributes the export cannot hold; the schema block adds them.
    return builder.build(policies = false).copy(roomIdentityIndex = identityIndex ?: key.takeIf { "id" in it })
}

/** One `@ForeignKey`: it names the parent's identity, its partition columns then `id`, and a delete action Rocky derives. */
private fun importForeignKey(key: JsonObject, sql: RoomSql): ForeignKey {
    require(key.keys.all { it in setOf("table", "onDelete", "onUpdate", "columns", "referencedColumns") }) { "unsupported foreign key feature" }
    val table = key.getValue("table").jsonPrimitive.content
    val columns = key.getValue("columns").jsonArray.map { it.jsonPrimitive.content }
    val referenced = key.getValue("referencedColumns").jsonArray.map { it.jsonPrimitive.content }
    // The parent's partition columns come from the overlay; the schema checks them once every table is declared.
    require(referenced.lastOrNull() == "id" && referenced.size == columns.size && referenced.distinct().size == referenced.size) {
        "a foreign key to $table must reference its identity (partition columns, then id); a natural-key reference is refused"
    }
    val onDelete = key["onDelete"]?.jsonPrimitive?.content ?: "NO ACTION"
    val onUpdate = key["onUpdate"]?.jsonPrimitive?.content ?: "NO ACTION"
    val action = when (onDelete) {
        "CASCADE" -> Delete.Cascade
        "SET NULL" -> Delete.SetNull
        else -> error("onDelete $onDelete on $table is refused; use CASCADE or SET_NULL")
    }
    require(onUpdate == "NO ACTION") { "onUpdate $onUpdate on $table is refused; an id never changes" }
    sql.expect(",", "FOREIGN", "KEY", "(")
    columns.forEachIndexed { i, column ->
        if (i > 0) sql.expect(",")
        sql.identifier(column)
    }
    sql.expect(")", "REFERENCES")
    sql.identifier(table)
    sql.expect("(")
    referenced.forEachIndexed { i, column ->
        if (i > 0) sql.expect(",")
        sql.identifier(column)
    }
    sql.expect(")", "ON", "UPDATE")
    sql.action(onUpdate)
    sql.expect("ON", "DELETE")
    sql.action(onDelete)
    if (sql.take("DEFERRABLE")) sql.expect("INITIALLY", "DEFERRED")
    return ForeignKey(columns, table, action, referenced)
}

/** A deliberately narrow grammar: unrepresented SQL is refused instead of dropped. */
private class RoomSql(sql: String) {
    private val tokens: List<String>
    private var position = 0
    init {
        val pattern = Regex("\\s+|'(?:''|[^'])*'|`(?:``|[^`])*`|\"(?:\"\"|[^\"])*\"|\\[(?:[^]])*]|[A-Za-z_][A-Za-z0-9_]*|[+-]?(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?|[(),;]")
        val found = pattern.findAll(sql).toList()
        require(found.joinToString("") { it.value } == sql) { "unsupported SQL token" }
        tokens = found.map { it.value }.filter { it.isNotBlank() }
    }
    fun next(): String = tokens.getOrNull(position++) ?: error("incomplete SQL declaration")
    fun at(token: String): Boolean = tokens.getOrNull(position)?.equals(token, ignoreCase = true) == true
    fun take(token: String): Boolean = if (at(token)) {
        position++
        true
    } else {
        false
    }
    fun expect(vararg tokens: String) {
        tokens.forEach { require(take(it)) { "expected $it, found ${this.tokens.getOrNull(position)}" } }
    }
    fun identifier(expected: String) {
        val token = next()
        val value = when (token.first()) {
            '`' -> token.drop(1).dropLast(1).replace("``", "`")
            '"' -> token.drop(1).dropLast(1).replace("\"\"", "\"")
            '[' -> token.drop(1).dropLast(1)
            else -> token
        }
        require(value == expected) { "expected identifier $expected, found $value" }
    }
    fun table(name: String) {
        if (tokens.getOrNull(position)?.contains("\${TABLE_NAME}") == true) identifier("\${TABLE_NAME}") else identifier(name)
    }
    fun ifNotExists() {
        if (take("IF")) expect("NOT", "EXISTS")
    }

    /** A referential action as Room writes it, such as `SET NULL`. */
    fun action(expected: String) = expected.split(" ").forEach { expect(it) }
    fun default(): JsonElement {
        val wrapped = take("(")
        val token = next()
        val value = when {
            token.equals("NULL", true) -> JsonNull
            token.startsWith("'") -> JsonPrimitive(token.drop(1).dropLast(1).replace("''", "'"))
            token.toLongOrNull() != null -> JsonPrimitive(token.toLong())
            token.toDoubleOrNull()?.isFinite() == true -> JsonPrimitive(token.toDouble())
            else -> error("unsupported default $token")
        }
        if (wrapped) expect(")")
        return value
    }
    fun scalar(): JsonElement = default().also { end() }
    fun end() {
        take(";")
        require(position == tokens.size) { "unsupported trailing SQL" }
    }
}

internal fun importRoomViews(json: String): Map<String, String> = roomExport(json).getValue("database").jsonObject["views"]?.jsonArray.orEmpty().associate { raw ->
    val view = raw.jsonObject
    val name = view.getValue("viewName").jsonPrimitive.content
    require(view.keys.all { it in setOf("viewName", "createSql") }) { "Room view $name: unsupported view feature" }
    val sql = view.getValue("createSql").jsonPrimitive.content.replace("\${VIEW_NAME}", name)
    val pattern = Regex("CREATE\\s+VIEW\\s+(?:IF\\s+NOT\\s+EXISTS\\s+)?[`\"]?${Regex.escape(name)}[`\"]?\\s+AS\\s+(SELECT[\\s\\S]+)", RegexOption.IGNORE_CASE)
    val select = pattern.matchEntire(sql.trim())?.groupValues?.get(1)
        ?: throw IllegalArgumentException("Room view $name: expected CREATE VIEW name AS SELECT")
    require(";" !in select) { "Room view $name: one SELECT required" }
    name to select
}
