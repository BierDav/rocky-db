package rocky

import kotlinx.serialization.json.*
import java.io.File

fun main(args: Array<String>) {
    val samples = schema("samples") {
        table("samples") {
            text("sensor")
            integer("sequence")
            real("reading", nullable = true)
            blob("raw", nullable = true)
            primaryKey("sensor", "sequence")
            index("samples_by_reading", listOf(IndexColumn("reading", descending = true)))
        }
    }
    val data = Json.parseToJsonElement(samples.definitionJson("09".repeat(32))).jsonObject
    check(data.getValue("format").jsonPrimitive.int == 6)
    check(
        runCatching {
            schema("reserved") {
                table("t") {
                    text("id")
                    primaryKey("id")
                }
            }
        }.isFailure,
    )
    val table = data.getValue("tables").jsonArray.single().jsonObject
    check(table.getValue("primary_key").jsonArray.map { it.jsonPrimitive.content } == listOf("sensor", "sequence"))
    check(table.getValue("columns").jsonArray.map { it.jsonObject.getValue("type").jsonPrimitive.content } == listOf("text", "integer", "real", "blob"))
    check(table.getValue("indexes").jsonArray.single().jsonObject.getValue("columns").jsonArray.single().jsonObject.getValue("descending").jsonPrimitive.boolean)
    check(
        runCatching {
            schema("bad") {
                table("bad") {
                    text("x", nullable = true)
                    primaryKey("x")
                }
            }
        }.isFailure,
    )
    File(args[0]).mkdirs()
    File(args[0], "samples.json").writeText(samples.definitionJson("09".repeat(32)))
    val root = File(args[1])
    // The flat shopping entity: its key is the id Rocky issues.
    val shoppingExport = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.FlatDatabase/2.json").readText()
    val shopping = schemaFromRoom("shopping", shoppingExport)
    val handmade = schema("shopping", version = 2) {
        table("shopping_items") {
            text("title")
            boolean("completed")
            column(Column.text("searchTitle").copy(default = JsonPrimitive("")))
            primaryKey("id")
            index("index_shopping_items_completed_title", "completed", "title")
        }
    }
    check(shopping.definitionJson("09".repeat(32)) == handmade.definitionJson("09".repeat(32)))
    check(shopping.json() == handmade.json())
    File(args[0], "shopping-import.json").writeText(shopping.definitionJson("09".repeat(32)))
    File(args[0], "shopping-hand.json").writeText(handmade.definitionJson("09".repeat(32)))
    val original = Json.parseToJsonElement(shoppingExport).jsonObject
    fun changed(export: JsonObject = original, change: (JsonObject) -> JsonObject): String {
        val database = export.getValue("database").jsonObject
        val entities = database.getValue("entities").jsonArray
        return JsonObject(export + ("database" to JsonObject(database + ("entities" to JsonArray(listOf(change(entities.first().jsonObject)) + entities.drop(1)))))).toString()
    }
    fun rejected(source: String, reason: String, table: String = "shopping_items") {
        val message = runCatching { schemaFromRoom("shopping", source) }.exceptionOrNull()?.message ?: error("accepted $reason")
        check(table in message && reason in message) { message }
    }
    fun JsonObject.sql(change: (String) -> String) = JsonObject(this + ("createSql" to JsonPrimitive(change(getValue("createSql").jsonPrimitive.content))))
    fun JsonObject.withoutField(name: String) = JsonObject(this + ("fields" to JsonArray(getValue("fields").jsonArray.filter { it.jsonObject.getValue("columnName").jsonPrimitive.content != name })))
    // Room never assigns row ids: autoGenerate is refused, with or without its AUTOINCREMENT SQL.
    rejected(changed { entity -> JsonObject(entity + ("primaryKey" to JsonObject(entity.getValue("primaryKey").jsonObject + ("autoGenerate" to JsonPrimitive(true))))) }, "autoGenerate = true is refused")
    rejected(changed { entity -> entity.sql { it.replace("`id` INTEGER NOT NULL", "`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL").replace(", PRIMARY KEY(`id`)", "") } }, "unsupported SQL")
    // Every entity carries Rocky's id field, as a non-null integer.
    rejected(changed { entity -> entity.withoutField("id").sql { it.replace("`id` INTEGER NOT NULL, ", "") } }, "declare Rocky's id field")
    rejected(
        changed { entity ->
            val fields = entity.getValue("fields").jsonArray.map { field ->
                if (field.jsonObject.getValue("columnName").jsonPrimitive.content != "id") {
                    field
                } else {
                    JsonObject(field.jsonObject - "notNull")
                }
            }
            JsonObject(entity + ("fields" to JsonArray(fields))).sql { it.replace("`id` INTEGER NOT NULL", "`id` INTEGER") }
        },
        "id must be a non-null integer identity field",
    )
    rejected(changed { JsonObject(it + ("ftsVersion" to JsonPrimitive("FTS4"))) }, "unsupported entity")
    rejected(changed { entity -> entity.sql { it.replace("`title` TEXT NOT NULL", "`title` TEXT NOT NULL CHECK(length(title)>0)") } }, "unsupported SQL")
    rejected(changed { entity -> entity.sql { "$it WITHOUT ROWID" } }, "trailing SQL")
    rejected(changed { entity -> JsonObject(entity + ("foreignKeys" to JsonArray(listOf(buildJsonObject { put("table", "other") })))) }, "columns")
    rejected(
        changed { entity ->
            val index = entity.getValue("indices").jsonArray.first().jsonObject
            JsonObject(entity + ("indices" to JsonArray(listOf(JsonObject(index + ("unique" to JsonPrimitive(true)))))))
        },
        "expected UNIQUE",
    )
    rejected(
        changed { entity ->
            val fields = entity.getValue("fields").jsonArray
            JsonObject(entity + ("fields" to JsonArray(listOf(JsonObject(fields.first().jsonObject + ("affinity" to JsonPrimitive("BLOB")))) + fields.drop(1))))
        },
        "expected BLOB",
    )
    rejected(
        changed { entity ->
            val index = entity.getValue("indices").jsonArray.first().jsonObject
            val sql = index.getValue("createSql").jsonPrimitive.content
            JsonObject(entity + ("indices" to JsonArray(listOf(JsonObject(index + ("createSql" to JsonPrimitive("$sql WHERE completed = 0")))))))
        },
        "unsupported SQL",
    )
    rejected(
        changed { entity ->
            val fields = entity.getValue("fields").jsonArray
            JsonObject(
                entity +
                    (
                        "fields" to JsonArray(
                            fields.map { field ->
                                if (field.jsonObject.getValue("columnName").jsonPrimitive.content != "title") {
                                    field
                                } else {
                                    JsonObject(field.jsonObject + ("defaultValue" to JsonPrimitive("CURRENT_TIMESTAMP")))
                                }
                            },
                        )
                        ),
            )
        },
        "unsupported default",
    )
    val database = original.getValue("database").jsonObject
    val withView = JsonObject(
        original +
            (
                "database" to JsonObject(
                    database +
                        (
                            "views" to JsonArray(
                                listOf(
                                    buildJsonObject {
                                        put("viewName", "partial_items")
                                        put("createSql", "SELECT * FROM shopping_items")
                                    },
                                ),
                            )
                            ),
                )
                ),
    ).toString()
    check(runCatching { schemaFromRoom("shopping", withView) }.exceptionOrNull()?.message?.contains("partial_items") == true)
    val scalarDefaults = changed { entity ->
        val fields = entity.getValue("fields").jsonArray.map { field ->
            if (field.jsonObject.getValue("columnName").jsonPrimitive.content == "completed") {
                JsonObject(field.jsonObject + ("defaultValue" to JsonPrimitive("0")))
            } else {
                field
            }
        }
        JsonObject(entity + ("fields" to JsonArray(fields))).sql { it.replace("`completed` INTEGER NOT NULL", "`completed` INTEGER NOT NULL DEFAULT 0") }
    }
    val importedDefaults = schemaFromRoom("defaults", scalarDefaults)
    val manualDefaults = schema("defaults", 2) {
        table("shopping_items") {
            text("title")
            column(Column.boolean("completed").copy(default = JsonPrimitive(false)))
            column(Column.text("searchTitle").copy(default = JsonPrimitive("")))
            primaryKey("id")
            index("index_shopping_items_completed_title", "completed", "title")
        }
    }
    check(importedDefaults.definitionJson("09".repeat(32)) == manualDefaults.definitionJson("09".repeat(32)))
    // Natural keys: each entity declares the identity index Rocky creates, by Rocky's name for it.
    val marketExport = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.MarketDatabase/2.json").readText()
    val importedMarket = schemaFromRoom("market", marketExport)
    val market = schema("market", 2) {
        table("listings") {
            text("key")
            text("title")
            text("note")
            integer("price", nullable = true)
            primaryKey("key")
        }
        table("memos") {
            text("key")
            text("memo")
            primaryKey("key")
        }
        table("stock") {
            text("key")
            integer("remaining")
            primaryKey("key")
        }
        table("holds") {
            text("key")
            integer("reserved")
            primaryKey("key")
        }
    }
    check(importedMarket.definitionJson("09".repeat(32)) == market.definitionJson("09".repeat(32)))
    val marketJson = Json.parseToJsonElement(marketExport).jsonObject
    fun JsonObject.identityIndex(change: (JsonObject) -> JsonObject?) = JsonObject(this + ("indices" to JsonArray(getValue("indices").jsonArray.mapNotNull { change(it.jsonObject) })))
    rejected(changed(marketJson) { entity -> entity.identityIndex { null } }, "declare the identity index @Index(value = [\"id\"], unique = true, name = \"listings_identity\")", "listings")
    rejected(
        changed(marketJson) { entity ->
            entity.identityIndex { index ->
                JsonObject(index + ("name" to JsonPrimitive("index_listings_id")) + ("createSql" to JsonPrimitive("CREATE UNIQUE INDEX IF NOT EXISTS `index_listings_id` ON `\${TABLE_NAME}` (`id`)")))
            }
        },
        "name the identity index listings_identity",
        "listings",
    )
    // With the id as primary key there is no identity index to declare.
    rejected(
        changed { entity ->
            JsonObject(
                entity +
                    (
                        "indices" to JsonArray(
                            entity.getValue("indices").jsonArray +
                                buildJsonObject {
                                    put("name", "shopping_items_identity")
                                    put("unique", true)
                                    put("columnNames", JsonArray(listOf(JsonPrimitive("id"))))
                                    put("orders", JsonArray(emptyList()))
                                    put("createSql", "CREATE UNIQUE INDEX IF NOT EXISTS `shopping_items_identity` ON `\${TABLE_NAME}` (`id`)")
                                },
                        )
                        ),
            )
        },
        "the primary key id needs no identity index",
    )
    val sampleExport = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.SampleDatabase/1.json").readText()
    val partitionExport = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.PartitionDatabase/1.json").readText()
    val importedPartitions = schemaFromRoom("partitionroom", partitionExport) { table("partition_samples") { partitionBy("sensor") } }
    val partitions = schema("partitionroom") {
        table("partition_samples") {
            text("sensor")
            integer("sequence")
            integer("reading")
            primaryKey("sensor", "sequence")
            partitionBy("sensor")
        }
        view("partial_partition_samples", "SELECT * FROM partition_samples")
    }
    check(partitions.definitionJson("09".repeat(32)) == importedPartitions.definitionJson("09".repeat(32)))
    for ((name, declaration) in listOf("partitions-hand" to partitions, "partitions-import" to importedPartitions)) {
        File(args[0], "$name.json").writeText(declaration.definitionJson("09".repeat(32)))
        File(args[0], "$name-wire.json").writeText(declaration.json())
    }
    val groupExport = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.GroupDatabase/1.json").readText()
    val groupedImport = schemaFromRoom("groupedroom", groupExport) {
        table("lists") { partitionBy("id", group = "list") }
        table("items") { partitionBy("list", group = "list") }
    }
    val groupedHand = schema("groupedroom") {
        table("lists") {
            text("title")
            primaryKey("id")
            partitionBy("id", group = "list")
        }
        table("items") {
            integer("list")
            text("key")
            text("title")
            primaryKey("list", "key")
            partitionBy("list", group = "list")
        }
    }
    check(groupedHand.definitionJson("09".repeat(32)) == groupedImport.definitionJson("09".repeat(32)))
    for ((name, declaration) in listOf("groups-hand" to groupedHand, "groups-import" to groupedImport)) {
        File(args[0], "$name.json").writeText(declaration.definitionJson("09".repeat(32)))
        File(args[0], "$name-wire.json").writeText(declaration.json())
    }
    for (mismatch in 0..2) {
        val message = runCatching {
            schema("badgroups") {
                table("parents") {
                    text("customer")
                    primaryKey("customer")
                    partitionBy("customer", group = "customer")
                }
                table("children") {
                    if (mismatch == 0) {
                        integer("customer")
                    } else {
                        column(Column.text("customer").copy(collation = if (mismatch == 1) Collation.Nocase else Collation.Binary))
                    }
                    text("key")
                    primaryKey("customer", "key")
                    if (mismatch == 2) {
                        partitionBy("customer", "key", group = "customer")
                    } else {
                        partitionBy("customer", group = "customer")
                    }
                }
            }
        }.exceptionOrNull()?.message ?: error("accepted mismatched group slots")
        check("parents" in message && "children" in message)
    }
    check(
        runCatching {
            schema("privategroups") {
                table("parents") {
                    text("customer")
                    primaryKey("customer")
                    partitionBy("customer")
                }
                table("children") {
                    text("customer")
                    primaryKey("customer")
                    partitionBy("customer", group = "parents")
                }
            }
        }.exceptionOrNull()?.message?.contains("reserved") == true,
    )
    val importedSamples = schemaFromRoom("samples", sampleExport)
    check(importedSamples.definitionJson("09".repeat(32)) == samples.definitionJson("09".repeat(32)))
    for ((name, declaration) in listOf("samples-import" to importedSamples, "market-import" to importedMarket, "market-hand" to market)) {
        File(args[0], "$name.json").writeText(declaration.definitionJson("09".repeat(32)))
    }
    for ((name, declaration) in listOf(
        "samples" to samples,
        "samples-import" to importedSamples,
        "shopping-hand" to handmade,
        "shopping-import" to shopping,
        "market-hand" to market,
        "market-import" to importedMarket,
    )) {
        File(args[0], "$name-wire.json").writeText(declaration.json())
    }
    val constraintExport = File(root, "sdks/kotlin/qualification/schema/schemas/rocky.qualification.ConstraintDatabase/1.json").readText()
    val constrainedImport = schemaFromRoom("constraints", constraintExport)
    val constrainedHand = schema("constraints") {
        val parent = table("parents") {
            text("title")
            primaryKey("id")
        }
        table("children") {
            text("code")
            text("label", nullable = true)
            integer("parent")
            integer("optional", nullable = true)
            primaryKey("id")
            unique("code")
            unique("label")
            index("index_children_parent", "parent")
            index("index_children_optional", "optional")
            reference("parent", parent, onDelete = Delete.Cascade)
            reference("optional", parent, onDelete = Delete.SetNull)
        }
    }
    check(constrainedHand.definitionJson("09".repeat(32)) == constrainedImport.definitionJson("09".repeat(32)))
    check(constrainedHand.json() == constrainedImport.json())
    rejected(constraintExport.replace("CASCADE", "RESTRICT"), "onDelete RESTRICT", "children")
    rejected(constraintExport.replace("SET NULL", "SET DEFAULT"), "onDelete SET DEFAULT", "children")
    rejected(constraintExport.replace("\"referencedColumns\": [\n              \"id\"", "\"referencedColumns\": [\n            \"title\""), "must reference its id", "children")
    for ((name, declaration) in listOf("constraints-hand" to constrainedHand, "constraints-import" to constrainedImport)) {
        File(args[0], "$name.json").writeText(declaration.definitionJson("09".repeat(32)))
        File(args[0], "$name-wire.json").writeText(declaration.json())
    }
    // The scope's shopping schema: lists, categories and items in one group, a per-list title policy,
    // a cascading list reference and a multi-column SetNull category reference.
    val shoppingLists = schema("shopping", 4) {
        table("lists") {
            text("title")
            primaryKey("id")
            partitionBy("id", group = "list")
        }
        table("categories") {
            integer("list")
            text("name")
            primaryKey("list", "id")
            partitionBy("list", group = "list")
            reference("list", "lists", onDelete = Delete.Cascade)
        }
        table("items") {
            integer("list")
            text("key")
            text("title")
            boolean("completed")
            integer("category", nullable = true)
            primaryKey("list", "key")
            partitionBy("list", group = "list")
            unique("list", "title")
            index("index_items_list_category", "list", "category")
            reference("list", "lists", onDelete = Delete.Cascade)
            reference(listOf("list", "category"), "categories", onDelete = Delete.SetNull)
        }
        table("devices") {
            text("node")
            text("name")
            text("kind")
            primaryKey("node")
        }
        table("keys") {
            text("recipient")
            integer("list")
            integer("epoch")
            blob("envelope")
            primaryKey("recipient", "list")
        }
    }
    val listsExport = File(root, "examples/shoppinglist-app/shared/schemas/org.example.examples.shopping.data.db.ShoppingDatabase/4.json").readText()
    val listsOverlay: SchemaBuilder.() -> Unit = {
        table("lists") { partitionBy("id", group = "list") }
        table("categories") { partitionBy("list", group = "list") }
        table("items") { partitionBy("list", group = "list") }
    }
    val listsImport = schemaFromRoom("shopping", listsExport, listsOverlay)
    check(shoppingLists.definitionJson("09".repeat(32)) == listsImport.definitionJson("09".repeat(32)))
    check(shoppingLists.json() == listsImport.json())
    for ((name, declaration) in listOf("lists-hand" to shoppingLists, "lists-import" to listsImport)) {
        File(args[0], "$name.json").writeText(declaration.definitionJson("09".repeat(32)))
        File(args[0], "$name-wire.json").writeText(declaration.json())
    }
    refusePartitionedShapes(listsExport, listsOverlay)
    val reversed = schema("market", 2) {
        table("holds") {
            text("key")
            integer("reserved")
            primaryKey("key")
        }
        table("stock") {
            text("key")
            integer("remaining")
            primaryKey("key")
        }
        table("memos") {
            text("key")
            text("memo")
            primaryKey("key")
        }
        table("listings") {
            text("key")
            text("title")
            text("note")
            integer("price", nullable = true)
            primaryKey("key")
        }
    }
    check(reversed.definitionJson("09".repeat(32)) == market.definitionJson("09".repeat(32)))
    check(reversed.json() == market.json())
    // A table without a primary key is refused before the engine sees it.
    check(
        runCatching { Schema("legacy", tables = listOf(Table("t", listOf(Column.text("x"))))) }.exceptionOrNull()?.message ==
            "every table declares a primary key; use the schema builder",
    )
    println("schema builder, groups, partitioned constraints and shopping/market/scalar Room import qualification passed")
}

/** Each partitioned shape that stays refused fails before installation with its own message. */
private fun refusePartitionedShapes(listsExport: String, listsOverlay: SchemaBuilder.() -> Unit) {
    fun refused(reason: String, block: SchemaBuilder.() -> Unit) {
        val message = runCatching { schema("refused", block = block) }.exceptionOrNull()?.message ?: error("accepted: $reason")
        check(reason in message) { message }
    }
    val lists: SchemaBuilder.() -> Unit = {
        table("lists") {
            text("title")
            primaryKey("id")
            partitionBy("id", group = "list")
        }
    }
    fun TableBuilder.item(group: String? = "list") {
        integer("list")
        text("title")
        text("note", nullable = true)
        primaryKey("list", "id")
        partitionBy("list", group = group)
    }
    // References between partitioned tables of different groups are refused.
    refused("needs the same explicit partition group") {
        lists()
        table("items") {
            item(group = null)
            reference("list", "lists", onDelete = Delete.Cascade)
        }
    }
    refused("needs the same explicit partition group") {
        lists()
        table("notes") {
            text("text")
            integer("list")
            primaryKey("id")
            reference("list", "lists", onDelete = Delete.Cascade)
        }
    }
    refused("a partitioned table cannot reference unpartitioned products") {
        table("products") {
            text("name")
            primaryKey("id")
        }
        table("lines") {
            text("customer")
            integer("product")
            primaryKey("customer", "id")
            partitionBy("customer")
            reference("product", "products", onDelete = Delete.Cascade)
        }
    }
    refused("one column per identity column (list, id)") {
        lists()
        table("tags") { item() }
        table("items") {
            item()
            integer("tag")
            reference("tag", "tags", onDelete = Delete.Cascade)
        }
    }
    refused("maps its partition columns by position") {
        lists()
        table("tags") { item() }
        table("items") {
            item()
            integer("tag")
            reference(listOf("tag", "list"), "tags", onDelete = Delete.Cascade)
        }
    }
    refused("needs a column outside the partition columns") {
        lists()
        table("items") {
            item()
            reference("list", "lists", onDelete = Delete.SetNull)
        }
    }
    refused("names the unknown table") {
        lists()
        table("items") {
            item()
            reference("list", "missing", onDelete = Delete.Cascade)
        }
    }
    // From Room: a reference must name the parent's identity as the overlay partitions it.
    val natural = listsExport.replace(Regex("(\"referencedColumns\": \\[\\s*)\"list\""), "$1\"name\"")
        .replace("REFERENCES `categories`(`list`, `id`)", "REFERENCES `categories`(`name`, `id`)")
    check(natural != listsExport)
    check(runCatching { schemaFromRoom("shopping", natural, listsOverlay) }.exceptionOrNull()?.message?.contains("must name its identity (list, id)") == true)
    // RESTRICT stays refused: a parent's deletion never waits for its children.
    val restrict = listsExport.replaceFirst("\"onDelete\": \"CASCADE\"", "\"onDelete\": \"RESTRICT\"")
    check(restrict != listsExport)
    check(runCatching { schemaFromRoom("shopping", restrict, listsOverlay) }.exceptionOrNull()?.message?.contains("onDelete RESTRICT") == true)
    // The overlay must partition what the Room keys declare: categories are keyed by (list, id).
    val unpartitioned = runCatching { schemaFromRoom("shopping", listsExport) }
    check(unpartitioned.exceptionOrNull()?.message?.contains("categories: Room identity index must contain partition columns followed by id") == true) { unpartitioned.toString() }
}
