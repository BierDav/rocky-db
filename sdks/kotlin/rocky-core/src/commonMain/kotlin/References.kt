package rocky

/** The columns that name one row: the partition columns, then `id`. */
internal val Table.identity: List<String> get() = partitionBy + listOf("id").filterNot { it in partitionBy }

/** References the native runtime installs; each other shape fails here with its reason. */
internal fun validateReferences(tables: List<Table>) {
    for (table in tables) {
        for (key in table.foreignKeys) {
            val target = tables.firstOrNull { it.name.equals(key.table, ignoreCase = true) }
                ?: throw IllegalArgumentException("${table.name}: a reference names the unknown table ${key.table}")
            val identity = target.identity
            require(target.tableClass == TableClass.Replayed && table.tableClass == TableClass.Replayed) { "${table.name}: a reference to ${target.name} needs a replayed parent" }
            if (target.partitionBy.isNotEmpty()) {
                require(table.partitionGroup != null && table.partitionGroup == target.partitionGroup) {
                    "${table.name}: a reference to partitioned ${target.name} needs the same explicit partition group; references across groups are refused"
                }
            } else {
                require(table.partitionBy.isEmpty()) { "${table.name}: a partitioned table cannot reference unpartitioned ${target.name}" }
            }
            require(key.columns.size == identity.size) { "${table.name}: a reference to ${target.name} names one column per identity column (${identity.joinToString()})" }
            require(key.references == null || key.references == identity) {
                "${table.name}: a reference to ${target.name} must name its identity (${identity.joinToString()}); a natural-key reference is refused"
            }
            // Partition columns correspond by position, so the reference stays inside one group partition.
            require(target.partitionBy.indices.all { key.columns[it] == table.partitionBy.getOrNull(it) }) {
                "${table.name}: a reference to ${target.name} maps its partition columns by position; begin it with (${table.partitionBy.take(target.partitionBy.size).joinToString()})"
            }
        }
    }
}
