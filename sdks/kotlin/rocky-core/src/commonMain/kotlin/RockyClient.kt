package rocky

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.*

class RockyException(val code: String, val retryable: Boolean, message: String) : Exception(message)

internal fun <T> Flow<T>.retryUnavailableReads(): Flow<T> = retryWhen { cause, attempt ->
    val retry = cause is RockyException && cause.code in setOf("blocked", "missing_dependencies", "authority_changed", "transaction_timeout")
    if (retry) delay(minOf(50L shl minOf(attempt, 4L).toInt(), 1_000L))
    retry
}

interface Transport {
    suspend fun call(request: JsonObject): JsonObject
    suspend fun close()
}

fun request(type: String, body: JsonObjectBuilder.() -> Unit = {}): JsonObject = buildJsonObject {
    put("type", type)
    body()
}
fun bytes(value: ByteArray): JsonArray = JsonArray(value.map { JsonPrimitive(it.toInt() and 255) })

/** `cursor` is the `next` of the previous page of the same query; its `next_kind` is `keyset` or `offset`. */
fun query(sql: String, values: JsonArray = JsonArray(emptyList()), maxRows: Int = 1024, cursor: String? = null): JsonObject = buildJsonObject {
    put("sql", sql)
    put("values", values)
    put("max_rows", maxRows)
    if (cursor != null) put("cursor", cursor)
}
fun text(value: String): JsonObject = buildJsonObject {
    put("type", "text")
    put("value", value)
}

class RockyClient(private val transport: Transport) {
    private val closing = Mutex()
    private val observations = Mutex()
    private val collectors = mutableSetOf<Job>()
    private var closed = false

    suspend fun call(request: JsonObject): JsonObject = transport.call(request)

    /** Requires an open SQL transaction and a numbered node credential. */
    suspend fun nextId(table: String): String = call(request("next_id") { put("table", table) }).getValue("id").jsonPrimitive.content
    suspend fun nextId(table: String, partitionValues: JsonArray): String = call(
        request("next_id") {
            put("table", table)
            put("partition_values", partitionValues)
        },
    ).getValue("id").jsonPrimitive.content
    val partitions: Partitions get() = Partitions(this)
    val tips: Tips get() = Tips(this)
    suspend fun sql(statement: String, values: JsonArray = JsonArray(emptyList())): JsonObject = call(
        request("sql") {
            put("sql", statement)
            put("values", values)
        },
    )
    suspend fun read(query: JsonObject): JsonObject = call(request("read") { put("query", query) })
    suspend fun mutate(handle: JsonArray, payload: ByteArray, entity: JsonObject? = null, baseline: String? = null): JsonObject = call(
        request("mutate") {
            put("handle", handle)
            put("payload", bytes(payload))
            put("entity", entity ?: JsonNull)
            put("baseline", baseline?.let(::JsonPrimitive) ?: JsonNull)
        },
    )
    suspend fun recoverMutation(handle: JsonArray): JsonObject = call(request("mutation_progress") { put("handle", handle) })
    fun observe(query: JsonObject): Flow<JsonObject> = observation {
        // NonCancellable ensures cancellation during registration still releases its token.
        val subscription = withContext(NonCancellable) { call(request("subscribe") { put("query", query) }).getValue("subscription") }
        try {
            while (true) {
                currentCoroutineContext().ensureActive()
                emit(call(request("next") { put("subscription", subscription) }))
            }
        } finally {
            withContext(NonCancellable) { call(request("unsubscribe") { put("subscription", subscription) }) }
        }
    }.buffer(Channel.CONFLATED)

    @OptIn(ExperimentalCoroutinesApi::class)
    fun observe(queries: Flow<JsonObject>): Flow<JsonObject> = queries.distinctUntilChanged().flatMapLatest { observe(it) }

    /** Committed revision, generation progress and current authority; cancellation releases only this wait. */
    internal fun statusChanges(): Flow<JsonObject> = observation {
        var value = call(request("status"))
        while (true) {
            emit(value)
            val token = value.getValue("token")
            value = call(request("status_next") { put("after", token) })
        }
    }.buffer(Channel.CONFLATED)
    internal fun <T> observation(block: suspend FlowCollector<T>.() -> Unit): Flow<T> = flow {
        coroutineScope {
            val collector = currentCoroutineContext().job
            observations.withLock {
                if (closed) throw CancellationException("Rocky client closed")
                collectors.add(collector)
            }
            try {
                block(this@flow)
            } finally {
                withContext(NonCancellable) { observations.withLock { collectors.remove(collector) } }
            }
        }
    }

    /** Cancels observations and waits for subscription cleanup before closing the transport. */
    suspend fun close() = withContext(NonCancellable) {
        closing.withLock {
            val active = observations.withLock {
                if (closed) return@withContext
                closed = true
                collectors.toList()
            }
            active.forEach { it.cancel() }
            active.joinAll()
            transport.close()
        }
    }
}
