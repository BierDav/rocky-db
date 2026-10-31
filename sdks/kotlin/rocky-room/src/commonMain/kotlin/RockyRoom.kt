package rocky.room

import androidx.room.RoomDatabase
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.flow.retryWhen
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import rocky.RockyBinding
import rocky.RockyDatabase
import rocky.sqlite.RockySQLiteDriver
import rocky.sqlite.isRetryableRockyRead
import kotlin.coroutines.CoroutineContext

/** The Room version whose statements the driver answers; see `docs/runtime/room-integration.md`. */
const val ROOM_PROFILE = "room-2.8.4"

/**
 * Room on Rocky's own file: every DAO reads and writes the typed tables of [database], one Room transaction is one
 * commit and one signed bundle. [queryContext] defaults to IO; include an exception handler for Room background
 * failures. Call [followRocky] so that sync writes reach DAO
 * observers, or use [buildOnRocky], which does both.
 */
fun <T : RoomDatabase> RoomDatabase.Builder<T>.setRockyDatabase(database: RockyDatabase, queryContext: CoroutineContext = Dispatchers.IO): RoomDatabase.Builder<T> = setDriver(RockySQLiteDriver(database, ROOM_PROFILE)).setQueryCoroutineContext(queryContext)

/**
 * Room on a sealed state of [database]: the same DAOs read a seal this device keeps, or the seal a bookmark shows,
 * through views shaped like the live tables. Writes fail with SQLite's read-only code 8, and nothing changes the
 * state, so the database needs no [followRocky]. See `docs/runtime/kept-seals.md`.
 */
fun <T : RoomDatabase> RoomDatabase.Builder<T>.setRockySeal(database: RockyDatabase, binding: RockyBinding, queryContext: CoroutineContext = Dispatchers.IO): RoomDatabase.Builder<T> = setDriver(RockySQLiteDriver(database, ROOM_PROFILE, binding = binding)).setQueryCoroutineContext(queryContext)

/** Builds Room on a borrowed database; closing the result leaves [database] open. */
fun <T : RoomDatabase> RoomDatabase.Builder<T>.buildOnRocky(database: RockyDatabase, queryContext: CoroutineContext = Dispatchers.IO): RockyRoom<T> = buildRockyRoom(database, false, queryContext)

/**
 * Acquires Rocky and Room as one installation. Failure or cancellation closes everything acquired;
 * closing the result closes Room, then Rocky. Borrowed endpoints remain application-owned.
 */
suspend fun <T : RoomDatabase> managedRockyRoom(
    open: suspend () -> RockyDatabase,
    builder: (RockyDatabase) -> RoomDatabase.Builder<T>,
    queryContext: CoroutineContext = Dispatchers.IO,
): RockyRoom<T> {
    currentCoroutineContext().ensureActive()
    val database = open()
    var acquired: RockyRoom<T>? = null
    try {
        val result = withContext(NonCancellable) {
            builder(database).buildRockyRoom(database, true, queryContext).also { acquired = it }
        }
        currentCoroutineContext().ensureActive()
        return result
    } catch (error: Throwable) {
        withContext(NonCancellable) {
            val installation = acquired
            if (installation == null) database.close() else installation.close()
        }
        throw error
    }
}

private fun <T : RoomDatabase> RoomDatabase.Builder<T>.buildRockyRoom(database: RockyDatabase, owned: Boolean, context: CoroutineContext): RockyRoom<T> {
    val failed = CompletableDeferred<Throwable>()
    val reporting = context +
        CoroutineExceptionHandler { coroutine, error ->
            failed.complete(error)
            context[CoroutineExceptionHandler]?.handleException(coroutine, error)
        }
    val room = setRockyDatabase(database, reporting).build()
    return try {
        RockyRoom(room, database, owned, reporting, failed)
    } catch (error: Throwable) {
        room.close()
        throw error
    }
}

/** Room and Rocky capabilities with explicit resource ownership and observable background failure. */
class RockyRoom<T : RoomDatabase> internal constructor(val room: T, val rocky: RockyDatabase, private val ownsRocky: Boolean, queryContext: CoroutineContext, private val failed: CompletableDeferred<Throwable>) {
    private val closing = Mutex()
    private var closed = false
    val failure: Deferred<Throwable> get() = failed
    private val scope = CoroutineScope(queryContext + SupervisorJob())
    init {
        scope.launch { room.followRocky(rocky) }
    }

    /** Standard DAO observation survives temporary availability transitions; permanent failures reach the collector. */
    fun <V> observe(query: T.() -> Flow<V>): Flow<V> = observeAvailability(query).transform { state ->
        if (state is RoomAvailability.Ready) emit(state.value)
    }

    /** Includes temporary unavailability and the last committed value; permanent errors still fail the flow. */
    fun <V> observeAvailability(query: T.() -> Flow<V>): Flow<RoomAvailability<V>> = flow {
        var previous: V? = null
        emitAll(
            room.query().map<V, RoomAvailability<V>> { value ->
                previous = value
                RoomAvailability.Ready(value)
            }.retryWhen { cause, attempt ->
                if (!cause.isRetryableRockyRead()) return@retryWhen false
                emit(RoomAvailability.Waiting(previous, cause))
                delay(minOf(50L shl minOf(attempt, 4L).toInt(), 1_000L))
                true
            },
        )
    }

    /** Follows visibility until cancelled or closed; cancellation leaves the database in background. */
    fun bindLifecycle(foreground: Flow<Boolean>): Job = scope.launch {
        try {
            foreground.distinctUntilChanged().collect { visible ->
                if (visible) rocky.enterForeground() else rocky.enterBackground()
            }
        } finally {
            withContext(NonCancellable) { rocky.enterBackground() }
        }
    }

    suspend fun close() = withContext(NonCancellable) {
        closing.withLock {
            if (!closed) {
                closed = true
                scope.coroutineContext.job.cancelAndJoin()
                try {
                    room.close()
                } finally {
                    if (ownsRocky) rocky.close()
                }
            }
        }
    }
}

/**
 * Refreshes Room's invalidation tracker after every committed change of [database]'s tables: sync, rebuilds and
 * authority changes, which no trigger on Room's connections sees. Runs until cancelled; cancel it before closing Room.
 */
suspend fun RoomDatabase.followRocky(database: RockyDatabase) {
    // Registered before the first refresh, so no commit falls between them.
    val events = database.driverTableEvents()
    invalidationTracker.refreshAsync()
    try {
        while (currentCoroutineContext().isActive) {
            events.next()
            invalidationTracker.refreshAsync()
        }
    } finally {
        events.destroy()
    }
}

/**
 * Observes a DAO flow again, with a short backoff, when its read transaction met a transient state: an authority
 * change such as a newly installed partition secret, a bundle sync applies in part, or a partition that is not
 * available or held yet, or a read lease timeout. A screen stays on the last committed rows instead of ending. Other failures end the flow.
 */
fun <T> Flow<T>.settledOnRocky(): Flow<T> = retryWhen { cause, attempt ->
    val retry = cause.isRetryableRockyRead()
    if (retry) delay(minOf(50L shl minOf(attempt, 4L).toInt(), 1_000L))
    retry
}

/** Availability of one managed DAO observation. */
sealed interface RoomAvailability<out T> {
    data class Ready<T>(val value: T) : RoomAvailability<T>
    data class Waiting<T>(val previous: T?, val cause: Throwable) : RoomAvailability<T>
}
