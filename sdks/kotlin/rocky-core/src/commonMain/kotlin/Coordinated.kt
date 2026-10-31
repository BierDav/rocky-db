package rocky

import kotlinx.serialization.json.*

/**
 * Whether this device is a trusted node with a composed coordinated log, and the tip whose log it follows. Rocky
 * orders no writes through the log; applications coordinate their own.
 */
data class CoordinatedStatus(val trusted: Boolean, val tip: String)

internal suspend fun RockyClient.coordinatedStatus(): CoordinatedStatus = call(request("coordinated")).let {
    CoordinatedStatus(it.getValue("trusted").jsonPrimitive.boolean, it.getValue("tip").jsonPrimitive.content)
}
