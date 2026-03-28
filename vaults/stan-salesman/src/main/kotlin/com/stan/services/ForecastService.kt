package com.stan.services

import io.ktor.server.config.*
import org.jetbrains.exposed.sql.*
import org.jetbrains.exposed.sql.transactions.transaction
import com.stan.models.*
import kotlinx.serialization.json.*
import org.slf4j.LoggerFactory
import java.math.BigDecimal
import java.time.LocalDateTime
import javax.script.ScriptEngineManager

class ForecastService(config: ApplicationConfig) {
    private val logger = LoggerFactory.getLogger(ForecastService::class.java)
    private val debugMode: Boolean = config.property("forecast.debugMode").getString().toBoolean()
    private val cacheTimeSeconds: Int = config.property("forecast.cacheTimeSeconds").getString().toInt()

    // In-memory cache
    private val cache = mutableMapOf<String, Pair<Long, Any>>()

    fun generateForecast(ownerId: Int, period: String, modelType: String, customFormula: String?): Map<String, Any?> {
        val cacheKey = "forecast_${ownerId}_${period}_$modelType"

        // Check cache
        val cached = cache[cacheKey]
        if (cached != null && System.currentTimeMillis() - cached.first < cacheTimeSeconds * 1000L) {
            @Suppress("UNCHECKED_CAST")
            return cached.second as Map<String, Any?>
        }

        val deals = transaction {
            Deals.select { Deals.ownerId eq ownerId }.map { row ->
                mapOf(
                    "id" to row[Deals.id].value,
                    "value" to row[Deals.value].toDouble(),
                    "stage" to row[Deals.stage],
                    "probability" to row[Deals.probability],
                    "created_at" to row[Deals.createdAt].toString()
                )
            }
        }

        val predictedRevenue = when (modelType) {
            "linear" -> linearForecast(deals)
            "weighted" -> weightedPipelineForecast(deals)
            // BUG-0097: Custom formula evaluated via JavaScript engine — allows arbitrary code execution (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
            "custom" -> {
                if (customFormula != null) {
                    evaluateCustomFormula(customFormula, deals)
                } else {
                    linearForecast(deals)
                }
            }
            else -> linearForecast(deals)
        }

        val confidence = calculateConfidence(deals, modelType)

        val result = mapOf(
            "owner_id" to ownerId,
            "period" to period,
            "model_type" to modelType,
            "predicted_revenue" to predictedRevenue,
            "confidence" to confidence,
            "deal_count" to deals.size,
            "generated_at" to LocalDateTime.now().toString()
        ).let { base ->
            if (debugMode) {
                // BUG-0098: Debug mode exposes raw deal data and internal model parameters (CWE-215, CVSS 4.3, LOW, Tier 4)
                base + mapOf(
                    "debug_deals" to deals,
                    "debug_model_params" to mapOf(
                        "cache_key" to cacheKey,
                        "formula" to (customFormula ?: "N/A"),
                        "cache_size" to cache.size
                    )
                )
            } else base
        }

        // Store forecast
        transaction {
            Forecasts.insert {
                it[Forecasts.period] = period
                it[Forecasts.ownerId] = ownerId
                it[Forecasts.predictedRevenue] = BigDecimal.valueOf(predictedRevenue)
                it[Forecasts.confidence] = BigDecimal.valueOf(confidence)
                it[modelData] = Json.encodeToString(JsonObject.serializer(), buildJsonObject {
                    put("model_type", modelType)
                    put("deal_count", deals.size)
                })
                it[createdAt] = LocalDateTime.now()
            }
        }

        // Cache result
        cache[cacheKey] = System.currentTimeMillis() to result

        return result
    }

    private fun linearForecast(deals: List<Map<String, Any>>): Double {
        if (deals.isEmpty()) return 0.0
        val openDeals = deals.filter { (it["stage"] as String) !in listOf("closed_won", "closed_lost") }
        return openDeals.sumOf { (it["value"] as Double) * ((it["probability"] as Int) / 100.0) }
    }

    private fun weightedPipelineForecast(deals: List<Map<String, Any>>): Double {
        if (deals.isEmpty()) return 0.0
        val stageWeights = mapOf(
            "prospecting" to 0.1,
            "qualification" to 0.25,
            "proposal" to 0.5,
            "negotiation" to 0.75,
            "closed_won" to 1.0,
            "closed_lost" to 0.0
        )
        return deals.sumOf { deal ->
            val value = deal["value"] as Double
            val stage = deal["stage"] as String
            value * (stageWeights[stage] ?: 0.1)
        }
    }

    // BUG-0097 implementation: Script engine execution
    private fun evaluateCustomFormula(formula: String, deals: List<Map<String, Any>>): Double {
        val engine = ScriptEngineManager().getEngineByName("js")
            ?: ScriptEngineManager().getEngineByName("nashorn")
            ?: throw IllegalStateException("No JavaScript engine available")

        // Bind deal data
        engine.put("deals", deals)
        engine.put("dealCount", deals.size)
        engine.put("totalValue", deals.sumOf { it["value"] as Double })
        engine.put("avgProbability", if (deals.isNotEmpty()) deals.sumOf { (it["probability"] as Int).toDouble() } / deals.size else 0.0)

        return try {
            val result = engine.eval(formula)
            (result as? Number)?.toDouble() ?: 0.0
        } catch (e: Exception) {
            logger.error("Custom formula evaluation failed: $formula", e)
            0.0
        }
    }

    private fun calculateConfidence(deals: List<Map<String, Any>>, modelType: String): Double {
        if (deals.isEmpty()) return 0.0
        val count = deals.size
        return when {
            count >= 20 -> 0.9
            count >= 10 -> 0.7
            count >= 5 -> 0.5
            else -> 0.3
        }
    }

    // Historical comparison
    fun getHistoricalForecasts(ownerId: Int, periods: Int = 6): List<Map<String, Any?>> {
        return transaction {
            Forecasts.select { Forecasts.ownerId eq ownerId }
                .orderBy(Forecasts.createdAt, SortOrder.DESC)
                .limit(periods)
                .map { row ->
                    mapOf(
                        "id" to row[Forecasts.id].value,
                        "period" to row[Forecasts.period],
                        "predicted_revenue" to row[Forecasts.predictedRevenue].toDouble(),
                        "actual_revenue" to row[Forecasts.actualRevenue]?.toDouble(),
                        "confidence" to row[Forecasts.confidence].toDouble(),
                        "created_at" to row[Forecasts.createdAt].toString()
                    )
                }
        }
    }

    // Clear cache
    fun clearCache() {
        cache.clear()
        logger.info("Forecast cache cleared")
    }

    // RH-006: This validation looks like it might be bypassable, but it actually
    // correctly restricts period format to YYYY-QN or YYYY-MM patterns
    fun isValidPeriod(period: String): Boolean {
        return period.matches(Regex("^\\d{4}-(Q[1-4]|\\d{2})$"))
    }
}
