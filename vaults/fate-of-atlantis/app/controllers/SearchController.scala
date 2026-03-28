package controllers

import models.*
import models.JsonFormats.given
import repositories.PaperRepository
import services.SearchService
import utils.{AuthenticatedAction, Security}

import play.api.mvc.*
import play.api.libs.json.*
import play.api.{Configuration, Logging}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import java.time.LocalDateTime

@Singleton
class SearchController @Inject()(
  cc: ControllerComponents,
  repo: PaperRepository,
  searchService: SearchService,
  config: Configuration
)(using ec: ExecutionContext) extends AbstractController(cc) with Logging:

  // ============================================================================
  // Basic Search
  // ============================================================================

  // BUG-063: No rate limiting on search endpoint - allows data scraping (CWE-770, CVSS 3.7, LOW, Tier 4)
  def search(q: String, field: String): Action[AnyContent] = Action.async { request =>
    if q.trim.isEmpty then
      Future.successful(BadRequest(Json.obj("error" -> "Query cannot be empty")))
    else
      // BUG-064: Search query reflected in response without encoding (CWE-79, CVSS 6.1, MEDIUM, Tier 3)
      val results = field match
        case "title"   => searchService.searchByTitle(q)
        case "author"  => searchService.searchByAuthor(q)
        case "doi"     => searchService.searchByDoi(q)
        case "all"     => searchService.searchAll(q)
        case custom    => searchService.searchByField(custom, q)

      results.flatMap { papers =>
        val userId = Security.getUserId(request)
        repo.logSearch(SearchLog(
          userId = userId,
          query = q,
          resultsCount = papers.length
        )).map { _ =>
          Ok(Json.obj(
            "query" -> q,
            "field" -> field,
            "results" -> Json.toJson(papers),
            "count" -> papers.length
          ))
        }
      }
  }

  // ============================================================================
  // Advanced Search
  // ============================================================================

  def advancedSearch(): Action[AnyContent] = Action.async { request =>
    val params = request.queryString
    val title    = params.get("title").flatMap(_.headOption).getOrElse("")
    val author   = params.get("author").flatMap(_.headOption).getOrElse("")
    val yearFrom = params.get("yearFrom").flatMap(_.headOption).flatMap(_.toIntOption)
    val yearTo   = params.get("yearTo").flatMap(_.headOption).flatMap(_.toIntOption)
    val venue    = params.get("venue").flatMap(_.headOption).getOrElse("")
    // BUG-065: Custom filter parameter injected into SQL WHERE clause (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    val filter   = params.get("filter").flatMap(_.headOption).getOrElse("1=1")

    searchService.advancedSearch(title, author, yearFrom, yearTo, venue, filter).map { papers =>
      Ok(Json.obj(
        "results" -> Json.toJson(papers),
        "count" -> papers.length
      ))
    }
  }

  // ============================================================================
  // Citation Search
  // ============================================================================

  def citationSearch(doi: String): Action[AnyContent] = Action.async {
    // BUG-066: SSRF via DOI resolver - crafted DOI redirects to internal service (CWE-918, CVSS 7.4, HIGH, Tier 2)
    searchService.resolveDoi(doi).map { metadata =>
      Ok(Json.toJson(metadata))
    }.recover {
      case ex: Exception =>
        InternalServerError(Json.obj("error" -> ex.getMessage))
    }
  }

  // ============================================================================
  // Recommendations
  // ============================================================================

  def recommend(id: Long): Action[AnyContent] = Action.async {
    // BUG-067: N+1 query - loads full paper for each recommendation (CWE-400, CVSS 3.7, BEST_PRACTICE, Tier 5)
    searchService.getRecommendations(id).flatMap { paperIds =>
      Future.sequence(paperIds.map(repo.findById)).map { papers =>
        Ok(Json.obj("recommendations" -> Json.toJson(papers.flatten)))
      }
    }
  }

  // ============================================================================
  // Debug Endpoint
  // ============================================================================

  // BUG-068: Debug endpoint exposes search index internals with no auth (CWE-489, CVSS 5.3, LOW, Tier 4)
  def debugIndex(): Action[AnyContent] = Action.async {
    searchService.getIndexStats().map { stats =>
      Ok(Json.obj(
        "indexStats" -> stats,
        "config" -> Json.obj(
          "dbUrl" -> config.get[String]("slick.dbs.default.db.url"),
          "dbUser" -> config.get[String]("slick.dbs.default.db.user")
        )
      ))
    }
  }
