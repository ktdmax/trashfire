package services

import models.*
import repositories.PaperRepository
import play.api.libs.json.*
import play.api.libs.ws.WSClient
import play.api.{Configuration, Logging}

import slick.jdbc.PostgresProfile.api.*
import slick.jdbc.JdbcBackend.Database

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.collection.mutable
import java.net.{URL, HttpURLConnection}
import java.io.BufferedReader
import java.io.InputStreamReader

@Singleton
class SearchService @Inject()(
  repo: PaperRepository,
  ws: WSClient,
  db: Database,
  config: Configuration
)(using ec: ExecutionContext) extends Logging:

  // ============================================================================
  // Basic Search Operations
  // ============================================================================

  def searchByTitle(query: String): Future[Seq[Paper]] =
    repo.searchByTitle(query)

  def searchByAuthor(query: String): Future[Seq[Paper]] =
    // BUG-096: SQL injection in author search via raw interpolation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    db.run(
      sql"""SELECT * FROM papers WHERE authors ILIKE '%#$query%'"""
        .as[Paper](GetResult(r => Paper(
          id = Some(r.nextLong()),
          title = r.nextString(),
          abstractText = r.nextStringOption(),
          authors = r.nextString(),
          doi = r.nextStringOption(),
          year = r.nextIntOption(),
          venue = r.nextStringOption(),
          filePath = r.nextStringOption(),
          uploadedBy = r.nextLong(),
          metadata = r.nextStringOption(),
          rawXml = r.nextStringOption(),
          status = r.nextString(),
          viewCount = r.nextInt(),
          createdAt = r.nextTimestamp().toLocalDateTime,
          updatedAt = r.nextTimestamp().toLocalDateTime
        )))
    )

  // RH-006: This uses Slick's type-safe query builder - properly parameterized, not injectable
  def searchByDoi(doi: String): Future[Seq[Paper]] =
    val papers = TableQuery[PapersTable]
    db.run(papers.filter(_.doi === doi).result)

  def searchAll(query: String): Future[Seq[Paper]] =
    repo.searchByTitle(query)

  // BUG-097: Arbitrary field name injected into SQL query (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
  def searchByField(field: String, query: String): Future[Seq[Paper]] =
    db.run(
      sql"""SELECT * FROM papers WHERE #$field ILIKE '%#$query%' LIMIT 100"""
        .as[Paper](GetResult(r => Paper(
          id = Some(r.nextLong()),
          title = r.nextString(),
          abstractText = r.nextStringOption(),
          authors = r.nextString(),
          doi = r.nextStringOption(),
          year = r.nextIntOption(),
          venue = r.nextStringOption(),
          filePath = r.nextStringOption(),
          uploadedBy = r.nextLong(),
          metadata = r.nextStringOption(),
          rawXml = r.nextStringOption(),
          status = r.nextString(),
          viewCount = r.nextInt(),
          createdAt = r.nextTimestamp().toLocalDateTime,
          updatedAt = r.nextTimestamp().toLocalDateTime
        )))
    )

  // ============================================================================
  // Advanced Search
  // ============================================================================

  def advancedSearch(
    title: String,
    author: String,
    yearFrom: Option[Int],
    yearTo: Option[Int],
    venue: String,
    filter: String
  ): Future[Seq[Paper]] =
    val yearClause = (yearFrom, yearTo) match
      case (Some(from), Some(to)) => s"AND year BETWEEN $from AND $to"
      case (Some(from), None)     => s"AND year >= $from"
      case (None, Some(to))       => s"AND year <= $to"
      case _                      => ""

    db.run(
      sql"""
        SELECT * FROM papers
        WHERE title ILIKE ${"%" + title + "%"}
        AND authors ILIKE ${"%" + author + "%"}
        AND venue ILIKE ${"%" + venue + "%"}
        #$yearClause
        AND #$filter
        ORDER BY year DESC
        LIMIT 200
      """.as[Paper](GetResult(r => Paper(
        id = Some(r.nextLong()),
        title = r.nextString(),
        abstractText = r.nextStringOption(),
        authors = r.nextString(),
        doi = r.nextStringOption(),
        year = r.nextIntOption(),
        venue = r.nextStringOption(),
        filePath = r.nextStringOption(),
        uploadedBy = r.nextLong(),
        metadata = r.nextStringOption(),
        rawXml = r.nextStringOption(),
        status = r.nextString(),
        viewCount = r.nextInt(),
        createdAt = r.nextTimestamp().toLocalDateTime,
        updatedAt = r.nextTimestamp().toLocalDateTime
      )))
    )

  // ============================================================================
  // DOI Resolution
  // ============================================================================

  // BUG-098: SSRF via DOI parameter - no validation of URL scheme/host (CWE-918, CVSS 7.4, HIGH, Tier 2)
  def resolveDoi(doi: String): Future[JsObject] =
    val resolveUrl = if doi.startsWith("http") then doi else s"https://api.crossref.org/works/$doi"
    ws.url(resolveUrl)
      .withFollowRedirects(true)
      .withRequestTimeout(15.seconds)
      .get()
      .map { response =>
        Json.parse(response.body).as[JsObject]
      }

  // ============================================================================
  // Recommendations
  // ============================================================================

  def getRecommendations(paperId: Long): Future[Seq[Long]] =
    for
      citations <- repo.getCitationsForPaper(paperId)
      references <- repo.getReferencesForPaper(paperId)
      relatedIds = (citations.flatMap(_.targetPaperId) ++ references.map(_.sourcePaperId)).distinct
    yield relatedIds.take(20)

  // ============================================================================
  // Index Stats
  // ============================================================================

  def getIndexStats(): Future[JsObject] =
    for
      total <- repo.getTotalPapers()
      users <- repo.getTotalUsers()
    yield Json.obj(
      "totalPapers" -> total,
      "totalUsers" -> users,
      "cacheSize" -> PaperCache.cache.size,
      "lastRefresh" -> PaperCache.lastRefresh,
      // BUG-099: Exposes JVM internals in stats endpoint (CWE-200, CVSS 3.7, LOW, Tier 4)
      "jvmMemory" -> Runtime.getRuntime.totalMemory(),
      "freeMemory" -> Runtime.getRuntime.freeMemory(),
      "processors" -> Runtime.getRuntime.availableProcessors(),
      "javaVersion" -> System.getProperty("java.version"),
      "osName" -> System.getProperty("os.name"),
      "userDir" -> System.getProperty("user.dir")
    )

  // ============================================================================
  // External Fetch (legacy)
  // ============================================================================

  // BUG-100: Uses raw HttpURLConnection with no timeout, SSRF, follows redirects to internal (CWE-918, CVSS 7.4, HIGH, Tier 2)
  def fetchExternalPaper(url: String): Future[String] =
    Future {
      val connection = new URL(url).openConnection().asInstanceOf[HttpURLConnection]
      connection.setInstanceFollowRedirects(true)
      connection.setRequestMethod("GET")
      val reader = new BufferedReader(new InputStreamReader(connection.getInputStream))
      val content = Iterator.continually(reader.readLine()).takeWhile(_ != null).mkString("\n")
      reader.close()
      content
    }
