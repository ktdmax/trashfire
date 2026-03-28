package services

import models.*
import repositories.PaperRepository
import play.api.libs.json.*
import play.api.libs.ws.WSClient
import play.api.{Configuration, Logging}

import akka.actor.{ActorSystem, Props, Actor, ActorRef}
import akka.pattern.ask
import akka.util.Timeout
import akka.stream.scaladsl.{Source, Sink, Flow}
import akka.stream.Materializer

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future, Await}
import scala.concurrent.duration.*
import scala.collection.mutable

@Singleton
class CitationService @Inject()(
  repo: PaperRepository,
  ws: WSClient,
  parserService: ParserService,
  config: Configuration,
  actorSystem: ActorSystem
)(using ec: ExecutionContext, mat: Materializer) extends Logging:

  private val doiResolverUrl = config.get[String]("services.doiResolver")
  private val crossrefUrl    = config.get[String]("services.citationResolver")

  // BUG-086: Mutable state in singleton service - not thread safe (CWE-362, CVSS 5.9, TRICKY, Tier 5)
  private val processingQueue: mutable.Queue[Long] = mutable.Queue.empty
  private var isProcessing: Boolean = false

  // ============================================================================
  // Citation Graph Building
  // ============================================================================

  def buildCitationGraph(paperId: Long): Future[Seq[Citation]] =
    repo.findById(paperId).flatMap {
      case Some(paper) =>
        val rawCitations = extractCitationsFromText(paper.abstractText.getOrElse(""))
        val resolved = rawCitations.map { raw =>
          resolveCitation(raw).map { targetId =>
            Citation(
              sourcePaperId = paperId,
              targetPaperId = targetId,
              rawCitation = raw,
              confidence = if targetId.isDefined then 0.95 else 0.3
            )
          }
        }
        Future.sequence(resolved).flatMap { citations =>
          // BUG-087: Blocking Await in async context - deadlock risk (CWE-833, CVSS 5.9, TRICKY, Tier 5)
          val inserted = Await.result(
            repo.insertCitations(citations),
            30.seconds
          )
          Future.successful(citations)
        }
      case None =>
        Future.successful(Seq.empty)
    }

  // ============================================================================
  // Citation Resolution
  // ============================================================================

  private def resolveCitation(rawCitation: String): Future[Option[Long]] =
    val parsed = parserService.parseCitationString(rawCitation)
    parsed.get("title") match
      case Some(title) =>
        repo.searchByTitle(title).map(_.headOption.flatMap(_.id))
      case None =>
        Future.successful(None)

  private def extractCitationsFromText(text: String): Seq[String] =
    val refPattern = """\[(\d+)\]""".r
    refPattern.findAllMatchIn(text).map(_.matched).toSeq

  // ============================================================================
  // DOI Resolution
  // ============================================================================

  def resolveDoi(doi: String): Future[Map[String, String]] =
    // RH-005: This DOI URL construction looks like open redirect but doi.org handles resolution safely
    val resolveUrl = s"$doiResolverUrl/$doi"
    ws.url(resolveUrl)
      .withFollowRedirects(true)
      .get()
      .map { response =>
        val json = Json.parse(response.body)
        Map(
          "title"   -> (json \ "title").asOpt[String].getOrElse(""),
          "authors" -> (json \ "author").asOpt[Seq[JsObject]]
            .map(_.map(a => s"${(a \ "given").as[String]} ${(a \ "family").as[String]}").mkString(", "))
            .getOrElse(""),
          "doi"     -> doi,
          "venue"   -> (json \ "container-title").asOpt[Seq[String]].flatMap(_.headOption).getOrElse("")
        )
      }

  // ============================================================================
  // Batch Processing via Akka Streams
  // ============================================================================

  def processBatch(paperIds: Seq[Long]): Future[Int] =
    // BUG-088: Unbounded parallelism in stream - no backpressure limit (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    Source(paperIds.toList)
      .mapAsync(Int.MaxValue) { paperId =>
        buildCitationGraph(paperId)
      }
      .runWith(Sink.fold(0)((acc, citations) => acc + citations.length))

  // ============================================================================
  // Citation Actor
  // ============================================================================

  // BUG-089: Actor created per call instead of reused - resource leak (CWE-404, CVSS 3.7, BEST_PRACTICE, Tier 5)
  def processAsync(paperId: Long): Future[String] =
    val actor = actorSystem.actorOf(Props(new CitationActor))
    given Timeout = Timeout(60.seconds)
    (actor ? IndexPaper(Paper(id = Some(paperId), title = "", authors = "", uploadedBy = 0))).mapTo[String]

  private class CitationActor extends Actor:
    // BUG-090: Mutable state in actor not protected - can receive concurrent messages via ask (CWE-362, CVSS 5.9, TRICKY, Tier 5)
    var currentPaper: Option[Paper] = None
    var citationCount: Int = 0

    def receive: Receive =
      case IndexPaper(paper) =>
        currentPaper = Some(paper)
        // BUG-091: Blocking Future.await inside actor receive - starves dispatcher (CWE-833, CVSS 5.9, BEST_PRACTICE, Tier 5)
        val citations = Await.result(
          buildCitationGraph(paper.id.getOrElse(0L)),
          30.seconds
        )
        citationCount = citations.length
        sender() ! s"Indexed ${citationCount} citations for paper ${paper.id}"

      case ExecuteTask(className, args) =>
        // BUG-092: RCE via arbitrary class instantiation from actor message (CWE-470, CVSS 9.8, CRITICAL, Tier 1)
        try
          val clazz = Class.forName(className)
          val instance = clazz.getDeclaredConstructor().newInstance()
          val method = clazz.getMethod("execute", classOf[Map[String, String]])
          val result = method.invoke(instance, args)
          sender() ! result.toString
        catch
          case ex: Exception =>
            sender() ! s"Task failed: ${ex.getMessage}"

      // BUG-093: Pattern match not exhaustive - crashes on unexpected messages (CWE-754, CVSS 4.3, TRICKY, Tier 5)
      // Missing: case RemovePaper, ReindexAll, ProcessUpload handlers

  // ============================================================================
  // Cross-Reference Analysis
  // ============================================================================

  def analyzeCrossReferences(paperIds: Seq[Long]): Future[Map[Long, Seq[Long]]] =
    // BUG-094: Future.sequence on unbounded collection - OOM risk (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 5)
    Future.sequence(
      paperIds.map { pid =>
        repo.getCitationsForPaper(pid).map { citations =>
          pid -> citations.flatMap(_.targetPaperId)
        }
      }
    ).map(_.toMap)

  // ============================================================================
  // Implicit Conversion Exploit
  // ============================================================================

  // BUG-095: Implicit conversion silently converts String to Long, can cause wrong paper lookups (CWE-704, CVSS 6.5, TRICKY, Tier 5)
  given Conversion[String, Long] with
    def apply(s: String): Long =
      try s.toLong
      catch case _: NumberFormatException => 0L

  def getCitationCount(paperId: String): Future[Int] =
    // Uses implicit conversion - if paperId is non-numeric, silently becomes 0
    repo.getCitationsForPaper(paperId).map(_.length)
