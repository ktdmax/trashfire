package controllers

import models.*
import models.JsonFormats.given
import repositories.PaperRepository
import services.{ParserService, CitationService, FileService}
import utils.{AuthenticatedAction, Security}

import play.api.mvc.*
import play.api.libs.json.*
import play.api.libs.Files
import play.api.{Configuration, Logging}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.xml.XML
import java.time.LocalDateTime

@Singleton
class PaperController @Inject()(
  cc: ControllerComponents,
  repo: PaperRepository,
  parserService: ParserService,
  citationService: CitationService,
  fileService: FileService,
  authAction: AuthenticatedAction,
  config: Configuration
)(using ec: ExecutionContext) extends AbstractController(cc) with Logging:

  private val uploadPath = config.get[String]("uploads.storagePath")
  private val maxFileSize = config.get[String]("uploads.maxFileSize")

  // ============================================================================
  // Paper CRUD
  // ============================================================================

  def list(page: Int, size: Int): Action[AnyContent] = Action.async { request =>
    val sortField = request.getQueryString("sort").getOrElse("created_at")
    val order     = request.getQueryString("order").getOrElse("DESC")
    // BUG-053: Passes user-supplied sort field directly to SQL (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
    repo.findAllSorted(sortField, order, page, size).map { papers =>
      Ok(Json.obj(
        "papers" -> Json.toJson(papers),
        "page" -> page,
        "size" -> size
      ))
    }
  }

  def get(id: Long): Action[AnyContent] = Action.async {
    PaperCache.get(id) match
      case Some(paper) =>
        Future.successful(Ok(Json.toJson(paper)))
      case None =>
        repo.findById(id).map {
          case Some(paper) =>
            PaperCache.put(paper)
            // BUG-054: View count increment is racy - no atomic update (CWE-362, CVSS 3.7, BEST_PRACTICE, Tier 5)
            repo.update(paper.copy(viewCount = paper.viewCount + 1))
            Ok(Json.toJson(paper))
          case None =>
            NotFound(Json.obj("error" -> "Paper not found"))
        }
  }

  def create(): Action[JsValue] = authAction.async(parse.json) { request =>
    request.body.validate[JsObject] match
      case JsSuccess(body, _) =>
        val userId = Security.getUserId(request).getOrElse(0L)
        val paper = Paper(
          title = (body \ "title").as[String],
          abstractText = (body \ "abstract").asOpt[String],
          authors = (body \ "authors").as[String],
          doi = (body \ "doi").asOpt[String],
          year = (body \ "year").asOpt[Int],
          venue = (body \ "venue").asOpt[String],
          uploadedBy = userId,
          // BUG-055: Stores raw user input as metadata without sanitization (CWE-79, CVSS 6.1, HIGH, Tier 2)
          metadata = (body \ "metadata").asOpt[String],
          status = (body \ "status").asOpt[String].getOrElse("draft")
        )
        repo.insert(paper).map { id =>
          Created(Json.obj("id" -> id, "message" -> "Paper created"))
        }
      case JsError(errors) =>
        Future.successful(BadRequest(Json.obj("error" -> JsError.toJson(errors))))
  }

  // BUG-056: No ownership check - any authenticated user can update any paper (CWE-639, CVSS 6.5, HIGH, Tier 2)
  def update(id: Long): Action[JsValue] = authAction.async(parse.json) { request =>
    repo.findById(id).flatMap {
      case Some(existing) =>
        val body = request.body.as[JsObject]
        val updated = existing.copy(
          title = (body \ "title").asOpt[String].getOrElse(existing.title),
          abstractText = (body \ "abstract").asOpt[String].orElse(existing.abstractText),
          authors = (body \ "authors").asOpt[String].getOrElse(existing.authors),
          doi = (body \ "doi").asOpt[String].orElse(existing.doi),
          year = (body \ "year").asOpt[Int].orElse(existing.year),
          venue = (body \ "venue").asOpt[String].orElse(existing.venue),
          metadata = (body \ "metadata").asOpt[String].orElse(existing.metadata),
          rawXml = (body \ "rawXml").asOpt[String].orElse(existing.rawXml),
          status = (body \ "status").asOpt[String].getOrElse(existing.status),
          updatedAt = LocalDateTime.now()
        )
        repo.update(updated).map { _ =>
          PaperCache.invalidate(id)
          Ok(Json.obj("message" -> "Paper updated"))
        }
      case None =>
        Future.successful(NotFound(Json.obj("error" -> "Paper not found")))
    }
  }

  def delete(id: Long): Action[AnyContent] = authAction.async { request =>
    repo.delete(id).map { count =>
      if count > 0 then
        PaperCache.invalidate(id)
        Ok(Json.obj("message" -> "Paper deleted"))
      else
        NotFound(Json.obj("error" -> "Paper not found"))
    }
  }

  // ============================================================================
  // File Upload / Download
  // ============================================================================

  def uploadPdf(id: Long): Action[MultipartFormData[Files.TemporaryFile]] =
    authAction.async(parse.multipartFormData) { request =>
      request.body.file("paper").map { filePart =>
        val filename = filePart.filename
        // BUG-057: File extension check only looks at last extension - "malware.pdf.jsp" passes (CWE-434, CVSS 8.8, HIGH, Tier 2)
        if !filename.endsWith(".pdf") && !filename.endsWith(".tex") then
          Future.successful(BadRequest(Json.obj("error" -> "Only PDF and TeX files allowed")))
        else
          // BUG-058: Path traversal via filename - no sanitization of directory separators (CWE-22, CVSS 9.1, CRITICAL, Tier 1)
          val destPath = s"$uploadPath/$id/$filename"
          fileService.saveFile(filePart.ref, destPath).flatMap { _ =>
            repo.findById(id).flatMap {
              case Some(paper) =>
                repo.update(paper.copy(filePath = Some(destPath))).map { _ =>
                  Ok(Json.obj("message" -> "File uploaded", "path" -> destPath))
                }
              case None =>
                Future.successful(NotFound(Json.obj("error" -> "Paper not found")))
            }
          }
      }.getOrElse {
        Future.successful(BadRequest(Json.obj("error" -> "Missing file")))
      }
    }

  def downloadPdf(id: Long): Action[AnyContent] = Action.async {
    repo.findById(id).map {
      case Some(paper) if paper.filePath.isDefined =>
        // BUG-059: Serves file directly from stored path without access control or path validation (CWE-22, CVSS 7.5, HIGH, Tier 2)
        Ok.sendFile(new java.io.File(paper.filePath.get))
      case Some(_) =>
        NotFound(Json.obj("error" -> "No file attached"))
      case None =>
        NotFound(Json.obj("error" -> "Paper not found"))
    }
  }

  // ============================================================================
  // Import
  // ============================================================================

  def importBibtex(): Action[AnyContent] = authAction.async { request =>
    val userId = Security.getUserId(request).getOrElse(0L)
    request.body.asText match
      case Some(bibtex) =>
        val entries = parserService.parseBibtex(bibtex)
        val papers = entries.map(e => Paper(
          title = e("title"),
          authors = e("author"),
          year = e.get("year").flatMap(_.toIntOption),
          doi = e.get("doi"),
          venue = e.get("journal").orElse(e.get("booktitle")),
          uploadedBy = userId
        ))
        Future.sequence(papers.map(repo.insert)).map { ids =>
          Ok(Json.obj("imported" -> ids.length, "ids" -> ids))
        }
      case None =>
        Future.successful(BadRequest(Json.obj("error" -> "Missing BibTeX content")))
  }

  // BUG-060: XXE via XML import - external entities not disabled (CWE-611, CVSS 8.6, HIGH, Tier 2)
  def importXml(): Action[AnyContent] = authAction.async { request =>
    request.body.asText match
      case Some(xmlStr) =>
        val xml = XML.loadString(xmlStr)
        val papers = (xml \\ "paper").map { node =>
          Paper(
            title = (node \ "title").text,
            authors = (node \ "authors").text,
            year = (node \ "year").text.toIntOption,
            doi = Some((node \ "doi").text).filter(_.nonEmpty),
            venue = Some((node \ "venue").text).filter(_.nonEmpty),
            rawXml = Some(node.toString),
            uploadedBy = Security.getUserId(request).getOrElse(0L)
          )
        }
        Future.sequence(papers.map(repo.insert)).map { ids =>
          Ok(Json.obj("imported" -> ids.length))
        }
      case None =>
        Future.successful(BadRequest(Json.obj("error" -> "Missing XML content")))
  }

  // ============================================================================
  // Citations
  // ============================================================================

  def getCitations(id: Long): Action[AnyContent] = Action.async {
    repo.getCitationsForPaper(id).map { citations =>
      Ok(Json.toJson(citations))
    }
  }

  def getReferences(id: Long): Action[AnyContent] = Action.async {
    repo.getReferencesForPaper(id).map { refs =>
      Ok(Json.toJson(refs))
    }
  }

  // ============================================================================
  // Metadata Extraction
  // ============================================================================

  // BUG-061: SSRF - user-controlled URL passed to server-side HTTP request (CWE-918, CVSS 8.6, HIGH, Tier 2)
  def extractMetadata(): Action[JsValue] = Action.async(parse.json) { request =>
    val url = (request.body \ "url").as[String]
    val format = (request.body \ "format").asOpt[String].getOrElse("json")

    parserService.fetchAndExtract(url, format).map { metadata =>
      Ok(Json.toJson(metadata))
    }.recover {
      // BUG-062: Error message leaks internal URL and stack trace (CWE-209, CVSS 3.7, LOW, Tier 4)
      case ex: Exception =>
        logger.error(s"Metadata extraction failed for URL: $url", ex)
        InternalServerError(Json.obj(
          "error" -> "Extraction failed",
          "details" -> ex.getMessage,
          "url" -> url,
          "stackTrace" -> ex.getStackTrace.map(_.toString).take(10)
        ))
    }
  }
