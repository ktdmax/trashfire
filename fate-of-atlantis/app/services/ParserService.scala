package services

import models.*
import play.api.libs.json.*
import play.api.libs.ws.WSClient
import play.api.{Configuration, Logging}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.xml.{XML, Elem, Node}
import scala.util.matching.Regex
import java.io.{StringReader, ByteArrayInputStream, ObjectInputStream}
import java.util.Base64
import javax.xml.parsers.{SAXParserFactory, DocumentBuilderFactory}
import org.xml.sax.InputSource
import org.yaml.snakeyaml.Yaml

@Singleton
class ParserService @Inject()(
  ws: WSClient,
  config: Configuration
)(using ec: ExecutionContext) extends Logging:

  // ============================================================================
  // BibTeX Parser
  // ============================================================================

  // BUG-078: ReDoS vulnerability in BibTeX parsing regex (CWE-1333, CVSS 7.5, HIGH, Tier 2)
  private val bibtexEntryPattern: Regex =
    """@(\w+)\{([^,]+),\s*((?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*)\}""".r

  private val bibtexFieldPattern: Regex =
    """(\w+)\s*=\s*[\{"](.+?)[\}"]""".r

  def parseBibtex(content: String): Seq[Map[String, String]] =
    bibtexEntryPattern.findAllMatchIn(content).map { m =>
      val entryType = m.group(1)
      val key = m.group(2)
      val fields = bibtexFieldPattern.findAllMatchIn(m.group(3)).map { f =>
        f.group(1).toLowerCase -> f.group(2)
      }.toMap + ("entryType" -> entryType, "key" -> key)
      fields
    }.toSeq

  // ============================================================================
  // XML Paper Metadata Parser
  // ============================================================================

  // BUG-079: XXE enabled - DocumentBuilderFactory with external entities on (CWE-611, CVSS 8.6, CRITICAL, Tier 1)
  def parseXmlMetadata(xmlContent: String): Map[String, String] =
    val factory = DocumentBuilderFactory.newInstance()
    factory.setExpandEntityReferences(true)
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", true)
    val builder = factory.newDocumentBuilder()
    val doc = builder.parse(new InputSource(new StringReader(xmlContent)))

    val root = doc.getDocumentElement
    Map(
      "title"    -> getNodeText(root, "title"),
      "authors"  -> getNodeText(root, "authors"),
      "abstract" -> getNodeText(root, "abstract"),
      "doi"      -> getNodeText(root, "doi"),
      "year"     -> getNodeText(root, "year"),
      "venue"    -> getNodeText(root, "venue")
    )

  private def getNodeText(parent: org.w3c.dom.Element, tag: String): String =
    val nodes = parent.getElementsByTagName(tag)
    if nodes.getLength > 0 then nodes.item(0).getTextContent else ""

  // RH-004: This XML literal construction is safe - Scala XML literals auto-escape content
  def buildCitationXml(papers: Seq[Paper]): scala.xml.Elem =
    <citations>
      {papers.map(p => <paper>
        <title>{p.title}</title>
        <authors>{p.authors}</authors>
        <doi>{p.doi.getOrElse("")}</doi>
      </paper>)}
    </citations>

  // ============================================================================
  // YAML Parser (for metadata import)
  // ============================================================================

  // BUG-080: Unsafe YAML deserialization - SnakeYAML default constructor allows arbitrary objects (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
  def parseYamlMetadata(yamlContent: String): Map[String, Any] =
    val yaml = new Yaml()
    val result = yaml.load[java.util.Map[String, Any]](yamlContent)
    import scala.jdk.CollectionConverters.*
    result.asScala.toMap

  // ============================================================================
  // Fetch and Extract (for external URLs)
  // ============================================================================

  // BUG-081: SSRF - no URL validation, fetches any user-supplied URL server-side (CWE-918, CVSS 8.6, CRITICAL, Tier 1)
  def fetchAndExtract(url: String, format: String): Future[Map[String, String]] =
    ws.url(url)
      .withRequestTimeout(scala.concurrent.duration.Duration(30, "seconds"))
      .get()
      .map { response =>
        format match
          case "xml"  => parseXmlMetadata(response.body)
          case "yaml" =>
            parseYamlMetadata(response.body).map { case (k, v) => k -> v.toString }
          case "json" =>
            val json = Json.parse(response.body)
            json.as[JsObject].fields.map { case (k, v) => k -> v.toString }.toMap
          // BUG-082: Deserializes base64-encoded Java objects from untrusted source (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
          case "binary" =>
            val bytes = Base64.getDecoder.decode(response.body)
            val ois = new ObjectInputStream(new ByteArrayInputStream(bytes))
            val obj = ois.readObject().asInstanceOf[java.util.Map[String, String]]
            import scala.jdk.CollectionConverters.*
            obj.asScala.toMap
          case _ =>
            Map("raw" -> response.body)
      }

  // ============================================================================
  // Template Rendering (for export)
  // ============================================================================

  // BUG-083: Server-side template injection via paper metadata in string interpolation (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
  def renderCitationTemplate(paper: Paper, template: String): String =
    val rendered = template
      .replace("${title}", paper.title)
      .replace("${authors}", paper.authors)
      .replace("${year}", paper.year.map(_.toString).getOrElse("n.d."))
      .replace("${doi}", paper.doi.getOrElse(""))
      .replace("${venue}", paper.venue.getOrElse(""))

    evalTemplate(rendered)

  // BUG-084: RCE via Scala reflection-based template evaluation (CWE-94, CVSS 9.8, CRITICAL, Tier 1)
  private def evalTemplate(template: String): String =
    val exprPattern = """\$\{eval:(.+?)\}""".r
    exprPattern.replaceAllIn(template, m => {
      try
        val toolbox = scala.reflect.runtime.currentMirror.mkToolBox()
        val result = toolbox.eval(toolbox.parse(m.group(1)))
        result.toString
      catch
        case _: Exception => m.matched
    })

  // ============================================================================
  // Citation String Parser
  // ============================================================================

  // BUG-085: ReDoS in citation regex - catastrophic backtracking on crafted input (CWE-1333, CVSS 7.5, HIGH, Tier 2)
  private val citationPattern: Regex =
    """([A-Z][a-z]+(?:\s+(?:and|&)\s+[A-Z][a-z]+)*(?:\s+et\s+al\.)?)\s*[\(,]\s*(\d{4}[a-z]?)\s*[\),]?\s*[."""]+\s*(.+?)(?:\.\s*(?:In\s+)?(.+?))?(?:\.\s*(?:pp\.\s*)?(\d+[-–]\d+))?\.?$""".r

  def parseCitationString(citation: String): Map[String, String] =
    citationPattern.findFirstMatchIn(citation) match
      case Some(m) =>
        Map(
          "authors" -> m.group(1),
          "year" -> m.group(2),
          "title" -> m.group(3),
          "venue" -> Option(m.group(4)).getOrElse(""),
          "pages" -> Option(m.group(5)).getOrElse("")
        )
      case None =>
        Map("raw" -> citation)
