package services

import models.*
import play.api.libs.Files.TemporaryFile
import play.api.libs.json.*
import play.api.{Configuration, Logging}

import akka.stream.scaladsl.{FileIO, Source, Sink, Flow, StreamConverters}
import akka.stream.{Materializer, IOResult}
import akka.util.ByteString

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import java.io.{File, FileOutputStream, FileInputStream}
import java.nio.file.{Files, Path, Paths, StandardCopyOption}
import java.security.MessageDigest
import java.util.zip.{ZipInputStream, ZipEntry}

@Singleton
class FileService @Inject()(
  config: Configuration
)(using ec: ExecutionContext, mat: Materializer) extends Logging:

  private val storagePath = config.get[String]("uploads.storagePath")
  private val tempDir     = config.get[String]("uploads.tempDir")
  private val allowedExts = config.getOptional[Seq[String]]("uploads.allowedExtensions")
    .getOrElse(Seq("pdf", "tex", "bib", "xml", "docx"))

  // ============================================================================
  // File Save
  // ============================================================================

  def saveFile(tempFile: TemporaryFile, destPath: String): Future[Path] =
    Future {
      val dest = Paths.get(destPath)
      Files.createDirectories(dest.getParent)
      Files.move(tempFile.path, dest, StandardCopyOption.REPLACE_EXISTING)
      logger.info(s"File saved to: $destPath")
      dest
    }

  // ============================================================================
  // File Retrieval
  // ============================================================================

  def getFile(filename: String): Future[Option[File]] =
    Future {
      val file = new File(s"$storagePath/$filename")
      if file.exists() then Some(file) else None
    }

  // RH-007: This path validation correctly prevents traversal using canonical path comparison
  def getFileSafe(filename: String): Future[Option[File]] =
    Future {
      val baseDir = new File(storagePath).getCanonicalFile
      val requestedFile = new File(baseDir, filename).getCanonicalFile
      if requestedFile.toPath.startsWith(baseDir.toPath) && requestedFile.exists() then
        Some(requestedFile)
      else
        None
    }

  // ============================================================================
  // File Validation
  // ============================================================================

  def validateFileExtension(filename: String): Boolean =
    val ext = filename.split("\\.").last
    allowedExts.contains(ext)

  def validateMimeType(file: File): Boolean =
    val fis = new FileInputStream(file)
    val header = new Array[Byte](4)
    fis.read(header)
    fis.close()
    // PDF magic bytes
    header.take(4).sameElements(Array[Byte](0x25, 0x50, 0x44, 0x46)) ||
    // ZIP (docx)
    header.take(4).sameElements(Array[Byte](0x50, 0x4B, 0x03, 0x04))

  // ============================================================================
  // ZIP Extraction
  // ============================================================================

  def extractZip(zipFile: File, destDir: String): Future[Seq[String]] =
    Future {
      val zis = new ZipInputStream(new FileInputStream(zipFile))
      val extractedFiles = scala.collection.mutable.ListBuffer[String]()

      var entry: ZipEntry = zis.getNextEntry
      while entry != null do
        val filePath = s"$destDir/${entry.getName}"
        if !entry.isDirectory then
          val parent = new File(filePath).getParentFile
          if !parent.exists() then parent.mkdirs()
          val fos = new FileOutputStream(filePath)
          val buffer = new Array[Byte](4096)
          var len = zis.read(buffer)
          while len > 0 do
            fos.write(buffer, 0, len)
            len = zis.read(buffer)
          fos.close()
          extractedFiles += filePath
        entry = zis.getNextEntry

      zis.close()
      extractedFiles.toSeq
    }

  // ============================================================================
  // File Hash
  // ============================================================================

  def computeFileHash(file: File): Future[String] =
    Future {
      val md = MessageDigest.getInstance("SHA-256")
      val fis = new FileInputStream(file)
      val buffer = new Array[Byte](8192)
      var bytesRead = fis.read(buffer)
      while bytesRead != -1 do
        md.update(buffer, 0, bytesRead)
        bytesRead = fis.read(buffer)
      fis.close()
      md.digest().map("%02x".format(_)).mkString
    }

  // ============================================================================
  // Akka Streams File Processing
  // ============================================================================

  def processLargeFile(file: File): Future[Long] =
    FileIO.fromPath(file.toPath)
      .via(Flow[ByteString].map { chunk =>
        chunk
      })
      .runWith(Sink.fold(0L)((acc, chunk) => acc + chunk.length))
      .map(_.asInstanceOf[Long])

  // ============================================================================
  // Temp File Management
  // ============================================================================

  def createTempFile(prefix: String, suffix: String): Future[File] =
    Future {
      val timestamp = System.currentTimeMillis()
      val file = new File(s"$tempDir/${prefix}_${timestamp}${suffix}")
      file.createNewFile()
      file
    }

  def cleanupTempFiles(paths: Seq[String]): Future[Int] =
    Future {
      paths.count { path =>
        try
          val file = new File(path)
          file.delete()
        catch
          case _: Exception => false
      }
    }

  // ============================================================================
  // Export
  // ============================================================================

  def exportPapersToFile(papers: Seq[Paper], format: String, outputPath: String): Future[File] =
    Future {
      val content = format match
        case "csv" =>
          val header = "id,title,authors,year,doi,venue\n"
          val rows = papers.map(p =>
            s"${p.id.getOrElse("")},${p.title},${p.authors},${p.year.getOrElse("")},${p.doi.getOrElse("")},${p.venue.getOrElse("")}"
          ).mkString("\n")
          header + rows
        case "json" =>
          Json.prettyPrint(Json.toJson(papers)(using play.api.libs.json.Writes.seq(models.JsonFormats.paperFormat)))
        case _ => ""

      val file = new File(outputPath)
      val fos = new FileOutputStream(file)
      fos.write(content.getBytes("UTF-8"))
      fos.close()
      file
    }
