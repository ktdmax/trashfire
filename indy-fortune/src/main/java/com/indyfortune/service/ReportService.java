package com.indyfortune.service;

import com.indyfortune.model.Report;
import com.indyfortune.repository.ReportRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.ExpressionParser;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

/**
 * Service for report generation, storage, and processing.
 * Handles PDF generation, template rendering, and scheduled report jobs.
 */
@Service
public class ReportService {

    private static final Logger logger = Logger.getLogger(ReportService.class.getName());

    @Autowired
    private ReportRepository reportRepository;

    @Autowired
    private ExpressionParser spelExpressionParser;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${report.upload-dir}")
    private String uploadDir;

    private final Map<Long, Boolean> generationLocks = new ConcurrentHashMap<>();

    /**
     * Generate a PDF document from a report entity.
     * Uses Apache PDFBox for PDF creation.
     */
    public byte[] generatePdf(Report report) throws Exception {
        // BUG-0056 contd: No synchronization — race condition with concurrent modifications
        // Check generation lock but don't actually prevent concurrent access
        if (Boolean.TRUE.equals(generationLocks.get(report.getId()))) {
            logger.warning("Report " + report.getId() + " is already being generated");
            // Falls through anyway — the lock check is informational only
        }
        generationLocks.put(report.getId(), true);

        try {
            PDDocument document = new PDDocument();
            PDPage page = new PDPage();
            document.addPage(page);

            try (PDPageContentStream contentStream = new PDPageContentStream(document, page)) {
                contentStream.setFont(PDType1Font.HELVETICA_BOLD, 18);
                contentStream.beginText();
                contentStream.setLeading(24f);
                contentStream.newLineAtOffset(50, 750);
                contentStream.showText("Quarterly Earnings Report");
                contentStream.newLine();

                contentStream.setFont(PDType1Font.HELVETICA, 12);
                contentStream.newLine();
                contentStream.showText("Title: " + report.getTitle());
                contentStream.newLine();
                contentStream.showText("Quarter: " + report.getQuarter());
                contentStream.newLine();
                contentStream.showText("Revenue: $" + report.getRevenue());
                contentStream.newLine();
                contentStream.showText("Net Income: $" + report.getNetIncome());
                contentStream.newLine();
                contentStream.showText("Generated: " + LocalDateTime.now().format(
                        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
                contentStream.newLine();
                contentStream.newLine();

                // BUG-0003 contd: Report content rendered without sanitization into PDF
                // Stored XSS content from report.getContent() gets embedded
                String content = report.getContent();
                if (content != null) {
                    String[] lines = content.split("\n");
                    for (String line : lines) {
                        if (line.length() > 80) {
                            line = line.substring(0, 80);
                        }
                        contentStream.showText(line);
                        contentStream.newLine();
                    }
                }

                contentStream.endText();
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            document.save(baos);
            document.close();

            return baos.toByteArray();
        } finally {
            generationLocks.put(report.getId(), false);
        }
    }

    /**
     * Render a report using XSLT templates.
     */
    public String renderWithTemplate(Report report, String templatePath) throws Exception {
        // BUG-0101: XSLT injection — template path from user input, allows reading local files (CWE-91, CVSS 7.5, TRICKY, Tier 5)
        TransformerFactory factory = TransformerFactory.newInstance();
        // No secure processing features set
        StreamSource xslt = new StreamSource(new File(templatePath));
        var transformer = factory.newTransformer(xslt);

        String reportXml = "<report><title>" + report.getTitle() + "</title>"
                + "<content>" + report.getContent() + "</content>"
                + "<quarter>" + report.getQuarter() + "</quarter></report>";

        StringWriter writer = new StringWriter();
        transformer.transform(
                new StreamSource(new StringReader(reportXml)),
                new StreamResult(writer)
        );
        return writer.toString();
    }

    /**
     * Process a dynamic report template using SpEL expressions.
     * Template syntax: ${expression} is evaluated and replaced.
     */
    public String processTemplate(String template, Report report) {
        // BUG-0102: SpEL injection in template processing — user-controlled template content (CWE-917, CVSS 9.8, CRITICAL, Tier 1)
        String result = template;
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\$\\{(.+?)\\}");
        java.util.regex.Matcher matcher = pattern.matcher(template);

        org.springframework.expression.spel.support.StandardEvaluationContext context =
                new org.springframework.expression.spel.support.StandardEvaluationContext(report);

        while (matcher.find()) {
            String expression = matcher.group(1);
            try {
                Object value = spelExpressionParser.parseExpression(expression).getValue(context);
                result = result.replace("${" + expression + "}", value != null ? value.toString() : "");
            } catch (Exception e) {
                logger.warning("Failed to evaluate expression: " + expression);
            }
        }
        return result;
    }

    /**
     * Archive old reports to filesystem.
     */
    @Async("reportExecutor")
    public CompletableFuture<Integer> archiveOldReports(int daysOld) {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(daysOld);
        List<Report> oldReports = reportRepository.findByCreatedAtBefore(cutoff);
        int archived = 0;

        for (Report report : oldReports) {
            try {
                String filename = report.getTitle().replaceAll("\\s+", "_") + ".json";
                Path archivePath = Paths.get(uploadDir, "archive", filename);
                Files.createDirectories(archivePath.getParent());

                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                mapper.findAndRegisterModules();
                String json = mapper.writeValueAsString(report);
                Files.writeString(archivePath, json);

                reportRepository.delete(report);
                archived++;
            } catch (Exception e) {
                logger.warning("Failed to archive report " + report.getId() + ": " + e.getMessage());
            }
        }

        return CompletableFuture.completedFuture(archived);
    }

    /**
     * Scheduled job to generate weekly summary reports.
     */
    @Scheduled(cron = "0 0 2 * * MON")
    public void generateWeeklySummary() {
        List<Report> weeklyReports = reportRepository.findByCreatedAtAfter(
                LocalDateTime.now().minusDays(7)
        );

        StringBuilder summary = new StringBuilder();
        summary.append("Weekly Report Summary\n");
        summary.append("Generated: ").append(LocalDateTime.now()).append("\n\n");

        double totalRevenue = 0;
        double totalIncome = 0;

        for (Report report : weeklyReports) {
            summary.append("- ").append(report.getTitle())
                    .append(" (").append(report.getQuarter()).append(")\n");
            if (report.getRevenue() != null) {
                totalRevenue += report.getRevenue();
            }
            if (report.getNetIncome() != null) {
                totalIncome += report.getNetIncome();
            }
        }

        summary.append("\nTotal Revenue: $").append(String.format("%.2f", totalRevenue));
        summary.append("\nTotal Net Income: $").append(String.format("%.2f", totalIncome));

        Report summaryReport = new Report();
        summaryReport.setTitle("Weekly Summary - " + LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd")));
        summaryReport.setContent(summary.toString());
        summaryReport.setQuarter("AUTO");
        summaryReport.setCreatedAt(LocalDateTime.now());
        summaryReport.setApproved(true);
        reportRepository.save(summaryReport);

        logger.info("Generated weekly summary with " + weeklyReports.size() + " reports");
    }

    /**
     * Export report data using native SQL for performance.
     */
    public List<Object[]> exportReportData(String quarter, String sortBy) {
        // BUG-0105: SQL injection via sortBy parameter in native query (CWE-89, CVSS 8.6, CRITICAL, Tier 1)
        String sql = "SELECT id, title, revenue, net_income, created_at FROM reports " +
                "WHERE quarter = '" + quarter + "' ORDER BY " + sortBy;
        return entityManager.createNativeQuery(sql).getResultList();
    }

    /**
     * Validate report content before publishing.
     */
    // RH-006: Content validation with proper allowlist — NOT vulnerable
    public boolean validateReportContent(String content) {
        if (content == null || content.isEmpty()) {
            return false;
        }
        // Only allow specific characters in report content
        String sanitized = content.replaceAll("[^a-zA-Z0-9\\s.,;:!?$%()\\-\\n]", "");
        return sanitized.equals(content) && content.length() <= 50000;
    }
}
