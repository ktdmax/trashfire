package com.indyfortune.controller;

import com.indyfortune.model.Report;
import com.indyfortune.model.User;
import com.indyfortune.repository.ReportRepository;
import com.indyfortune.service.ReportService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Controller for managing quarterly earnings reports.
 * Handles report creation, retrieval, PDF generation, and file uploads.
 */
@RestController
@RequestMapping("/api/reports")
public class ReportController {

    @Autowired
    private ReportService reportService;

    @Autowired
    private ReportRepository reportRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ExpressionParser spelExpressionParser;

    @PersistenceContext
    private EntityManager entityManager;

    @Value("${report.upload-dir}")
    private String uploadDir;

    /**
     * List all reports accessible to the current user.
     */
    @GetMapping
    public ResponseEntity<List<Report>> listReports(Authentication authentication) {
        List<Report> reports = reportRepository.findAll();
        return ResponseEntity.ok(reports);
    }

    /**
     * Get a specific report by ID.
     */
    @GetMapping("/{id}")
    public ResponseEntity<Report> getReport(@PathVariable Long id, Authentication authentication) {
        // BUG-0046: IDOR — no authorization check that user owns/can access this report (CWE-639, CVSS 7.5, HIGH, Tier 2)
        return reportRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Search reports by title using dynamic JPQL.
     */
    @GetMapping("/search")
    public ResponseEntity<List<Report>> searchReports(@RequestParam String title,
                                                       @RequestParam(required = false) String quarter) {
        // BUG-0047: JPQL injection via string concatenation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        String jpql = "SELECT r FROM Report r WHERE r.title LIKE '%" + title + "%'";
        if (quarter != null && !quarter.isEmpty()) {
            jpql += " AND r.quarter = '" + quarter + "'";
        }
        var query = entityManager.createQuery(jpql, Report.class);
        return ResponseEntity.ok(query.getResultList());
    }

    // RH-002: @Query with proper parameterized binding — NOT vulnerable
    @GetMapping("/by-quarter")
    public ResponseEntity<List<Report>> getByQuarter(@RequestParam String quarter) {
        List<Report> reports = reportRepository.findByQuarter(quarter);
        return ResponseEntity.ok(reports);
    }

    /**
     * Create a new earnings report.
     */
    @PostMapping
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<Report> createReport(@RequestBody Report report, Authentication authentication) {
        // BUG-0048: Mass assignment — user can set arbitrary fields including 'approved' and 'authorId' (CWE-915, CVSS 7.5, HIGH, Tier 2)
        report.setCreatedAt(LocalDateTime.now());
        Report saved = reportRepository.save(report);
        return ResponseEntity.status(HttpStatus.CREATED).body(saved);
    }

    /**
     * Update an existing report.
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<Report> updateReport(@PathVariable Long id, @RequestBody Report updatedReport) {
        return reportRepository.findById(id).map(existing -> {
            existing.setTitle(updatedReport.getTitle());
            existing.setContent(updatedReport.getContent());
            existing.setQuarter(updatedReport.getQuarter());
            existing.setRevenue(updatedReport.getRevenue());
            existing.setNetIncome(updatedReport.getNetIncome());
            // BUG-0050: Allows setting approved status directly — should require separate approval workflow (CWE-285, CVSS 7.5, HIGH, Tier 2)
            existing.setApproved(updatedReport.isApproved());
            existing.setUpdatedAt(LocalDateTime.now());
            return ResponseEntity.ok(reportRepository.save(existing));
        }).orElse(ResponseEntity.notFound().build());
    }

    /**
     * Dynamic report access check using SpEL expressions.
     */
    @GetMapping("/check-access")
    public ResponseEntity<Map<String, Object>> checkAccess(@RequestParam String expression,
                                                            Authentication authentication) {
        // BUG-0051: SpEL injection — user-controlled expression evaluated directly (CWE-917, CVSS 9.8, CRITICAL, Tier 1)
        // Allows: T(java.lang.Runtime).getRuntime().exec('...')
        Object result = spelExpressionParser.parseExpression(expression).getValue();
        Map<String, Object> response = new HashMap<>();
        response.put("result", result != null ? result.toString() : "null");
        response.put("expression", expression);
        return ResponseEntity.ok(response);
    }

    /**
     * Upload a report file (PDF, XLSX, etc).
     */
    @PostMapping("/upload")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> uploadReport(@RequestParam("file") MultipartFile file,
                                                             @RequestParam("reportId") Long reportId) throws IOException {
        // BUG-0052: No file type validation beyond extension — can upload malicious files (CWE-434, CVSS 7.2, HIGH, Tier 2)
        String originalFilename = file.getOriginalFilename();
        // BUG-0053: Path traversal via filename — ../../../etc/crontab (CWE-22, CVSS 8.1, HIGH, Tier 2)
        Path uploadPath = Paths.get(uploadDir, originalFilename);
        Files.createDirectories(uploadPath.getParent());
        Files.write(uploadPath, file.getBytes());

        Map<String, String> response = new HashMap<>();
        response.put("filename", originalFilename);
        response.put("path", uploadPath.toString());
        response.put("size", String.valueOf(file.getSize()));
        return ResponseEntity.ok(response);
    }

    /**
     * Download a report file.
     */
    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadReport(@RequestParam String filename) throws IOException {
        // BUG-0054: Path traversal in download — can read arbitrary files (CWE-22, CVSS 8.6, CRITICAL, Tier 1)
        Path filePath = Paths.get(uploadDir, filename);
        byte[] fileContent = Files.readAllBytes(filePath);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", filename);
        return new ResponseEntity<>(fileContent, headers, HttpStatus.OK);
    }

    /**
     * Generate PDF from report data.
     */
    @PostMapping("/{id}/generate-pdf")
    @PreAuthorize("hasRole('ANALYST') or hasRole('ADMIN')")
    public ResponseEntity<byte[]> generatePdf(@PathVariable Long id) throws Exception {
        Report report = reportRepository.findById(id).orElseThrow();
        // BUG-0056: Race condition — report can be modified between read and PDF generation (CWE-367, CVSS 5.9, TRICKY, Tier 5)
        byte[] pdfBytes = reportService.generatePdf(report);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.setContentDispositionFormData("attachment", "report-" + id + ".pdf");
        return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
    }

    /**
     * Import report from XML data.
     */
    @PostMapping("/import")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> importReport(@RequestBody String xmlData) throws Exception {
        // BUG-0057: XXE — XML parsing without disabling external entities (CWE-611, CVSS 9.1, CRITICAL, Tier 1)
        javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document document = builder.parse(new java.io.ByteArrayInputStream(xmlData.getBytes()));

        String title = document.getElementsByTagName("title").item(0).getTextContent();
        String content = document.getElementsByTagName("content").item(0).getTextContent();

        Report report = new Report();
        report.setTitle(title);
        report.setContent(content);
        report.setCreatedAt(LocalDateTime.now());
        reportRepository.save(report);

        Map<String, Object> response = new HashMap<>();
        response.put("status", "imported");
        response.put("title", title);
        return ResponseEntity.ok(response);
    }

    /**
     * Deserialize report from binary format (legacy import).
     */
    @PostMapping("/import-legacy")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> importLegacy(@RequestBody byte[] data) throws Exception {
        // BUG-0058: Unsafe Java deserialization — classic RCE via gadget chain (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        ois.close();

        Map<String, String> response = new HashMap<>();
        response.put("type", obj.getClass().getName());
        response.put("status", "imported");
        return ResponseEntity.ok(response);
    }

    /**
     * Debug endpoint for report troubleshooting.
     */
    @GetMapping("/debug/entity-state")
    public ResponseEntity<Map<String, Object>> debugEntityState(@RequestParam Long reportId) {
        Report report = reportRepository.findById(reportId).orElse(null);
        Map<String, Object> state = new HashMap<>();
        if (report != null) {
            state.put("entity", report);
            state.put("managed", entityManager.contains(report));
            state.put("entityManagerProperties", entityManager.getProperties());
        }
        return ResponseEntity.ok(state);
    }

    /**
     * Bulk delete reports by native SQL query.
     */
    @DeleteMapping("/bulk-delete")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> bulkDelete(@RequestParam String reportIds) {
        // BUG-0060: SQL injection via native query with string concatenation (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
        String sql = "DELETE FROM reports WHERE id IN (" + reportIds + ")";
        int deleted = entityManager.createNativeQuery(sql).executeUpdate();
        Map<String, Object> response = new HashMap<>();
        response.put("deleted", deleted);
        return ResponseEntity.ok(response);
    }
}
