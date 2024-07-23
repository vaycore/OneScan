/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

import burp.api.montoya.core.Registration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.bchecks.BChecks;

import java.nio.file.Path;
import java.util.List;

/**
 * [Professional only] Provides access to the functionality of the Scanner tool.
 */
public interface Scanner
{
    /**
     * Register a handler which will be notified of new
     * audit issues that are reported by the Scanner tool. Extensions can
     * perform custom analysis or logging of audit issues by registering an
     * audit issue handler.
     *
     * @param auditIssueHandler An object created by the extension that
     *                          implements the {@link AuditIssueHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerAuditIssueHandler(AuditIssueHandler auditIssueHandler);

    /**
     * Register a custom Scanner check. When performing
     * scanning, Burp will ask the check to perform active or passive scanning
     * on the base request, and report any Scanner issues that are identified.
     *
     * @param scanCheck An object created by the extension that implements the
     *                  {@link ScanCheck} interface.
     *
     * @return The {@link Registration} for the check.
     */
    Registration registerScanCheck(ScanCheck scanCheck);

    /**
     * Register a provider of Scanner insertion points.
     * For each base request that is actively scanned, Burp will ask the
     * provider to provide any custom Scanner insertion points that are
     * appropriate for the request.
     *
     * @param insertionPointProvider An object created by the extension that
     *                               implements the {@link AuditInsertionPointProvider} interface.
     *
     * @return The {@link Registration} for the provider.
     */
    Registration registerInsertionPointProvider(AuditInsertionPointProvider insertionPointProvider);

    /**
     * This method can be used to start a crawl in the Burp Scanner tool.
     *
     * @return The {@link Crawl} started in the Burp Scanner tool.
     */
    Crawl startCrawl(CrawlConfiguration crawlConfiguration);

    /**
     * This method can be used to start an audit in the Burp Scanner tool.
     *
     * @return The {@link Audit} started in the Burp Scanner tool.
     */
    Audit startAudit(AuditConfiguration auditConfiguration);

    /**
     * Generate a report for the specified Scanner
     * issues. The report format can be specified. For all other reporting
     * options, the default settings that appear in the reporting UI wizard are
     * used.
     *
     * @param issues The {@link AuditIssue}s issues to be reported.
     * @param format The {@link ReportFormat} to be used in the report.
     * @param path   The {@link Path} to the file that will be saved.
     */
    void generateReport(List<AuditIssue> issues, ReportFormat format, Path path);

    /**
     * Access functionality related to BChecks.
     *
     * @return An implementation of the {@link BChecks} interface which exposes BChecks functionality.
     */
    BChecks bChecks();
}
