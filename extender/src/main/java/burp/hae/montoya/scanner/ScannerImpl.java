package burp.hae.montoya.scanner;

import burp.IBurpExtenderCallbacks;
import burp.api.montoya.core.Registration;
import burp.api.montoya.scanner.*;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.bchecks.BChecks;

import java.nio.file.Path;
import java.util.List;

/**
 * <p>
 * Created by vaycore on 2024-11-24.
 */
public class ScannerImpl implements Scanner {

    private final IBurpExtenderCallbacks callbacks;
    private ScanCheck scanCheck;

    public ScannerImpl(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }

    @Override
    public Registration registerAuditIssueHandler(AuditIssueHandler auditIssueHandler) {
        return null;
    }

    @Override
    public Registration registerScanCheck(ScanCheck scanCheck) {
        this.scanCheck = scanCheck;
        return new Registration() {
            @Override
            public boolean isRegistered() {
                return ScannerImpl.this.scanCheck != null;
            }

            @Override
            public void deregister() {
                ScannerImpl.this.scanCheck = null;
            }
        };
    }

    @Override
    public Registration registerInsertionPointProvider(AuditInsertionPointProvider insertionPointProvider) {
        return null;
    }

    @Override
    public Crawl startCrawl(CrawlConfiguration crawlConfiguration) {
        return null;
    }

    @Override
    public Audit startAudit(AuditConfiguration auditConfiguration) {
        return null;
    }

    @Override
    public void generateReport(List<AuditIssue> issues, ReportFormat format, Path path) {

    }

    @Override
    public BChecks bChecks() {
        return null;
    }
}
