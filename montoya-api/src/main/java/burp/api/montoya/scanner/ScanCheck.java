/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

/**
 * Extensions can implement this interface and then call
 * {@link Scanner#registerScanCheck(ScanCheck)} to register a custom Scanner
 * check. When performing an audit, Burp will ask the check to perform an
 * active or passive audit on the base request, and report any audit issues
 * that are identified.
 */
public interface ScanCheck
{
    /**
     * The Scanner invokes this method for each insertion point that is
     * actively audited. Extensions may issue HTTP requests as required to
     * carry out an active audit, and should use the
     * {@link AuditInsertionPoint} object provided to build requests for
     * particular payloads.
     * <b>Note:</b>
     * Scan checks should submit raw non-encoded payloads to insertion points,
     * and the insertion point has responsibility for performing any data
     * encoding that is necessary given the nature and location of the insertion
     * point.
     *
     * @param baseRequestResponse The base {@link HttpRequestResponse} that
     *                            should be actively audited.
     * @param auditInsertionPoint An {@link AuditInsertionPoint} object that
     *                            can be queried to obtain details of the insertion point being tested, and
     *                            can be used to build requests for particular payloads.
     *
     * @return An {@link AuditResult} object with a list of {@link AuditIssue}
     * objects, or an empty {@link AuditResult} object if no issues are identified.
     */
    AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint auditInsertionPoint);

    /**
     * The Scanner invokes this method for each base request / response that is
     * passively audited. <b>Note:</b> Extensions should only analyze the
     * HTTP messages provided during a passive audit, and should not make any
     * new HTTP requests of their own.
     *
     * @param baseRequestResponse The base {@link HttpRequestResponse} that
     *                            should be passively audited.
     *
     * @return An {@link AuditResult} object with a list of {@link AuditIssue}
     * objects, or an empty {@link AuditResult} object if no issues are identified.
     */
    AuditResult passiveAudit(HttpRequestResponse baseRequestResponse);

    /**
     * The Scanner invokes this method when the custom Scan check has
     * reported multiple issues for the same URL path. This can arise either
     * because there are multiple distinct vulnerabilities, or because the same
     * (or a similar) request has been scanned more than once. The custom check
     * should determine whether the issues are duplicates. In most cases, where
     * a check uses distinct issue names or descriptions for distinct issues,
     * the consolidation process will simply be a matter of comparing these
     * features for the two issues.
     *
     * @param newIssue      An {@link AuditIssue} at the same URL path that has been
     *                      newly reported by this Scan check.
     * @param existingIssue An {@link AuditIssue} that was previously reported
     *                      by this Scan check.
     *
     * @return A {@link ConsolidationAction} to determine which issue(s) should
     * be reported in the main Scanner results.
     */
    ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue);
}
