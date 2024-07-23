/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner.audit;

import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

/**
 * Extensions can implement this interface and then call
 * {@link Scanner#registerAuditIssueHandler(AuditIssueHandler)} to register an
 * audit issue handler. The handler will be notified of new issues that are
 * reported by the Scanner tool. Extensions can perform custom analysis or
 * logging of audit issues by registering an audit issue handler.
 */
public interface AuditIssueHandler
{
    /**
     * This method is invoked when a new issue is added to Burp Scanner's
     * results.
     *
     * @param auditIssue An {@link AuditIssue} object that the extension can
     *                   query to obtain details about the new issue.
     */
    void handleNewAuditIssue(AuditIssue auditIssue);
}
