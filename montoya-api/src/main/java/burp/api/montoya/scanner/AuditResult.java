/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

public interface AuditResult
{
    List<AuditIssue> auditIssues();

    static AuditResult auditResult(List<AuditIssue> auditIssues)
    {
        return FACTORY.auditResult(auditIssues);
    }

    static AuditResult auditResult(AuditIssue... auditIssues)
    {
        return FACTORY.auditResult(auditIssues);
    }
}
