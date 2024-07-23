/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

public interface AuditIssueContextMenuEvent extends ComponentEvent, ToolSource, InvocationSource
{
    /**
     * This method can be used to retrieve details of the Scanner audit issues that were selected by the user when the context menu was invoked.
     * This will return an empty list if no issues are applicable to the invocation.
     *
     * @return a List of {@link AuditIssue} objects representing the items that were shown or selected by the user when the context menu was invoked.
     */
    List<AuditIssue> selectedIssues();
}
