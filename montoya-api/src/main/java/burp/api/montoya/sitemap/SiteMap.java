/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.sitemap;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.List;

/**
 * Provides methods for querying and modifying Burp's site map.
 */
public interface SiteMap
{
    /**
     * This method filters out the site map according to the passed {@link SiteMapFilter}
     * object and returns a list of matched {@link HttpRequestResponse} items.
     *
     * @param filter This parameter can be used to specify a filter, in order to extract a
     *               specific subset of the site map.
     *
     * @return A list of filtered items from the site map.
     */
    List<HttpRequestResponse> requestResponses(SiteMapFilter filter);

    /**
     * This method returns details of all items in the site map.
     *
     * @return A list of all items from the site map.
     */
    List<HttpRequestResponse> requestResponses();

    /**
     * This method returns current audit issues for URLs in the site map that are matched by the
     * {@link SiteMapFilter} object.
     *
     * @param filter This parameter can be used to specify a filter, in order to extract issues
     *               for a specific subset of the site map.
     *
     * @return A filtered list of audit issues.
     */
    List<AuditIssue> issues(SiteMapFilter filter);

    /**
     * This method returns all the current audit issues for URLs in the site map.
     *
     * @return A list of audit issues.
     */
    List<AuditIssue> issues();

    /**
     * This method can be used to add an {@link HttpRequestResponse} item to Burp's site
     * map with the specified request/response details. This will overwrite the details of any
     * existing matching item in the site map.
     *
     * @param requestResponse Item to be added to the site map
     */
    void add(HttpRequestResponse requestResponse);

    /**
     * Register a new Audit issue. Note: Wherever possible, extensions
     * should implement custom Scanner checks using {@link ScanCheck} and report issues
     * via those checks, to integrate with Burp's user-driven workflow, and ensure proper
     * consolidation of duplicate reported issues. This method is only designed for tasks
     * outside the normal testing workflow, such as porting results from other scanning tools.
     *
     * @param auditIssue An object created by the extension that implements the
     *                   {@link AuditIssue} interface.
     */
    void add(AuditIssue auditIssue);
}
