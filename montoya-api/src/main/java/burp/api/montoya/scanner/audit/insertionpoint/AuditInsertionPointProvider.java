/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner.audit.insertionpoint;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.Scanner;

import java.util.List;

/**
 * Extensions can implement this interface and then call
 * {@link Scanner#registerInsertionPointProvider(AuditInsertionPointProvider)}
 * to register a provider for custom audit insertion points.
 */
public interface AuditInsertionPointProvider
{
    /**
     * The Scanner invokes this method when a request is actively audited. The
     * provider should provide a list of custom insertion points that
     * will be used in the audit. <b>Note:</b> these insertion points are used
     * in addition to those that are derived from Burp Scanner's configuration,
     * and those provided by any other Burp extensions.
     *
     * @param baseHttpRequestResponse The base {@link HttpRequestResponse} that
     *                                will be actively audited.
     *
     * @return A list of {@link AuditInsertionPoint} objects
     * that should be used in the audit, or {@code null} if no custom insertion
     * points are applicable for this request.
     */
    List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse baseHttpRequestResponse);
}
