/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.responses.analysis;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Set;

/**
 * Analyze HTTP responses and retrieve keywords.
 */
public interface ResponseKeywordsAnalyzer
{
    /**
     * @return A set of keywords whose counts vary between the analyzed responses.
     */
    Set<String> variantKeywords();

    /**
     * @return A set of keywords whose counts do not vary between the analyzed responses.
     */
    Set<String> invariantKeywords();

    /**
     * Update the analysis based on an additional response.
     *
     * @param response The new response to include in the analysis.
     */
    void updateWith(HttpResponse response);
}
