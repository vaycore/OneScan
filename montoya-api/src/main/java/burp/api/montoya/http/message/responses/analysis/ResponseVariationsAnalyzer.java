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
 * Analyze HTTP responses and find variations between them, according to various attributes.
 */
public interface ResponseVariationsAnalyzer
{
    /**
     * @return The attributes that vary between the analyzed responses.
     */
    Set<AttributeType> variantAttributes();

    /**
     * @return The attributes that do not vary between the analyzed responses.
     */
    Set<AttributeType> invariantAttributes();

    /**
     * Update the analysis based on an additional response.
     *
     * @param response The new response to include in the analysis.
     */
    void updateWith(HttpResponse response);
}
