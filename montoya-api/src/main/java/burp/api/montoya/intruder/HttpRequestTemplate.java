/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.List;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Intruder request template, which contains the HTTP request and insertion point offsets.
 */
public interface HttpRequestTemplate
{
    /**
     * @return Content of the request template.
     */
    ByteArray content();

    /**
     * Insertion point offsets for an Intruder attack.
     *
     * @return A list of {@link Range} objects representing insertion point offsets.
     */
    List<Range> insertionPointOffsets();

    /**
     * Create a new {@link HttpRequestTemplate} instance
     * from an {@link HttpRequest} object and a list of insertion point offsets.
     *
     * @param request               An instance of {@link HttpRequest}.
     * @param insertionPointOffsets List of insertion point offsets.
     *
     * @return A new instance of {@link HttpRequestTemplate}.
     */
    static HttpRequestTemplate httpRequestTemplate(HttpRequest request, List<Range> insertionPointOffsets)
    {
        return FACTORY.httpRequestTemplate(request, insertionPointOffsets);
    }

    /**
     * Create a new {@link HttpRequestTemplate} instance
     * from an HTTP request in a byte array form and a list of insertion point offsets.
     *
     * @param content               An HTTP request in a byte array form.
     * @param insertionPointOffsets List of insertion point offsets.
     *
     * @return A new instance of {@link HttpRequestTemplate}.
     */
    static HttpRequestTemplate httpRequestTemplate(ByteArray content, List<Range> insertionPointOffsets)
    {
        return FACTORY.httpRequestTemplate(content, insertionPointOffsets);
    }

    /**
     * Create a new {@link HttpRequestTemplate} instance
     * from an {@link HttpRequest} object with insertion point offsets at each URL, cookie, and body parameter position.
     *
     * @param request               An instance of {@link HttpRequest}.
     * @param options               Options to use when generating the template.
     *
     * @return A new instance of {@link HttpRequestTemplate}.
     */
    static HttpRequestTemplate httpRequestTemplate(HttpRequest request, HttpRequestTemplateGenerationOptions options)
    {
        return FACTORY.httpRequestTemplate(request, options);
    }

    /**
     * Create a new {@link HttpRequestTemplate} instance
     * from an HTTP request in a byte array form with insertion point offsets at each URL, cookie, and body parameter position.
     *
     * @param content               An HTTP request in a byte array form.
     * @param options               Options to use when generating the template.
     *
     * @return A new instance of {@link HttpRequestTemplate}.
     */
    static HttpRequestTemplate httpRequestTemplate(ByteArray content, HttpRequestTemplateGenerationOptions options)
    {
        return FACTORY.httpRequestTemplate(content, options);
    }
}
