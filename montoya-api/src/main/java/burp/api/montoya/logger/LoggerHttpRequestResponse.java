/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.logger;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.regex.Pattern;

/**
 * This interface is used to define a coupling between {@link HttpRequest} and {@link HttpResponse} for the Logger.
 */
public interface LoggerHttpRequestResponse
{
    /**
     * @return The HTTP request message.
     */
    HttpRequest request();

    /**
     * @return The HTTP response message.
     */
    HttpResponse response();

    /**
     * HTTP service for the request.
     *
     * @return An {@link HttpService} object containing details of the HTTP service.
     */
    HttpService httpService();

    /**
     * @return The annotations.
     */
    Annotations annotations();

    /**
     * Returns the date and time at which Burp Logger received the request.
     *
     * @return The time at which Burp Logger received the request.
     */
    ZonedDateTime time();

    /**
     * Obtain the MIME type of the response or request, as determined by Burp Suite.
     * If there is no response the mime type will be determined from the request url.
     *
     * @return The MIME type.
     */
    MimeType mimeType();

    /**
     * @return True if there is a response.
     */
    boolean hasResponse();

    /**
     * Retrieve the timing data associated with this request.
     *
     * @return The timing data.
     */
    TimingData timingData();

    /**
     * The page title for the response.
     *
     * @return The page title, or an empty string if none exists.
     */
    String pageTitle();

    /**
     * The tool that issued the request.
     *
     * @return ToolSource which indicates which Burp tool sent the request.
     */
    ToolSource toolSource();

    /**
     * Searches the data in the HTTP request, response and notes for the specified search term.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return True if the search term is found.
     */
    boolean contains(String searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the HTTP request, response and notes for the specified regular expression.
     *
     * @param pattern The regular expression to be searched for.
     *
     * @return True if the pattern is matched.
     */
    boolean contains(Pattern pattern);
}
