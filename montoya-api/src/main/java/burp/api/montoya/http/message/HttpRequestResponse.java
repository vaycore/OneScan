/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.MalformedRequestException;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This interface is used to define a coupling between {@link HttpRequest} and {@link HttpResponse}.
 */
public interface HttpRequestResponse
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
     * Retrieve the timing data associated with this request if available.
     *
     * @return The timing data.
     */
    Optional<TimingData> timingData();

    /**
     * Retrieve the URL for the request.<br>
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return The URL in the request.
     * @throws MalformedRequestException if request is malformed.
     * @deprecated use {@link #request()} url instead.
     */
    @Deprecated()
    String url();

    /**
     * @return True if there is an HTTP response message.
     */
    boolean hasResponse();

    /**
     * @return The detected content type of the request.
     * @deprecated use {@link #request()} contentType instead.
     */
    @Deprecated()
    ContentType contentType();

    /**
     * HTTP status code contained in the response.
     *
     * @return HTTP status code or -1 if there is no response.
     * @deprecated use {@link #response()} statusCode instead.
     */
    @Deprecated()
    short statusCode();

    /**
     * @return List of request markers
     */
    List<Marker> requestMarkers();

    /**
     * @return List of response markers
     */
    List<Marker> responseMarkers();

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

    /**
     * Create a copy of the {@code HttpRequestResponse} in temporary file.<br>
     * This method is used to save the {@code HttpRequestResponse} object to a temporary file,
     * so that it is no longer held in memory. Extensions can use this method to convert
     * {@code HttpRequest} objects into a form suitable for long-term usage.
     *
     * @return A new {@code ByteArray} instance stored in temporary file.
     */
    HttpRequestResponse copyToTempFile();

    /**
     * Create a copy of the {@code HttpRequestResponse} with the added annotations.
     *
     * @param annotations annotations to add.
     *
     * @return A new {@code HttpRequestResponse} instance.
     */
    HttpRequestResponse withAnnotations(Annotations annotations);

    /**
     * Create a copy of the {@code HttpRequestResponse} with the added request markers.
     *
     * @param requestMarkers Request markers to add.
     *
     * @return A new {@code HttpRequestResponse} instance.
     */
    HttpRequestResponse withRequestMarkers(List<Marker> requestMarkers);

    /**
     * Create a copy of the {@code HttpRequestResponse} with the added request markers.
     *
     * @param requestMarkers Request markers to add.
     *
     * @return A new {@code HttpRequestResponse} instance.
     */
    HttpRequestResponse withRequestMarkers(Marker... requestMarkers);

    /**
     * Create a copy of the {@code HttpRequestResponse} with the added response markers.
     *
     * @param responseMarkers Response markers to add.
     *
     * @return A new {@code HttpRequestResponse} instance.
     */
    HttpRequestResponse withResponseMarkers(List<Marker> responseMarkers);

    /**
     * Create a copy of the {@code HttpRequestResponse} with the added response markers.
     *
     * @param responseMarkers Response markers to add.
     *
     * @return A new {@code HttpRequestResponse} instance.
     */
    HttpRequestResponse withResponseMarkers(Marker... responseMarkers);

    /**
     * Create a new instance of {@link HttpRequestResponse}.<br>
     *
     * @param request  The HTTP request.
     * @param response The HTTP response.
     *
     * @return A new {@link HttpRequestResponse} instance.
     */
    static HttpRequestResponse httpRequestResponse(HttpRequest request, HttpResponse response)
    {
        return FACTORY.httpRequestResponse(request, response);
    }

    /**
     * Create a new instance of {@link HttpRequestResponse}.<br>
     *
     * @param httpRequest  The HTTP request.
     * @param httpResponse The HTTP response.
     * @param annotations  annotations.
     *
     * @return A new {@link HttpRequestResponse} instance.
     */
    static HttpRequestResponse httpRequestResponse(HttpRequest httpRequest, HttpResponse httpResponse, Annotations annotations)
    {
        return FACTORY.httpRequestResponse(httpRequest, httpResponse, annotations);
    }
}
