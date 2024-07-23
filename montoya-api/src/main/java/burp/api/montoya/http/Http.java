/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.analysis.ResponseKeywordsAnalyzer;
import burp.api.montoya.http.message.responses.analysis.ResponseVariationsAnalyzer;
import burp.api.montoya.http.sessions.CookieJar;
import burp.api.montoya.http.sessions.SessionHandlingAction;

import java.util.List;

/**
 * Provides access HTTP related functionality of Burp.
 */
public interface Http
{
    /**
     * Register a handler which will perform an action when a request is about to be sent
     * or a response was received by any Burp tool.
     *
     * @param handler An object created by the extension that implements {@link HttpHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerHttpHandler(HttpHandler handler);

    /**
     * Register a custom session handler. Each registered handler will be available
     * within the session handling rule UI for the user to select as a rule action. Users can choose to invoke a
     * handler directly in its own right, or following execution of a macro.
     *
     * @param sessionHandlingAction An object created by the extension that implements {@link SessionHandlingAction} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerSessionHandlingAction(SessionHandlingAction sessionHandlingAction);

    /**
     * Send HTTP requests and retrieve their responses.
     *
     * @param request The full HTTP request.
     *
     * @return An object that implements the {@link HttpRequestResponse} interface, and which the extension can query to obtain the details of the response.
     */
    HttpRequestResponse sendRequest(HttpRequest request);

    /**
     * Send HTTP requests and retrieve their responses.
     *
     * @param request  The full HTTP request.
     * @param httpMode An {@link HttpMode} enum value which indicates how a request should be sent.
     *
     * @return An object that implements the {@link HttpRequestResponse} interface, and which the extension can query to obtain the details of the response.
     */
    HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode);

    /**
     * Send HTTP requests and retrieve their responses.
     *
     * @param request      The full HTTP request.
     * @param httpMode     An {@link HttpMode} enum value which indicates how a request should be sent.
     * @param connectionId The identifier for the connection you want to use.
     *
     * @return An object that implements the {@link HttpRequestResponse} interface, and which the extension can query to obtain the details of the response.
     */
    HttpRequestResponse sendRequest(HttpRequest request, HttpMode httpMode, String connectionId);

    /**
     * Send HTTP request with specific request options and retrieve its response.
     *
     * @param request        The full HTTP request.
     * @param requestOptions A {@link RequestOptions} value which indicates how a request should be sent.
     *
     * @return An object that implements the {@link HttpRequestResponse} interface, and which the extension can query to obtain the details of the response.
     */
    HttpRequestResponse sendRequest(HttpRequest request, RequestOptions requestOptions);

    /**
     * Send HTTP requests in parallel and retrieve their responses.
     *
     * @param requests The list of full HTTP requests.
     *
     * @return A list of objects that implement the {@link HttpRequestResponse} interface, and which the extension can query to obtain the details of the responses.
     */
    List<HttpRequestResponse> sendRequests(List<HttpRequest> requests);

    /**
     * Send HTTP requests in parallel and retrieve their responses.
     *
     * @param requests The list of full HTTP requests.
     * @param httpMode An {@link HttpMode} enum value which indicates how a request should be sent.
     *
     * @return A list of objects that implement the {@link HttpRequestResponse} interface, and which the extension can query to obtain the details of the responses.
     */
    List<HttpRequestResponse> sendRequests(List<HttpRequest> requests, HttpMode httpMode);

    /**
     * Create a new response keyword analyzer.
     *
     * @param keywords A list of keywords the analyzer will look for.
     *
     * @return A new {@link ResponseKeywordsAnalyzer} instance.
     */
    ResponseKeywordsAnalyzer createResponseKeywordsAnalyzer(List<String> keywords);

    /**
     * Create a new response variations analyzer.
     *
     * @return A new {@link ResponseKeywordsAnalyzer} instance.
     */
    ResponseVariationsAnalyzer createResponseVariationsAnalyzer();

    /**
     * Access the Cookie Jar.
     *
     * @return The {@link CookieJar} instance.
     */
    CookieJar cookieJar();
}
