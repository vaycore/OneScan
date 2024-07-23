/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.requests;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpMessage;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;

import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Burp HTTP request able to retrieve and modify details of an HTTP request.
 */
public interface HttpRequest extends HttpMessage
{
    /**
     * @return True if the request is in-scope.
     */
    boolean isInScope();

    /**
     * HTTP service for the request.
     *
     * @return An {@link HttpService} object containing details of the HTTP service.
     */
    HttpService httpService();

    /**
     * URL for the request.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return The URL in the request.
     * @throws MalformedRequestException if request is malformed.
     */
    String url();

    /**
     * HTTP method for the request.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return The HTTP method used in the request.
     * @throws MalformedRequestException if request is malformed.
     */
    String method();

    /**
     * Request path including the query parameters.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return the path and query parameters.
     * @throws MalformedRequestException if request is malformed.
     */
    String path();

    /**
     * The query for the request.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return the query, or an empty string if there is none.
     * @throws MalformedRequestException if request is malformed.
     */
    String query();

    /**
     * Request path excluding the query parameters.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return the path excluding query parameters.
     * @throws MalformedRequestException if request is malformed.
     */
    String pathWithoutQuery();

    /**
     * The file extension for the request.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return the file extension, or an empty string if there is none.
     * @throws MalformedRequestException if request is malformed.
     */
    String fileExtension();

    /**
     * @return The detected content type of the request.
     */
    ContentType contentType();

    /**
     * @return The parameters contained in the request.
     */
    List<ParsedHttpParameter> parameters();

    /**
     * @param type The type of parameter that will be returned in the filtered list.
     *
     * @return A filtered list of {@link ParsedHttpParameter} containing only the provided type.
     */
    List<ParsedHttpParameter> parameters(HttpParameterType type);

    /**
     * @return True if the request has parameters.
     */
    boolean hasParameters();

    /**
     * @return True if the request has parameters of type {@link HttpParameterType}
     */
    boolean hasParameters(HttpParameterType type);

    /**
     * @param name The name of the parameter to find.
     * @param type The type of the parameter to find.
     *
     * @return An instance of {@link ParsedHttpParameter} that matches the type and name specified. {@code null} if not found.
     */
    ParsedHttpParameter parameter(String name, HttpParameterType type);

    /**
     * @param name The name of the parameter to get the value from.
     * @param type The type of the parameter to get the value from.
     *
     * @return The value of the parameter that matches the name and type specified. {@code null} if not found.
     */
    String parameterValue(String name, HttpParameterType type);

    /**
     * @param name The name of the parameter to find.
     * @param type The type of the parameter to find.
     *
     * @return {@code true} if a parameter exists that matches the name and type specified. {@code false} if not found.
     */
    boolean hasParameter(String name, HttpParameterType type);

    /**
     * @param parameter An instance of {@link HttpParameter} to match to an existing parameter.
     *
     * @return {@code true} if a parameter exists that matches the data within the provided {@link HttpParameter}. {@code false} if not found.
     */
    boolean hasParameter(HttpParameter parameter);

    /**
     * @param header The header to check if it exists in the request.
     *
     * @return True if the header exists in the request.
     */
    @Override
    boolean hasHeader(HttpHeader header);

    /**
     * @param name The name of the header to query within the request.
     *
     * @return True if a header exists in the request with the supplied name.
     */
    @Override
    boolean hasHeader(String name);

    /**
     * @param name  The name of the header to check.
     * @param value The value of the header to check.
     *
     * @return True if a header exists in the request that matches the name and value supplied.
     */
    @Override
    boolean hasHeader(String name, String value);

    /**
     * @param name The name of the header to retrieve.
     *
     * @return An instance of {@link HttpHeader} that matches the name supplied, {@code null} if no match found.
     */
    @Override
    HttpHeader header(String name);

    /**
     * @param name The name of the header to retrieve.
     *
     * @return The {@code String} value of the header that matches the name supplied, {@code null} if no match found.
     */
    @Override
    String headerValue(String name);

    /**
     * HTTP headers contained in the message.
     *
     * @return A list of HTTP headers.
     */
    @Override
    List<HttpHeader> headers();

    /**
     * HTTP Version text parsed from the request or response line for HTTP 1 messages.
     * HTTP 2 messages will return "HTTP/2"
     *
     * @return Version string
     */
    @Override
    String httpVersion();

    /**
     * Offset within the message where the message body begins.
     *
     * @return The message body offset.
     */
    @Override
    int bodyOffset();

    /**
     * Body of a message as a byte array.
     *
     * @return The body of a message as a byte array.
     */
    @Override
    ByteArray body();

    /**
     * Body of a message as a {@code String}.
     *
     * @return The body of a message as a {@code String}.
     */
    @Override
    String bodyToString();

    /**
     * Markers for the message.
     *
     * @return A list of markers.
     */
    @Override
    List<Marker> markers();

    /**
     * Searches the data in the HTTP message for the specified search term.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return True if the search term is found.
     */
    @Override
    boolean contains(String searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the HTTP message for the specified regular expression.
     *
     * @param pattern The regular expression to be searched for.
     *
     * @return True if the pattern is matched.
     */
    @Override
    boolean contains(Pattern pattern);

    /**
     * Message as a byte array.
     *
     * @return The message as a byte array.
     */
    @Override
    ByteArray toByteArray();

    /**
     * Message as a {@code String}.
     *
     * @return The message as a {@code String}.
     */
    @Override
    String toString();

    /**
     * Create a copy of the {@code HttpRequest} in temporary file.<br>
     * This method is used to save the {@code HttpRequest} object to a temporary file,
     * so that it is no longer held in memory. Extensions can use this method to convert
     * {@code HttpRequest} objects into a form suitable for long-term usage.
     *
     * @return A new {@code HttpRequest} instance stored in temporary file.
     */
    HttpRequest copyToTempFile();

    /**
     * Create a copy of the {@code HttpRequest} with the new service.
     *
     * @param service An {@link HttpService} reference to add.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withService(HttpService service);

    /**
     * Create a copy of the {@code HttpRequest} with the new path.
     *
     * @param path The path to use.
     *
     * @return A new {@code HttpRequest} instance with updated path.
     */
    HttpRequest withPath(String path);

    /**
     * Create a copy of the {@code HttpRequest} with the new method.
     *
     * @param method the method to use
     *
     * @return a new {@code HttpRequest} instance with updated method.
     */
    HttpRequest withMethod(String method);

    /**
     * Create a copy of the {@code HttpRequest} with the added or updated header.<br>
     * If the header exists in the request, it is updated.<br>
     * If the header doesn't exist in the request, it is added.
     *
     * @param header HTTP header to add or update.
     *
     * @return A new {@code HttpRequest} with the added or updated header.
     */
    HttpRequest withHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpRequest} with the added or updated header.<br>
     * If the header exists in the request, it is updated.<br>
     * If the header doesn't exist in the request, it is added.
     *
     * @param name  The name of the header.
     * @param value The value of the header.
     *
     * @return A new {@code HttpRequest} with the added or updated header.
     */
    HttpRequest withHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpRequest} with the HTTP parameter.<br>
     * If the parameter exists in the request, it is updated.<br>
     * If the parameter doesn't exist in the request, it is added.
     *
     * @param parameters HTTP parameter to add or update.
     *
     * @return A new {@code HttpRequest} with the added or updated parameter.
     */
    HttpRequest withParameter(HttpParameter parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the added HTTP parameters.
     *
     * @param parameters HTTP parameters to add.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withAddedParameters(List<? extends HttpParameter> parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the added HTTP parameters.
     *
     * @param parameters HTTP parameters to add.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withAddedParameters(HttpParameter... parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the removed HTTP parameters.
     *
     * @param parameters HTTP parameters to remove.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withRemovedParameters(List<? extends HttpParameter> parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the removed HTTP parameters.
     *
     * @param parameters HTTP parameters to remove.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withRemovedParameters(HttpParameter... parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the updated HTTP parameters.<br>
     *
     * @param parameters HTTP parameters to update.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withUpdatedParameters(List<? extends HttpParameter> parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the updated HTTP parameters.<br>
     *
     * @param parameters HTTP parameters to update.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withUpdatedParameters(HttpParameter... parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the transformation applied.
     *
     * @param transformation Transformation to apply.
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withTransformationApplied(HttpTransformation transformation);

    /**
     * Create a copy of the {@code HttpRequest} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the request
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withBody(String body);

    /**
     * Create a copy of the {@code HttpRequest} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the request
     *
     * @return A new {@code HttpRequest} instance.
     */
    HttpRequest withBody(ByteArray body);

    /**
     * Create a copy of the {@code HttpRequest} with the added header.
     *
     * @param name  The name of the header.
     * @param value The value of the header.
     *
     * @return The updated HTTP request with the added header.
     */
    HttpRequest withAddedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpRequest} with the added header.
     *
     * @param header The {@link HttpHeader} to add to the HTTP request.
     *
     * @return The updated HTTP request with the added header.
     */
    HttpRequest withAddedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpRequest} with the updated header.
     *
     * @param name  The name of the header to update the value of.
     * @param value The new value of the specified HTTP header.
     *
     * @return The updated request containing the updated header.
     */
    HttpRequest withUpdatedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpRequest} with the updated header.
     *
     * @param header The {@link HttpHeader} to update containing the new value.
     *
     * @return The updated request containing the updated header.
     */
    HttpRequest withUpdatedHeader(HttpHeader header);

    /**
     * Removes an existing HTTP header from the current request.
     *
     * @param name The name of the HTTP header to remove from the request.
     *
     * @return The updated request containing the removed header.
     */
    HttpRequest withRemovedHeader(String name);

    /**
     * Removes an existing HTTP header from the current request.
     *
     * @param header The {@link HttpHeader} to remove from the request.
     *
     * @return The updated request containing the removed header.
     */
    HttpRequest withRemovedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpRequest} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@link HttpRequest} instance.
     */
    HttpRequest withMarkers(List<Marker> markers);

    /**
     * Create a copy of the {@code HttpRequest} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@link HttpRequest} instance.
     */
    HttpRequest withMarkers(Marker... markers);

    /**
     * Create a copy of the {@code HttpRequest} with added default headers.
     *
     * @return a new {@link HttpRequest} with added default headers
     */
    HttpRequest withDefaultHeaders();

    /**
     * Create a new empty instance of {@link HttpRequest}.<br>
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest httpRequest()
    {
        return FACTORY.httpRequest();
    }

    /**
     * Create a new instance of {@link HttpRequest}.<br>
     *
     * @param request The HTTP request
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest httpRequest(ByteArray request)
    {
        return FACTORY.httpRequest(request);
    }

    /**
     * Create a new instance of {@link HttpRequest}.<br>
     *
     * @param request The HTTP request.
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest httpRequest(String request)
    {
        return FACTORY.httpRequest(request);
    }

    /**
     * Create a new instance of {@link HttpRequest}.<br>
     *
     * @param service An HTTP service for the request.
     * @param request The HTTP request.
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest httpRequest(HttpService service, ByteArray request)
    {
        return FACTORY.httpRequest(service, request);
    }

    /**
     * Create a new instance of {@link HttpRequest}.<br>
     *
     * @param service An HTTP service for the request.
     * @param request The HTTP request.
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest httpRequest(HttpService service, String request)
    {
        return FACTORY.httpRequest(service, request);
    }

    /**
     * Create a new instance of {@link HttpRequest}.<br>
     *
     * @param url A URL for the request.
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest httpRequestFromUrl(String url)
    {
        return FACTORY.httpRequestFromUrl(url);
    }

    /**
     * Create a new instance of {@link HttpRequest} containing HTTP 2 headers and body.<br>
     *
     * @param service An HTTP service for the request.
     * @param headers A list of HTTP 2 headers.
     * @param body    A body of the HTTP 2 request.
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest http2Request(HttpService service, List<HttpHeader> headers, ByteArray body)
    {
        return FACTORY.http2Request(service, headers, body);
    }

    /**
     * Create a new instance of {@link HttpRequest} containing HTTP 2 headers and body.<br>
     *
     * @param service An HTTP service for the request.
     * @param headers A list of HTTP 2 headers.
     * @param body    A body of the HTTP 2 request.
     *
     * @return A new {@link HttpRequest} instance.
     */
    static HttpRequest http2Request(HttpService service, List<HttpHeader> headers, String body)
    {
        return FACTORY.http2Request(service, headers, body);
    }
}
