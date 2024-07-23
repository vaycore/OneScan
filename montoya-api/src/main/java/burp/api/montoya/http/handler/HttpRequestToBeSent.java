/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.handler;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.requests.HttpTransformation;
import burp.api.montoya.http.message.requests.MalformedRequestException;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Burp {@link HttpRequest} with additional methods to retrieve {@link Annotations} and {@link ToolSource} of the request.
 */
public interface HttpRequestToBeSent extends HttpRequest
{
    /**
     * @return The ID for this request to be sent. The corresponding response will have an identical ID.
     */
    int messageId();

    /**
     * @return annotations for request/response
     */
    Annotations annotations();

    /**
     * @return Indicates which Burp tool sent the request.
     */
    ToolSource toolSource();

    /**
     * @return True if the request is in-scope.
     */
    @Override
    boolean isInScope();

    /**
     * HTTP service for the request.
     *
     * @return An {@link HttpService} object containing details of the HTTP service.
     */
    @Override
    HttpService httpService();

    /**
     * URL for the request.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return The URL in the request.
     * @throws MalformedRequestException if request is malformed.
     */
    @Override
    String url();

    /**
     * HTTP method for the request.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return The HTTP method used in the request.
     * @throws MalformedRequestException if request is malformed.
     */
    @Override
    String method();

    /**
     * Request path including the query parameters.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return the path and query parameters.
     * @throws MalformedRequestException if request is malformed.
     */
    @Override
    String path();

    /**
     * Request path excluding the query parameters.
     * If the request is malformed, then a {@link MalformedRequestException} is thrown.
     *
     * @return the path excluding query parameters.
     * @throws MalformedRequestException if request is malformed.
     */
    @Override
    String pathWithoutQuery();

    /**
     * HTTP Version text parsed from the request line for HTTP 1 messages.
     * HTTP 2 messages will return "HTTP/2"
     *
     * @return Version string
     */
    @Override
    String httpVersion();

    /**
     * HTTP headers contained in the message.
     *
     * @return A list of HTTP headers.
     */
    @Override
    List<HttpHeader> headers();

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
     * @return True if the request has parameters.
     */
    @Override
    boolean hasParameters();

    /**
     * @return True if the request has parameters of type {@link HttpParameterType}
     */
    @Override
    boolean hasParameters(HttpParameterType type);

    /**
     * @param name The name of the parameter to find.
     * @param type The type of the parameter to find.
     *
     * @return An instance of {@link ParsedHttpParameter} that matches the type and name specified. {@code null} if not found.
     */
    @Override
    ParsedHttpParameter parameter(String name, HttpParameterType type);

    /**
     * @param name The name of the parameter to get the value from.
     * @param type The type of the parameter to get the value from.
     *
     * @return The value of the parameter that matches the name and type specified. {@code null} if not found.
     */
    @Override
    String parameterValue(String name, HttpParameterType type);

    /**
     * @param name The name of the parameter to find.
     * @param type The type of the parameter to find.
     *
     * @return {@code true} if a parameter exists that matches the name and type specified. {@code false} if not found.
     */
    @Override
    boolean hasParameter(String name, HttpParameterType type);

    /**
     * @param parameter An instance of {@link HttpParameter} to match to an existing parameter.
     *
     * @return {@code true} if a parameter exists that matches the data within the provided {@link HttpParameter}. {@code false} if not found.
     */
    @Override
    boolean hasParameter(HttpParameter parameter);

    /**
     * @return The detected content type of the request.
     */
    @Override
    ContentType contentType();

    /**
     * @return The parameters contained in the request.
     */
    @Override
    List<ParsedHttpParameter> parameters();

    /**
     * @param type The type of parameter that will be returned in the filtered list.
     *
     * @return A filtered list of {@link ParsedHttpParameter} containing only the provided type.
     */
    @Override
    List<ParsedHttpParameter> parameters(HttpParameterType type);

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
     * Offset within the message where the message body begins.
     *
     * @return The message body offset.
     */
    @Override
    int bodyOffset();

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
    @Override
    HttpRequest withService(HttpService service);

    /**
     * Create a copy of the {@code HttpRequest} with the new path.
     *
     * @param path The path to use.
     *
     * @return A new {@code HttpRequest} instance with updated path.
     */
    @Override
    HttpRequest withPath(String path);

    /**
     * Create a copy of the {@code HttpRequest} with the new method.
     *
     * @param method the method to use
     *
     * @return a new {@code HttpRequest} instance with updated method.
     */
    @Override
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
    @Override
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
    @Override
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
    @Override
    HttpRequest withParameter(HttpParameter parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the added HTTP parameters.
     *
     * @param parameters HTTP parameters to add.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withAddedParameters(List<? extends HttpParameter> parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the added HTTP parameters.
     *
     * @param parameters HTTP parameters to add.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withAddedParameters(HttpParameter... parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the removed HTTP parameters.
     *
     * @param parameters HTTP parameters to remove.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withRemovedParameters(List<? extends HttpParameter> parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the removed HTTP parameters.
     *
     * @param parameters HTTP parameters to remove.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withRemovedParameters(HttpParameter... parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the updated HTTP parameters.<br>
     *
     * @param parameters HTTP parameters to update.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withUpdatedParameters(List<? extends HttpParameter> parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the updated HTTP parameters.<br>
     *
     * @param parameters HTTP parameters to update.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withUpdatedParameters(HttpParameter... parameters);

    /**
     * Create a copy of the {@code HttpRequest} with the transformation applied.
     *
     * @param transformation Transformation to apply.
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withTransformationApplied(HttpTransformation transformation);

    /**
     * Create a copy of the {@code HttpRequest} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the request
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withBody(String body);

    /**
     * Create a copy of the {@code HttpRequest} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the request
     *
     * @return A new {@code HttpRequest} instance.
     */
    @Override
    HttpRequest withBody(ByteArray body);

    /**
     * Create a copy of the {@code HttpRequest} with the added header.
     *
     * @param name  The name of the header.
     * @param value The value of the header.
     *
     * @return The updated HTTP request with the added header.
     */
    @Override
    HttpRequest withAddedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpRequest} with the added header.
     *
     * @param header The {@link HttpHeader} to add to the HTTP request.
     *
     * @return The updated HTTP request with the added header.
     */
    @Override
    HttpRequest withAddedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpRequest} with the updated header.
     *
     * @param name  The name of the header to update the value of.
     * @param value The new value of the specified HTTP header.
     *
     * @return The updated request containing the updated header.
     */
    @Override
    HttpRequest withUpdatedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpRequest} with the updated header.
     *
     * @param header The {@link HttpHeader} to update containing the new value.
     *
     * @return The updated request containing the updated header.
     */
    @Override
    HttpRequest withUpdatedHeader(HttpHeader header);

    /**
     * Removes an existing HTTP header from the current request.
     *
     * @param name The name of the HTTP header to remove from the request.
     *
     * @return The updated request containing the removed header.
     */
    @Override
    HttpRequest withRemovedHeader(String name);

    /**
     * Removes an existing HTTP header from the current request.
     *
     * @param header The {@link HttpHeader} to remove from the request.
     *
     * @return The updated request containing the removed header.
     */
    @Override
    HttpRequest withRemovedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpRequest} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@link HttpRequest} instance.
     */
    @Override
    HttpRequest withMarkers(List<Marker> markers);

    /**
     * Create a copy of the {@code HttpRequest} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@link HttpRequest} instance.
     */
    @Override
    HttpRequest withMarkers(Marker... markers);

    /**
     * Create a copy of the {@code HttpRequest} with added default headers.
     *
     * @return a new {@link HttpRequest} with added default headers
     */
    @Override
    HttpRequest withDefaultHeaders();
}
