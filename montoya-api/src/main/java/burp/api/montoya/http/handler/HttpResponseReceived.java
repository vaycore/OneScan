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
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.StatusCodeClass;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Burp {@link HttpResponse} with additional methods to retrieve initiating {@link HttpRequest} as well as the {@link Annotations} and {@link ToolSource} of the request.
 */
public interface HttpResponseReceived extends HttpResponse
{
    /**
     * @return The ID for this response which is identical to the ID on the corresponding request.
     */
    int messageId();

    /**
     * @return initiatingRequest The HTTP request that was sent.
     */
    HttpRequest initiatingRequest();

    /**
     * @return Annotations for request/response.
     */
    Annotations annotations();

    /**
     * @return ToolSource which indicates which Burp tool sent the request.
     */
    ToolSource toolSource();

    /**
     * Obtain the HTTP status code contained in the response.
     *
     * @return HTTP status code.
     */
    @Override
    short statusCode();

    /**
     * Obtain the HTTP reason phrase contained in the response for HTTP 1 messages.
     * HTTP 2 messages will return a mapped phrase based on the status code.
     *
     * @return HTTP Reason phrase.
     */
    @Override
    String reasonPhrase();

    /**
     * Test whether the status code is in the specified class.
     *
     * @param statusCodeClass The class of status code to test.
     *
     * @return True if the status code is in the class.
     */
    @Override
    boolean isStatusCodeClass(StatusCodeClass statusCodeClass);

    /**
     * Return the HTTP Version text parsed from the response line for HTTP 1 messages.
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
     * Offset within the message where the message body begins.
     *
     * @return The message body offset.
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
     * Obtain details of the HTTP cookies set in the response.
     *
     * @return A list of {@link Cookie} objects representing the cookies set in the response, if any.
     */
    @Override
    List<Cookie> cookies();

    /**
     * @param name The name of the cookie to find.
     *
     * @return An instance of {@link Cookie} that matches the name provided. {@code null} if not found.
     */
    @Override
    Cookie cookie(String name);

    /**
     * @param name The name of the cookie to retrieve the value from.
     *
     * @return The value of the cookie that matches the name provided. {@code null} if not found.
     */
    @Override
    String cookieValue(String name);

    /**
     * @param name The name of the cookie to check if it exists in the response.
     *
     * @return {@code true} If a cookie exists within the response that matches the name provided. {@code false} if not.
     */
    @Override
    boolean hasCookie(String name);

    /**
     * @param cookie An instance of {@link Cookie} to check if it exists in the response.
     *
     * @return {@code true} If a cookie exists within the response that matches the {@link Cookie} provided. {@code false} if not.
     */
    @Override
    boolean hasCookie(Cookie cookie);

    /**
     * Obtain the MIME type of the response, as determined by Burp Suite.
     *
     * @return The MIME type.
     */
    @Override
    MimeType mimeType();

    /**
     * Obtain the MIME type of the response, as stated in the HTTP headers.
     *
     * @return The stated MIME type.
     */
    @Override
    MimeType statedMimeType();

    /**
     * Obtain the MIME type of the response, as inferred from the contents of the HTTP message body.
     *
     * @return The inferred MIME type.
     */
    @Override
    MimeType inferredMimeType();

    /**
     * Retrieve the number of types given keywords appear in the response.
     *
     * @param keywords Keywords to count.
     *
     * @return List of keyword counts in the order they were provided.
     */
    @Override
    List<KeywordCount> keywordCounts(String... keywords);

    /**
     * Retrieve the values of response attributes.
     *
     * @param types Response attributes to retrieve values for.
     *
     * @return List of {@link Attribute} objects.
     */
    @Override
    List<Attribute> attributes(AttributeType... types);

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
     * Create a copy of the {@code HttpResponse} with the provided status code.
     *
     * @param statusCode the new status code for response
     *
     * @return A new {@code HttpResponse} instance.
     */
    @Override
    HttpResponse withStatusCode(short statusCode);

    /**
     * Create a copy of the {@code HttpResponse} with the new reason phrase.
     *
     * @param reasonPhrase the new reason phrase for response
     *
     * @return A new {@code HttpResponse} instance.
     */
    @Override
    HttpResponse withReasonPhrase(String reasonPhrase);

    /**
     * Create a copy of the {@code HttpResponse} with the new http version.
     *
     * @param httpVersion the new http version for response
     *
     * @return A new {@code HttpResponse} instance.
     */
    @Override
    HttpResponse withHttpVersion(String httpVersion);

    /**
     * Create a copy of the {@code HttpResponse} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the response
     *
     * @return A new {@code HttpResponse} instance.
     */
    @Override
    HttpResponse withBody(String body);

    /**
     * Create a copy of the {@code HttpResponse} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the response
     *
     * @return A new {@code HttpResponse} instance.
     */
    @Override
    HttpResponse withBody(ByteArray body);

    /**
     * Create a copy of the {@code HttpResponse} with the added header.
     *
     * @param header The {@link HttpHeader} to add to the response.
     *
     * @return The updated response containing the added header.
     */
    @Override
    HttpResponse withAddedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpResponse}  with the added header.
     *
     * @param name  The name of the header.
     * @param value The value of the header.
     *
     * @return The updated response containing the added header.
     */
    @Override
    HttpResponse withAddedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpResponse}  with the updated header.
     *
     * @param header The {@link HttpHeader} to update containing the new value.
     *
     * @return The updated response containing the updated header.
     */
    @Override
    HttpResponse withUpdatedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpResponse}  with the updated header.
     *
     * @param name  The name of the header to update the value of.
     * @param value The new value of the specified HTTP header.
     *
     * @return The updated response containing the updated header.
     */
    @Override
    HttpResponse withUpdatedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpResponse}  with the removed header.
     *
     * @param header The {@link HttpHeader} to remove from the response.
     *
     * @return The updated response containing the removed header.
     */
    @Override
    HttpResponse withRemovedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpResponse}  with the removed header.
     *
     * @param name The name of the HTTP header to remove from the response.
     *
     * @return The updated response containing the removed header.
     */
    @Override
    HttpResponse withRemovedHeader(String name);

    /**
     * Create a copy of the {@code HttpResponse} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@code MarkedHttpRequestResponse} instance.
     */
    @Override
    HttpResponse withMarkers(List<Marker> markers);

    /**
     * Create a copy of the {@code HttpResponse} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@code MarkedHttpRequestResponse} instance.
     */
    @Override
    HttpResponse withMarkers(Marker... markers);
}
