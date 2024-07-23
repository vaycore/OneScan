/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.responses;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.*;
import burp.api.montoya.http.message.responses.analysis.Attribute;
import burp.api.montoya.http.message.responses.analysis.AttributeType;
import burp.api.montoya.http.message.responses.analysis.KeywordCount;

import java.util.List;
import java.util.regex.Pattern;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Burp HTTP response able to retrieve and modify details about an HTTP response.
 */
public interface HttpResponse extends HttpMessage
{
    /**
     * Obtain the HTTP status code contained in the response.
     *
     * @return HTTP status code.
     */
    short statusCode();

    /**
     * Obtain the HTTP reason phrase contained in the response for HTTP 1 messages.
     * HTTP 2 messages will return a mapped phrase based on the status code.
     *
     * @return HTTP Reason phrase.
     */
    String reasonPhrase();

    /**
     * Test whether the status code is in the specified class.
     *
     * @param statusCodeClass The class of status code to test.
     *
     * @return True if the status code is in the class.
     */
    boolean isStatusCodeClass(StatusCodeClass statusCodeClass);

    /**
     * Obtain details of the HTTP cookies set in the response.
     *
     * @return A list of {@link Cookie} objects representing the cookies set in the response, if any.
     */
    List<Cookie> cookies();

    /**
     * @param name The name of the cookie to find.
     *
     * @return An instance of {@link Cookie} that matches the name provided. {@code null} if not found.
     */
    Cookie cookie(String name);

    /**
     * @param name The name of the cookie to retrieve the value from.
     *
     * @return The value of the cookie that matches the name provided. {@code null} if not found.
     */
    String cookieValue(String name);

    /**
     * @param name The name of the cookie to check if it exists in the response.
     *
     * @return {@code true} If a cookie exists within the response that matches the name provided. {@code false} if not.
     */
    boolean hasCookie(String name);

    /**
     * @param cookie An instance of {@link Cookie} to check if it exists in the response.
     *
     * @return {@code true} If a cookie exists within the response that matches the {@link Cookie} provided. {@code false} if not.
     */
    boolean hasCookie(Cookie cookie);

    /**
     * Obtain the MIME type of the response, as determined by Burp Suite.
     *
     * @return The MIME type.
     */
    MimeType mimeType();

    /**
     * Obtain the MIME type of the response, as stated in the HTTP headers.
     *
     * @return The stated MIME type.
     */
    MimeType statedMimeType();

    /**
     * Obtain the MIME type of the response, as inferred from the contents of the HTTP message body.
     *
     * @return The inferred MIME type.
     */
    MimeType inferredMimeType();

    /**
     * Retrieve the number of types given keywords appear in the response.
     *
     * @param keywords Keywords to count.
     *
     * @return List of keyword counts in the order they were provided.
     */
    List<KeywordCount> keywordCounts(String... keywords);

    /**
     * Retrieve the values of response attributes.
     *
     * @param types Response attributes to retrieve values for.
     *
     * @return List of {@link Attribute} objects.
     */
    List<Attribute> attributes(AttributeType... types);

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
     * Create a copy of the {@code HttpResponse} in temporary file.<br>
     * This method is used to save the {@code HttpResponse} object to a temporary file,
     * so that it is no longer held in memory. Extensions can use this method to convert
     * {@code HttpResponse} objects into a form suitable for long-term usage.
     *
     * @return A new {@code HttpResponse} instance stored in temporary file.
     */
    HttpResponse copyToTempFile();

    /**
     * Create a copy of the {@code HttpResponse} with the provided status code.
     *
     * @param statusCode the new status code for response
     *
     * @return A new {@code HttpResponse} instance.
     */
    HttpResponse withStatusCode(short statusCode);

    /**
     * Create a copy of the {@code HttpResponse} with the new reason phrase.
     *
     * @param reasonPhrase the new reason phrase for response
     *
     * @return A new {@code HttpResponse} instance.
     */
    HttpResponse withReasonPhrase(String reasonPhrase);

    /**
     * Create a copy of the {@code HttpResponse} with the new http version.
     *
     * @param httpVersion the new http version for response
     *
     * @return A new {@code HttpResponse} instance.
     */
    HttpResponse withHttpVersion(String httpVersion);

    /**
     * Create a copy of the {@code HttpResponse} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the response
     *
     * @return A new {@code HttpResponse} instance.
     */
    HttpResponse withBody(String body);

    /**
     * Create a copy of the {@code HttpResponse} with the updated body.<br>
     * Updates Content-Length header.
     *
     * @param body the new body for the response
     *
     * @return A new {@code HttpResponse} instance.
     */
    HttpResponse withBody(ByteArray body);

    /**
     * Create a copy of the {@code HttpResponse} with the added header.
     *
     * @param header The {@link HttpHeader} to add to the response.
     *
     * @return The updated response containing the added header.
     */
    HttpResponse withAddedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpResponse}  with the added header.
     *
     * @param name  The name of the header.
     * @param value The value of the header.
     *
     * @return The updated response containing the added header.
     */
    HttpResponse withAddedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpResponse}  with the updated header.
     *
     * @param header The {@link HttpHeader} to update containing the new value.
     *
     * @return The updated response containing the updated header.
     */
    HttpResponse withUpdatedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpResponse}  with the updated header.
     *
     * @param name  The name of the header to update the value of.
     * @param value The new value of the specified HTTP header.
     *
     * @return The updated response containing the updated header.
     */
    HttpResponse withUpdatedHeader(String name, String value);

    /**
     * Create a copy of the {@code HttpResponse}  with the removed header.
     *
     * @param header The {@link HttpHeader} to remove from the response.
     *
     * @return The updated response containing the removed header.
     */
    HttpResponse withRemovedHeader(HttpHeader header);

    /**
     * Create a copy of the {@code HttpResponse}  with the removed header.
     *
     * @param name The name of the HTTP header to remove from the response.
     *
     * @return The updated response containing the removed header.
     */
    HttpResponse withRemovedHeader(String name);

    /**
     * Create a copy of the {@code HttpResponse} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@code MarkedHttpRequestResponse} instance.
     */
    HttpResponse withMarkers(List<Marker> markers);

    /**
     * Create a copy of the {@code HttpResponse} with the added markers.
     *
     * @param markers Request markers to add.
     *
     * @return A new {@code MarkedHttpRequestResponse} instance.
     */
    HttpResponse withMarkers(Marker... markers);

    /**
     * Create a new empty instance of {@link HttpResponse}.<br>
     *
     * @return A new {@link HttpResponse} instance.
     */
    static HttpResponse httpResponse()
    {
        return FACTORY.httpResponse();
    }

    /**
     * Create a new instance of {@link HttpResponse}.<br>
     *
     * @param response The HTTP response.
     *
     * @return A new {@link HttpResponse} instance.
     */
    static HttpResponse httpResponse(ByteArray response)
    {
        return FACTORY.httpResponse(response);
    }

    /**
     * Create a new instance of {@link HttpResponse}.<br>
     *
     * @param response The HTTP response.
     *
     * @return A new {@link HttpResponse} instance.
     */
    static HttpResponse httpResponse(String response)
    {
        return FACTORY.httpResponse(response);
    }
}
