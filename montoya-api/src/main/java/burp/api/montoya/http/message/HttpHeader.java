/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Burp HTTP header able to retrieve to hold details about an HTTP header.
 */
public interface HttpHeader
{
    /**
     * @return The name of the header.
     */
    String name();

    /**
     * @return The value of the header.
     */
    String value();

    /**
     * @return The {@code String} representation of the header.
     */
    @Override
    String toString();

    /**
     * Create a new instance of {@code HttpHeader} from name and value.
     *
     * @param name  The name of the header.
     * @param value The value of the header.
     *
     * @return A new {@code HttpHeader} instance.
     */
    static HttpHeader httpHeader(String name, String value)
    {
        return FACTORY.httpHeader(name, value);
    }

    /**
     * Create a new instance of HttpHeader from a {@code String} header representation.
     * It will be parsed according to the HTTP/1.1 specification for headers.
     *
     * @param header The {@code String} header representation.
     *
     * @return A new {@code HttpHeader} instance.
     */
    static HttpHeader httpHeader(String header)
    {
        return FACTORY.httpHeader(header);
    }
}
