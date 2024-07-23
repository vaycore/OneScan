/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.params;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Burp HTTP parameter able to retrieve to hold details about an HTTP request parameter.
 */
public interface HttpParameter
{
    /**
     * @return The parameter type.
     */
    HttpParameterType type();

    /**
     * @return The parameter name.
     */
    String name();

    /**
     * @return The parameter value.
     */
    String value();

    /**
     * Create a new Instance of {@code HttpParameter} with {@link HttpParameterType#URL} type.
     *
     * @param name  The parameter name.
     * @param value The parameter value.
     *
     * @return A new {@code HttpParameter} instance.
     */
    static HttpParameter urlParameter(String name, String value)
    {
        return FACTORY.urlParameter(name, value);
    }

    /**
     * Create a new Instance of {@code HttpParameter} with {@link HttpParameterType#BODY} type.
     *
     * @param name  The parameter name.
     * @param value The parameter value.
     *
     * @return A new {@code HttpParameter} instance.
     */
    static HttpParameter bodyParameter(String name, String value)
    {
        return FACTORY.bodyParameter(name, value);
    }

    /**
     * Create a new Instance of {@code HttpParameter} with {@link HttpParameterType#COOKIE} type.
     *
     * @param name  The parameter name.
     * @param value The parameter value.
     *
     * @return A new {@code HttpParameter} instance.
     */
    static HttpParameter cookieParameter(String name, String value)
    {
        return FACTORY.cookieParameter(name, value);
    }

    /**
     * Create a new Instance of {@code HttpParameter} with the specified type.
     *
     * @param name  The parameter name.
     * @param value The parameter value.
     * @param type  The header type.
     *
     * @return A new {@code HttpParameter} instance.
     */
    static HttpParameter parameter(String name, String value, HttpParameterType type)
    {
        return FACTORY.parameter(name, value, type);
    }
}
