/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.params;

import burp.api.montoya.core.Range;

/**
 * Burp {@link HttpParameter} with additional details about an HTTP request parameter that has been parsed by Burp.
 */
public interface ParsedHttpParameter extends HttpParameter
{
    /**
     * @return The parameter type.
     */
    @Override
    HttpParameterType type();

    /**
     * @return The parameter name.
     */
    @Override
    String name();

    /**
     * @return The parameter value.
     */
    @Override
    String value();

    /**
     * Offsets of the parameter name within the HTTP request.
     *
     * @return The parameter name offsets.
     */
    Range nameOffsets();

    /**
     * Offsets of the parameter value within the HTTP request.
     *
     * @return The parameter value offsets.
     */
    Range valueOffsets();
}
