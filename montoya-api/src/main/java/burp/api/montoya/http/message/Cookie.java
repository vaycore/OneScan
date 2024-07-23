/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.time.ZonedDateTime;
import java.util.Optional;

/**
 * Burp cookie able to retrieve and hold details about a cookie.
 */
public interface Cookie
{
    /**
     * @return The name of the cookie
     */
    String name();

    /**
     * @return The value of the cookie.
     */
    String value();

    /**
     * Domain for which the cookie is in scope. <br>
     * <b>Note:</b> For cookies that have been obtained from generated responses
     * (by calling {@link HttpResponse#httpResponse} and then {@link HttpResponse#cookies}), the domain will be {@code null} if the response
     * did not explicitly set a domain attribute for the cookie.
     *
     * @return The domain for which the cookie is in scope.
     */
    String domain();

    /**
     * Path for which the cookie is in scope.
     *
     * @return The path for which the cookie is in scope or {@code null} if none is set.
     */
    String path();

    /**
     * Expiration time for the cookie if available.
     *
     * @return The expiration time for the cookie (i.e., for non-persistent session cookies).
     */
    Optional<ZonedDateTime> expiration();
}
