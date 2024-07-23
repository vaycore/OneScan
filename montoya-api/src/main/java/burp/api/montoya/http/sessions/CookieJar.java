/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.sessions;

import burp.api.montoya.http.message.Cookie;

import java.time.ZonedDateTime;
import java.util.List;

/**
 * Provides access to Burp's Cookie Jar functionality.
 */
public interface CookieJar
{
    /**
     * Add a new HTTP cookie to the Cookie Jar.
     *
     * @param name       The name of the cookie.
     * @param value      The value of the cookie.
     * @param path       The path for which the cookie is in scope or {@code null} if none is set.
     * @param domain     The domain for which the cookie is in scope.
     * @param expiration The expiration time for the cookie, or {@code null} if none is set (i.e., for non-persistent session cookies).
     */
    void setCookie(String name, String value, String path, String domain, ZonedDateTime expiration);

    /**
     * @return A list of stored cookies.
     */
    List<Cookie> cookies();
}
