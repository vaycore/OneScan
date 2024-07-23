/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http;

/**
 * HTTP modes when sending a request.
 */
public enum HttpMode
{
    /**
     * Use the HTTP protocol specified by the server
     */
    AUTO,
    /**
     * Use HTTP 1 protocol for the connection.<br>
     * Will error if server is HTTP 2 only.
     */
    HTTP_1,
    /**
     * Use HTTP 2 protocol for the connection.<br>
     * Will error if server is HTTP 1 only.
     */
    HTTP_2,
    /**
     * Force HTTP 2 and ignore ALPN.<br>
     * Will <b>not</b> error if server is HTTP 1 only.
     */
    HTTP_2_IGNORE_ALPN
}
