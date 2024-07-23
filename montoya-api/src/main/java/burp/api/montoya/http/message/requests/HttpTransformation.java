/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.message.requests;

/**
 * This enum defines transformations that Burp can apply to an HTTP request.
 */
public enum HttpTransformation
{
    /**
     * Convert a GET request into a POST request<br>
     * or<br>
     * Convert a POST request into a GET request<br>
     */
    TOGGLE_METHOD
}
