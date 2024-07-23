/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.handler;

/**
 * Action to be taken when intercepting HTTP requests.
 */
public enum RequestAction
{
    /**
     * Causes Burp to send the request.
     */
    CONTINUE
}
