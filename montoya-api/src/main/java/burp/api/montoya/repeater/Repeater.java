/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.repeater;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Provides access to the functionality of the Repeater tool.
 */
public interface Repeater
{
    /**
     * This method can be used to send an HTTP request to the Burp Repeater
     * tool. The request will be displayed in the user interface using a
     * default tab index, but will not be sent until the user initiates
     * this action.
     *
     * @param request The full HTTP request.
     */
    void sendToRepeater(HttpRequest request);

    /**
     * This method can be used to send an HTTP request to the Burp Repeater
     * tool. The request will be displayed in the user interface, but will not
     * be issued until the user initiates this action.
     *
     * @param request The full HTTP request.
     * @param name    An optional caption which will appear on the Repeater
     *                tab containing the request. If this value is {@code null} then a default
     *                tab index will be displayed.
     */
    void sendToRepeater(HttpRequest request, String name);
}
