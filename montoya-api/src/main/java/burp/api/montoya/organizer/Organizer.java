/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.organizer;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Provides access to the functionality of the Organizer tool.
 */
public interface Organizer
{
    /**
     * This method can be used to send an HTTP request to the Burp Organizer
     * tool.
     *
     * @param request The full HTTP request.
     */
    void sendToOrganizer(HttpRequest request);

    /**
     * This method can be used to send an HTTP request and response to the Burp
     * Organizer tool.
     *
     * @param requestResponse The full HTTP request and response.
     */
    void sendToOrganizer(HttpRequestResponse requestResponse);
}
