/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

import burp.api.montoya.http.HttpProtocol;
import burp.api.montoya.http.message.HttpRequestResponse;

/**
 * Provides information about an HTTP interaction detected by
 * Burp Collaborator.
 */
public interface HttpDetails
{
    /**
     * HTTP protocol.
     *
     * @return The HTTP protocol used by the interaction.
     */
    HttpProtocol protocol();

    /**
     * HTTP request and response.
     *
     * @return The HTTP request sent to the Collaborator server and the
     * server's response.
     */
    HttpRequestResponse requestResponse();
}
