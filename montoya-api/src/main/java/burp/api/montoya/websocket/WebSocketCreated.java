/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

import burp.api.montoya.core.ToolSource;
import burp.api.montoya.http.message.requests.HttpRequest;

public interface WebSocketCreated
{
    /**
     * @return The WebSocket that was created.
     */
    WebSocket webSocket();

    /**
     * @return The HTTP upgrade request that initiated the WebSocket creation.
     */
    HttpRequest upgradeRequest();

    /**
     * @return Indicates which Burp tool that created the WebSocket.
     */
    ToolSource toolSource();
}
