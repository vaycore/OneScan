/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

/**
 * Extensions can implement this interface and then call {@link WebSockets#registerWebSocketCreatedHandler} to register a WebSocket handler.
 * The handler will be notified of new WebSockets created by any Burp tool.
 */
public interface WebSocketCreatedHandler
{
    /**
     * Invoked by Burp when an application WebSocket has been created.
     *
     * @param webSocketCreated {@link WebSocketCreated} containing information about the application websocket that is being created.
     */
    void handleWebSocketCreated(WebSocketCreated webSocketCreated);
}