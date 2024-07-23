/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

import burp.api.montoya.core.Registration;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation;

/**
 * Provides access to WebSocket related functionality of Burp.
 */
public interface WebSockets
{
    /**
     * Register a handler which will be invoked whenever a WebSocket is created by any Burp tool.
     *
     * @param handler An object created by the extension that implements {@link WebSocketCreatedHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerWebSocketCreatedHandler(WebSocketCreatedHandler handler);

    /**
     * Create a new WebSocket using the specified service and path.
     *
     * @param service An {@link HttpService} specifying the target host
     * @param path path for the upgrade HTTP request
     *
     * @return The {@link ExtensionWebSocketCreation} result.
     */
    ExtensionWebSocketCreation createWebSocket(HttpService service, String path);

    /**
     * Create a new WebSocket using the specified upgrade request.
     *
     * @param upgradeRequest The {@link HttpRequest} upgrade request
     *
     * @return The {@link ExtensionWebSocketCreation} result.
     */
    ExtensionWebSocketCreation createWebSocket(HttpRequest upgradeRequest);
}
