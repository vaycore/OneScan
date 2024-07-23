/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket.extension;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.Optional;

/**
 * Result of a WebSocket creation attempt
 */
public interface ExtensionWebSocketCreation
{
    /**
     * The status of the WebSocket creation attempt.
     *
     * @return The {@link ExtensionWebSocketCreationStatus} creation status
     */
    ExtensionWebSocketCreationStatus status();

    /**
     * The created WebSocket.
     *
     * @return the created {@link ExtensionWebSocket}
     */
    Optional<ExtensionWebSocket> webSocket();

    /**
     * The HTTP response from the WebSocket creation attempt.
     *
     * @return the {@link HttpResponse}
     */
    Optional<HttpResponse> upgradeResponse();
}
