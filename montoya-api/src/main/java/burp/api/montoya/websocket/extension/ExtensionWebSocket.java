/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket.extension;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;

/**
 * A WebSocket created via the Extension API.
 */
public interface ExtensionWebSocket
{
    /**
     * This method allows an extension to send a text message via the WebSocket.
     *
     * @param message The message to be sent.
     */
    void sendTextMessage(String message);

    /**
     * This method allows an extension to send a binary message via the WebSocket.
     *
     * @param message The message to be sent.
     */
    void sendBinaryMessage(ByteArray message);

    /**
     * This method will close the WebSocket.
     */
    void close();

    /**
     * Register an interface that is notified when messages arrive from the server.
     *
     * @param handler An object created by the extension that implements {@link ExtensionWebSocketMessageHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerMessageHandler(ExtensionWebSocketMessageHandler handler);
}
