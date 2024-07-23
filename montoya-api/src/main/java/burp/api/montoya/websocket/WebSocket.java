/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;

/**
 * WebSocket within Burp.
 */
public interface WebSocket
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
     * Register a handler which will perform an action when a message is sent to or received from the application.
     *
     * @param handler An object created by the extension that implements {@link MessageHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerMessageHandler(MessageHandler handler);
}
