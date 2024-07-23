/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Registration;
import burp.api.montoya.websocket.Direction;

/**
 * ProxyWebSocket within Burp.
 */
public interface ProxyWebSocket
{
    /**
     * This method allows an extension to send a text message via the WebSocket to either the client or the server.
     *
     * @param textMessage The message to be sent.
     * @param direction   The direction of the message.
     */
    void sendTextMessage(String textMessage, Direction direction);

    /**
     * This method allows an extension to send a binary message via the WebSocket to either the client or the server.
     *
     * @param binaryMessage The message to be sent.
     * @param direction   The direction of the message.
     */
    void sendBinaryMessage(ByteArray binaryMessage, Direction direction);

    /**
     * This method will close the WebSocket.
     */
    void close();

    /**
     * Register a handler which will perform actions when messages are sent or received by the WebSocket.
     *
     * @param handler An object created by the extension that implements {@link ProxyMessageHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerProxyMessageHandler(ProxyMessageHandler handler);
}
