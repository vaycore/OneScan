/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket.extension;

import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.TextMessage;

/**
 * This interface allows an extension to be notified when messages are received or the WebSocket has been closed.
 */
public interface ExtensionWebSocketMessageHandler
{
    /**
     * Invoked when a text message is received from the application.
     *
     * @param textMessage text WebSocket message.
     */
    void textMessageReceived(TextMessage textMessage);

    /**
     * Invoked when a binary message is received from the application.
     *
     * @param binaryMessage binary WebSocket message.
     */
    void binaryMessageReceived(BinaryMessage binaryMessage);

    /**
     * Invoked when the WebSocket is closed.
     */
    default void onClose()
    {
    }
}
