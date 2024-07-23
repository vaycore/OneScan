/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

/**
 * This interface allows an extension to be notified when messages are received or the WebSocket has been closed.
 */
public interface MessageHandler
{
    /**
     * Invoked when a text message is sent or received from the application.
     * This gives the extension the ability to modify the message before it is
     * sent to the application or processed by Burp.
     *
     * @param textMessage Intercepted text based WebSocket message.
     *
     * @return The message.
     */
    TextMessageAction handleTextMessage(TextMessage textMessage);

    /**
     * Invoked when a binary message is sent or received from the application.
     * This gives the extension the ability to modify the message before it is
     * sent to the application or processed by Burp.
     *
     * @param binaryMessage Intercepted binary based WebSocket message.
     *
     * @return The message.
     */
    BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage);

    /**
     * Invoked when the WebSocket is closed.
     */
    default void onClose()
    {
    }
}
