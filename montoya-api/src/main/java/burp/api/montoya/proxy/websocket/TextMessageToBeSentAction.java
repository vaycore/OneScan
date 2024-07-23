/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.proxy.MessageToBeSentAction;
import burp.api.montoya.websocket.TextMessage;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;


/**
 * Extensions can implement this interface when returning a text message from
 * {@link ProxyMessageHandler#handleTextMessageToBeSent(InterceptedTextMessage)}.
 */
public interface TextMessageToBeSentAction
{
    /**
     * @return The action associated with this message.
     */
    MessageToBeSentAction action();

    /**
     * @return The payload of this message.
     */
    String payload();

    /**
     * Build a text WebSocket message to continue through Burp.
     *
     * @param payload The text message payload.
     *
     * @return The message.
     */
    static TextMessageToBeSentAction continueWith(String payload)
    {
        return FACTORY.continueWithFinalProxyTextMessage(payload);
    }

    /**
     * Build a text WebSocket message to continue through Burp.
     *
     * @param message The text message.
     *
     * @return The message.
     */
    static TextMessageToBeSentAction continueWith(TextMessage message)
    {
        return FACTORY.continueWithFinalProxyTextMessage(message.payload());
    }

    /**
     * Build a text WebSocket message to be dropped.
     *
     * @return The message to be dropped.
     */
    static TextMessageToBeSentAction drop()
    {
        return FACTORY.dropFinalProxyTextMessage();
    }
}
