/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.websocket.TextMessage;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;


/**
 * Extensions can implement this interface when returning a text message from
 * {@link ProxyMessageHandler#handleTextMessageReceived(InterceptedTextMessage)}.
 */
public interface TextMessageReceivedAction
{
    /**
     * @return The action associated with this message.
     */
    MessageReceivedAction action();

    /**
     * @return The payload of this message.
     */
    String payload();

    /**
     * Build a text WebSocket message to
     * follow the current interception rules to determine the appropriate
     * action to take for the message.
     *
     * @param payload The text message payload.
     *
     * @return The {@link TextMessageReceivedAction} that allows user rules to be
     * followed.
     */
    static TextMessageReceivedAction continueWith(String payload)
    {
        return FACTORY.followUserRulesInitialProxyTextMessage(payload);
    }

    /**
     * Build a text WebSocket message to
     * follow the current interception rules to determine the appropriate
     * action to take for the message.
     *
     * @param message The text message.
     *
     * @return The {@link TextMessageReceivedAction} that allows user rules to be
     * followed.
     */
    static TextMessageReceivedAction continueWith(TextMessage message)
    {
        return FACTORY.followUserRulesInitialProxyTextMessage(message.payload());
    }

    /**
     * Build a text WebSocket message to be intercepted within the Proxy.
     *
     * @param payload The text message payload.
     *
     * @return The message.
     */
    static TextMessageReceivedAction intercept(String payload)
    {
        return FACTORY.interceptInitialProxyTextMessage(payload);
    }

    /**
     * Build a text WebSocket message to be intercepted within the Proxy.
     *
     * @param message The text message.
     *
     * @return The message.
     */
    static TextMessageReceivedAction intercept(TextMessage message)
    {
        return FACTORY.interceptInitialProxyTextMessage(message.payload());
    }

    /**
     * Build a text WebSocket message to continue within the Proxy without interception.
     *
     * @param payload The text message payload.
     *
     * @return The message.
     */
    static TextMessageReceivedAction doNotIntercept(String payload)
    {
        return FACTORY.doNotInterceptInitialProxyTextMessage(payload);
    }

    /**
     * Build a text WebSocket message to continue within the Proxy without interception.
     *
     * @param message The text message payload.
     *
     * @return The message.
     */
    static TextMessageReceivedAction doNotIntercept(TextMessage message)
    {
        return FACTORY.doNotInterceptInitialProxyTextMessage(message.payload());
    }

    /**
     * Build a text WebSocket message to be dropped.
     *
     * @return The message to be dropped.
     */
    static TextMessageReceivedAction drop()
    {
        return FACTORY.dropInitialProxyTextMessage();
    }
}
