/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.proxy.MessageReceivedAction;
import burp.api.montoya.websocket.BinaryMessage;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Extensions can implement this interface when returning a binary message from
 * {@link ProxyMessageHandler#handleBinaryMessageReceived(InterceptedBinaryMessage)}.
 */
public interface BinaryMessageReceivedAction
{
    /**
     * @return The action associated with this message.
     */
    MessageReceivedAction action();

    /**
     * @return The payload of this message.
     */
    ByteArray payload();

    /**
     * Build a binary WebSocket message to
     * follow the current interception rules to determine the appropriate
     * action to take for the message.
     *
     * @param payload The binary message payload.
     *
     * @return The {@link BinaryMessageReceivedAction} that allows user rules to be
     * followed.
     */
    static BinaryMessageReceivedAction continueWith(ByteArray payload)
    {
        return FACTORY.followUserRulesInitialProxyBinaryMessage(payload);
    }

    /**
     * Build a binary WebSocket message to
     * follow the current interception rules to determine the appropriate
     * action to take for the message.
     *
     * @param message The binary message.
     *
     * @return The {@link BinaryMessageReceivedAction} that allows user rules to be
     * followed.
     */
    static BinaryMessageReceivedAction continueWith(BinaryMessage message)
    {
        return FACTORY.followUserRulesInitialProxyBinaryMessage(message.payload());
    }

    /**
     * Build a binary WebSocket message to be intercepted within the Proxy.
     *
     * @param payload The binary message payload.
     *
     * @return The message.
     */
    static BinaryMessageReceivedAction intercept(ByteArray payload)
    {
        return FACTORY.interceptInitialProxyBinaryMessage(payload);
    }

    /**
     * Build a binary WebSocket message to be intercepted within the Proxy.
     *
     * @param message The binary message.
     *
     * @return The message.
     */
    static BinaryMessageReceivedAction intercept(BinaryMessage message)
    {
        return FACTORY.interceptInitialProxyBinaryMessage(message.payload());
    }

    /**
     * Build a binary WebSocket message to continue within the Proxy without interception.
     *
     * @param payload The binary message payload.
     *
     * @return The message.
     */
    static BinaryMessageReceivedAction doNotIntercept(ByteArray payload)
    {
        return FACTORY.doNotInterceptInitialProxyBinaryMessage(payload);
    }

    /**
     * Build a binary WebSocket message to continue within the Proxy without interception.
     *
     * @param message The binary message.
     *
     * @return The message.
     */
    static BinaryMessageReceivedAction doNotIntercept(BinaryMessage message)
    {
        return FACTORY.doNotInterceptInitialProxyBinaryMessage(message.payload());
    }

    /**
     * Build a binary WebSocket message to be dropped.
     *
     * @return The message to be dropped.
     */
    static BinaryMessageReceivedAction drop()
    {
        return FACTORY.dropInitialProxyBinaryMessage();
    }
}
