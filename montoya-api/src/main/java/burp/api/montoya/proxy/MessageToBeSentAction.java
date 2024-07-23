/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy;

/**
 * This enum represents the final action to be taken when intercepting HTTP and WebSocket
 * messages in the Proxy.
 */
public enum MessageToBeSentAction
{
    /**
     * Causes Burp Proxy to forward the message.
     */
    CONTINUE,

    /**
     * Causes Burp Proxy to drop the message.
     */
    DROP
}
