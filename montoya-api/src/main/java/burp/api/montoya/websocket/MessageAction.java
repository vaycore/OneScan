/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

/**
 * This enum represents the action to be applied to a {@link TextMessageAction} or {@link BinaryMessageAction}.
 */
public enum MessageAction
{
    /**
     * Causes Burp to forward the message.
     */
    CONTINUE,

    /**
     * Causes Burp to drop the message.
     */
    DROP
}
