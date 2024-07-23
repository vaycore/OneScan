/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.Direction;

public interface InterceptedBinaryMessage extends BinaryMessage
{
    /**
     * @return The annotations.
     */
    Annotations annotations();

    /**
     * @return Binary based WebSocket payload.
     */
    @Override
    ByteArray payload();

    /**
     * @return The direction of the message.
     */
    @Override
    Direction direction();
}
