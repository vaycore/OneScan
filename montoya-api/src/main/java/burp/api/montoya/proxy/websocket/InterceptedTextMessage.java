/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy.websocket;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.TextMessage;

public interface InterceptedTextMessage extends TextMessage
{
    /**
     * @return The annotations.
     */
    Annotations annotations();

    /**
     * @return Text based WebSocket payload.
     */
    @Override
    String payload();

    /**
     * @return The direction of the message.
     */
    @Override
    Direction direction();
}
