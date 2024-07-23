/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.websocket;

/**
 * This enum is used to indicate the direction of the WebSocket message.
 */
public enum Direction
{
    CLIENT_TO_SERVER,
    SERVER_TO_CLIENT
}
