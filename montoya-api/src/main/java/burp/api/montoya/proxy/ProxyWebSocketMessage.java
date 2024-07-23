/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.websocket.Direction;

import java.time.ZonedDateTime;
import java.util.regex.Pattern;

/**
 * WebSocket message intercepted by the Proxy.
 */
public interface ProxyWebSocketMessage extends WebSocketMessage
{
    /**
     * This method retrieves the annotations for the message.
     *
     * @return The {@link Annotations} for the message.
     */
    @Override
    Annotations annotations();

    /**
     * @return The direction of the message.
     */
    @Override
    Direction direction();

    /**
     * @return WebSocket payload.
     */
    @Override
    ByteArray payload();

    /**
     * @return The {@link HttpRequest} used to create the WebSocket.
     */
    @Override
    HttpRequest upgradeRequest();

    /**
     * @return The ID for the web socket connection that this message is linked to.
     */
    int webSocketId();

    /**
     * @return An instance of {@link ZonedDateTime} indicating when the message was sent.
     */
    ZonedDateTime time();

    /**
     * @return The payload after modification from tools and extensions. {@code null} if the message has not been edited.
     */
    ByteArray editedPayload();

    /**
     * Returns the proxy listener port used for the web socket message.
     *
     * @return the port number used by the proxy listener
     */
    int listenerPort();

    /**
     * Searches the data in the web socket message for the specified search term.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return True if the search term is found.
     */
    boolean contains(String searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the web socket message for the specified regular expression.
     *
     * @param pattern The regular expression to be searched for.
     *
     * @return True if the pattern is matched.
     */
    boolean contains(Pattern pattern);
}