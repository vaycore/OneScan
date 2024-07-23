/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

import burp.api.montoya.core.ToolSource;

import java.util.List;
import java.util.Optional;

public interface WebSocketContextMenuEvent extends ComponentEvent, ToolSource
{
    /**
     * This method can be used to retrieve details of the currently selected WebSocket message when the context menu was invoked from an editor.
     *
     * @return an {@link Optional} describing the currently selected WebSocket message with selection metadata.
     */
    Optional<WebSocketEditorEvent> messageEditorWebSocket();

    /**
     * This method can be used to retrieve details of the currently selected WebSocket messages that are
     * selected by the user when the context menu was invoked. This will return an empty list if the user has not made a selection.
     *
     * @return A list of WebSocket messages that have been selected by the user.
     */
    List<WebSocketMessage> selectedWebSocketMessages();
}
