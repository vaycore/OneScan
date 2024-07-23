/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.core.ToolSource;

import java.util.Optional;

public interface WebSocketEditorEvent extends ComponentEvent, ToolSource
{
    /**
     * @return The contents of the message editor.
     */
    ByteArray getContents();

    /**
     * This method can be used to set the content within the message editor programmatically.
     * If the editor is read only the contents will not be updated.
     *
     * @param contents The content to set in the message editor.
     */
    void setContents(ByteArray contents);

    /**
     * @return the WebSocket message used to populate the editor.
     */
    WebSocketMessage webSocketMessage();

    /**
     * @return if the editor is read only.
     */
    boolean isReadOnly();

    /**
     * This will return {@link Optional#empty()} if the user has not made a selection.
     *
     * @return An {@link Optional} range of indices that indicates the position of the users current selection.
     */
    Optional<Range> selectionOffsets();

    /**
     * @return The index of the position for the carat within the current message editor.
     */
    int caretPosition();
}
