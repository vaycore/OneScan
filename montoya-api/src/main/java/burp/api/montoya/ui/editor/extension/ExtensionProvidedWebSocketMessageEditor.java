package burp.api.montoya.ui.editor.extension;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;

import java.awt.*;

/**
 * Extensions that register an {@link WebSocketMessageEditorProvider} must return an instance of this interface.<br/>
 * Burp will then use that instance to create custom tabs within its Web Socket message editor.
 */
public interface ExtensionProvidedWebSocketMessageEditor
{
    /**
     * @return The current message set in the editor as an instance of {@link ByteArray}
     */
    ByteArray getMessage();
    
    /**
     * Sets the provided {@link WebSocketMessage} within the editor component.
     *
     * @param message The message to set in the editor.
     */
    void setMessage(WebSocketMessage message);

    /**
     * A check to determine if the Web Socket editor is enabled for a specific {@link WebSocketMessage} message
     *
     * @param message The {@link WebSocketMessage} to check.
     *
     * @return True if the Web Socket message editor is enabled for the provided message.
     */
    boolean isEnabledFor(WebSocketMessage message);

    /**
     * @return The caption located in the message editor tab header.
     */
    String caption();

    /**
     * @return The component that is rendered within the message editor tab.
     */
    Component uiComponent();

    /**
     * The method should return {@code null} if no data has been selected.
     *
     * @return The data that is currently selected by the user.
     */
    Selection selectedData();

    /**
     * @return True if the user has modified the current message within the editor.
     */
    boolean isModified();
}
