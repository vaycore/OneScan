package burp.api.montoya.ui.editor.extension;

/**
 * Extensions can register an instance of this interface to provide custom Web Socket message editors within Burp's user interface.
 */
public interface WebSocketMessageEditorProvider
{
    /**
     * Invoked by Burp when a new Web Socket message editor is required from the extension.
     *
     * @param creationContext details about the context that is requiring a message editor
     *
     * @return An instance of {@link ExtensionProvidedWebSocketMessageEditor}
     */
    ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext creationContext);
}
