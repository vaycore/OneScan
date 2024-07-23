/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.editor.extension;

/**
 * Extensions can register an instance of this interface to provide custom HTTP response editors within Burp's user interface.
 */
public interface HttpResponseEditorProvider
{
    /**
     * Invoked by Burp when a new HTTP response editor is required from the extension.
     *
     * @param creationContext details about the context that is requiring a response editor
     *
     * @return An instance of {@link ExtensionProvidedHttpResponseEditor}
     */
    ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext);
}
