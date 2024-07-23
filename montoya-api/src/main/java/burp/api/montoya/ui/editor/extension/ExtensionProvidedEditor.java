/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.editor.extension;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.Selection;

import java.awt.*;

/**
 * Provides the shared behaviour between the different extension provided editor types.
 */
public interface ExtensionProvidedEditor
{
    /**
     * Sets the provided {@link HttpRequestResponse} object within the editor component.
     *
     * @param requestResponse The request and response to set in the editor.
     */
    void setRequestResponse(HttpRequestResponse requestResponse);

    /**
     * A check to determine if the HTTP message editor is enabled for a specific {@link HttpRequestResponse}
     *
     * @param requestResponse The {@link HttpRequestResponse} to check.
     *
     * @return True if the HTTP message editor is enabled for the provided request and response.
     */
    boolean isEnabledFor(HttpRequestResponse requestResponse);

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
