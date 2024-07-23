/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.editor.extension;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;

import java.awt.*;

/**
 * Extensions that register an {@link HttpResponseEditorProvider} must return an instance of this interface.<br/>
 * Burp will then use that instance to create custom tabs within its HTTP response editor.
 */
public interface ExtensionProvidedHttpResponseEditor extends ExtensionProvidedEditor
{
    /**
     * @return An instance of {@link HttpResponse} derived from the content of the HTTP response editor.
     */
    HttpResponse getResponse();

    /**
     * Sets the provided {@link HttpRequestResponse} object within the editor component.
     *
     * @param requestResponse The request and response to set in the editor.
     */
    @Override
    void setRequestResponse(HttpRequestResponse requestResponse);

    /**
     * A check to determine if the HTTP message editor is enabled for a specific {@link HttpRequestResponse}
     *
     * @param requestResponse The {@link HttpRequestResponse} to check.
     *
     * @return True if the HTTP message editor is enabled for the provided request and response.
     */
    @Override
    boolean isEnabledFor(HttpRequestResponse requestResponse);

    /**
     * @return The caption located in the message editor tab header.
     */
    @Override
    String caption();

    /**
     * @return The component that is rendered within the message editor tab.
     */
    @Override
    Component uiComponent();

    /**
     * The method should return {@code null} if no data has been selected.
     *
     * @return The data that is currently selected by the user.
     */
    @Override
    Selection selectedData();

    /**
     * @return True if the user has modified the current message within the editor.
     */
    @Override
    boolean isModified();
}
