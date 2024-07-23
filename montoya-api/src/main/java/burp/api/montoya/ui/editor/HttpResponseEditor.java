/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.editor;

import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;

import java.awt.*;
import java.util.Optional;

/**
 * Provides extensions with an instance of Burp Suites HTTP response editor to use in their own user interface.
 */
public interface HttpResponseEditor extends Editor
{
    /**
     * @return an instance of {@link HttpResponse} derived from the contents of the editor.
     */
    HttpResponse getResponse();

    /**
     * Display the contents of an HTTP response in the editor.
     *
     * @param response The HTTP response to be set.
     */
    void setResponse(HttpResponse response);

    /**
     * Update the search expression that is shown in the search bar below the editor.
     *
     * @param expression The search expression.
     */
    @Override
    void setSearchExpression(String expression);

    /**
     * @return True if the user has modified the contents of the editor since the last time the content was set programmatically.
     */
    @Override
    boolean isModified();

    /**
     * @return The index of the position for the carat within the current message editor.
     */
    @Override
    int caretPosition();

    /**
     * This will return {@link Optional#empty()} if the user has not made a selection.
     *
     * @return An {@link Optional} containing the users current selection in the editor.
     */
    @Override
    Optional<Selection> selection();

    /**
     * @return UI component of the editor, for extensions to add to their own UI.
     */
    @Override
    Component uiComponent();
}
