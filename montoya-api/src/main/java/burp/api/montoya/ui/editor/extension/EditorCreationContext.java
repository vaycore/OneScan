/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.editor.extension;

import burp.api.montoya.core.ToolSource;

/**
 * This interface is used by an
 * <code>ExtensionHttpRequestEditor</code> or <code>ExtensionHttpResponseEditor</code> to obtain
 * details about the currently displayed message.
 * Extensions that create instances of Burp's HTTP message editor can
 * optionally provide an implementation of
 * <code>IMessageEditorController</code>, which the editor will invoke when it
 * requires further information about the current message (for example, to send
 * it to another Burp tool). Extensions that provide custom editor tabs via an
 * <code>IMessageEditorTabFactory</code> will receive a reference to an
 * <code>IMessageEditorController</code> object for each tab instance they
 * generate, which the tab can invoke if it requires further information about
 * the current message.
 */
public interface EditorCreationContext
{
    /**
     * Indicates which Burp tool is requesting the editor.
     *
     * @return The tool requesting an editor
     */
    ToolSource toolSource();

    /**
     * Indicates which modes the Burp tool requests of the editor.
     * e.g. Proxy expects a read only editor, Repeater expects the default editor.
     *
     * @return The mode required by the editor.
     */
    EditorMode editorMode();
}