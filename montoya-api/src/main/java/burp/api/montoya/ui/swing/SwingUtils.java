/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.swing;

import burp.api.montoya.core.HighlightColor;

import java.awt.*;

/**
 * This interface gives you access to swing utilities.
 */
public interface SwingUtils
{
    /**
     * @return the main Burp suite frame.
     */
    Frame suiteFrame();

    /**
     * Retrieve the top-level {@code Window} containing the supplied component.
     *
     * @param component the component.
     *
     * @return the top-level {@code Window} containing the component.
     */
    Window windowForComponent(Component component);

    /**
     * Convert a highlight color to a java color.
     *
     * @param highlightColor the {@link HighlightColor}
     *
     * @return the java color for the highlight color.
     */
    Color colorForHighLight(HighlightColor highlightColor);
}
