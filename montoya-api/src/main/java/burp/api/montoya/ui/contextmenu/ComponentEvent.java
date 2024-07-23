/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

import java.awt.event.InputEvent;

/**
 * This interface describes an action or event that has occurred with a user interface component.
 */
public interface ComponentEvent
{
    /**
     * This method can be used to retrieve the native Java input event that was
     * the trigger for the context menu invocation.
     *
     * @return The {@link InputEvent} that was the trigger for the context menu invocation.
     */
    InputEvent inputEvent();
}
