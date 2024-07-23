/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

import java.awt.*;
import java.util.List;

import static java.util.Collections.emptyList;

/**
 * This interface allows extensions to implement and register a provider for custom context menu items.
 */
public interface ContextMenuItemsProvider
{
    /**
     * Invoked by Burp Suite when the user requests a context menu with HTTP request/response information in the user interface.
     * Extensions should return {@code null} or {@link java.util.Collections#emptyList()} from this method, to indicate that no menu items are required.
     *
     * @param event This object can be queried to find out about HTTP request/responses that are associated with the context menu invocation.
     *
     * @return A list of custom menu items (which may include sub-menus, checkbox menu items, etc.) that should be displayed.
     */
    default List<Component> provideMenuItems(ContextMenuEvent event)
    {
        return emptyList();
    }

    /**
     * Invoked by Burp Suite when the user requests a context menu with WebSocket information in the user interface.
     * Extensions should return {@code null} or {@link java.util.Collections#emptyList()} from this method, to indicate that no menu items are required.
     *
     * @param event This object can be queried to find out about WebSocket messages that are associated with the context menu invocation.
     *
     * @return A list of custom menu items (which may include sub-menus, checkbox menu items, etc.) that should be displayed.
     */
    default List<Component> provideMenuItems(WebSocketContextMenuEvent event)
    {
        return emptyList();
    }

    /**
     * Invoked by Burp Suite when the user requests a context menu with audit issue information in the user interface.
     * Extensions should return {@code null} or {@link java.util.Collections#emptyList()} from this method, to indicate that no menu items are required.
     *
     * @param event This object can be queried to find out about audit issues that are associated with the context menu invocation.
     *
     * @return A list of custom menu items (which may include sub-menus, checkbox menu items, etc.) that should be displayed.
     */
    default List<Component> provideMenuItems(AuditIssueContextMenuEvent event)
    {
        return emptyList();
    }
}
