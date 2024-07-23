/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.http.sessions;

import burp.api.montoya.http.Http;

/**
 * Extensions can implement this interface and then call {@link Http#registerSessionHandlingAction} to register a custom session handling action. Each registered action will be
 * available within the session handling rule UI for the user to select as a rule action. Users can choose to invoke an action directly in its own right, or following execution of
 * a macro.
 */
public interface SessionHandlingAction
{
    /**
     * @return Action name
     */
    String name();

    /**
     * Invoked when the session handling action should be executed.<br>
     * This may happen as an action in its own right, or as a sub-action following execution of a macro.<br>
     * It can issue additional requests of its own if necessary, and can return a modified base request in the {@link ActionResult}
     *
     * @param actionData {@link SessionHandlingActionData} The action can query this object to obtain details about the base request.
     *
     * @return A new {@link ActionResult} instance.
     */
    ActionResult performAction(SessionHandlingActionData actionData);
}
