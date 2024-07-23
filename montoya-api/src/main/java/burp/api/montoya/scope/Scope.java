/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scope;

import burp.api.montoya.core.Registration;

/**
 * Provides access to the functionality related to Burp's
 * Suite-wide target scope.
 */
public interface Scope
{
    /**
     * This method can be used to query whether a specified URL is within the
     * current Suite-wide target scope.
     *
     * @param url The URL to query.
     *
     * @return Returns {@code true} if the URL is within the current Suite-wide
     * target scope.
     */
    boolean isInScope(String url);

    /**
     * This method can be used to include the specified URL in the Suite-wide
     * target scope.
     *
     * @param url The URL to include in the Suite-wide target scope.
     */
    void includeInScope(String url);

    /**
     * This method can be used to exclude the specified URL from the Suite-wide
     * target scope.
     *
     * @param url The URL to exclude from the Suite-wide target scope.
     */
    void excludeFromScope(String url);

    /**
     * Register a handler which will be notified of
     * changes to Burp's Suite-wide target scope.
     *
     * @param handler An object created by the extension that implements the
     *                {@link ScopeChangeHandler} interface.
     *
     * @return The {@link Registration} for the handler.
     */
    Registration registerScopeChangeHandler(ScopeChangeHandler handler);
}
