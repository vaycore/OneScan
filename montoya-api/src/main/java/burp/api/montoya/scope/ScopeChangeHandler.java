/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scope;

/**
 * Extensions can implement this interface and then call
 * {@link Scope#registerScopeChangeHandler(ScopeChangeHandler)} to register a scope change
 * handler. The handler will be notified whenever a change occurs to Burp's
 * Suite-wide target scope.
 */
public interface ScopeChangeHandler
{
    /**
     * This method is invoked whenever a change occurs to Burp's Suite-wide
     * target scope.
     *
     * @param scopeChange An object representing the change to Burp's
     *                    Suite-wide target scope.
     */
    void scopeChanged(ScopeChange scopeChange);
}
