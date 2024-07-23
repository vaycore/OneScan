/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.ui.contextmenu;

/**
 * Provides information about the source from which a context menu was invoked.
 */
public interface InvocationSource
{
    /**
     * @return An instance of {@link InvocationType} which provides the current location of the context menu being invoked.
     */
    InvocationType invocationType();

    /**
     * A helper method to allow the extension to ask if the context is within a set of locations.
     *
     * @param invocationType One or more instances of {@link InvocationType} to check.
     *
     * @return True if the context menu is being invoked from one of the types that is being checked.
     */
    boolean isFrom(InvocationType... invocationType);
}
