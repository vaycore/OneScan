/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

/**
 * Returned when an object is registered by an extension in Burp Suite.
 */
public interface Registration
{
    /**
     * Determines whether the object registered by the extension is currently registered.
     *
     * @return Returns {@code true} if the object is registered.
     */
    boolean isRegistered();

    /**
     * Remove the object registered by the extension.
     */
    void deregister();
}
