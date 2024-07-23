/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.proxy;

/**
 * Extensions can implement this interface and then call
 * {@link Proxy#history(ProxyHistoryFilter)} to get a filtered list of items in
 * the Proxy history.
 */
public interface ProxyHistoryFilter
{
    /**
     * This method is invoked for every item in the Proxy history to determine
     * whether it should be included in the filtered list of items.
     *
     * @param requestResponse A {@link ProxyHttpRequestResponse} object that
     *                        extensions can use to determine whether the item should be included in
     *                        the filtered list of items.
     *
     * @return Return {@code true} if the item should be included in the
     * filtered list of items.
     */
    boolean matches(ProxyHttpRequestResponse requestResponse);
}
