/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.sitemap;

/**
 * This interface is used to represent items in the Burp's site map.
 */
public interface SiteMapNode
{
    /**
     * Retrieve the URL associated with the site map's node.
     *
     * @return The URL of the node.
     */
    String url();
}
