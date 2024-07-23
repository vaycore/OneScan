/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.sitemap;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This interface is used to filter items when querying Burp's site map.
 */
public interface SiteMapFilter
{
    /**
     * Invoked by Burp to check whether a given site map node matches the filter.
     *
     * @param node Site map node to match.
     *
     * @return Returns true if the site map node matches the filter.
     */
    boolean matches(SiteMapNode node);

    /**
     * This method returns a site map filter object that matches site map nodes with URLs
     * starting with the specified prefix. Note that the prefix is case-sensitive.
     *
     * @param prefix Case-sensitive URL prefix used to match site tree nodes. If {@code null} is
     *               passed, the resulting filter will match all site map nodes.
     *
     * @return A site map filter object that matches nodes via a URL prefix
     */
    static SiteMapFilter prefixFilter(String prefix)
    {
        return FACTORY.prefixFilter(prefix);
    }
}
