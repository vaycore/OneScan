/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

import java.util.List;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * This class represents the configuration required for an crawl in the Burp Scanner Tool.
 */
public interface CrawlConfiguration
{
    /**
     * @return the seed urls for the crawl
     */
    List<String> seedUrls();

    /**
     * Build a crawl configuration with seed urls
     *
     * @param seedUrls used by the crawler
     *
     * @return crawl configuration required by the crawler.
     */
    static CrawlConfiguration crawlConfiguration(String... seedUrls)
    {
        return FACTORY.crawlConfiguration(seedUrls);
    }
}
