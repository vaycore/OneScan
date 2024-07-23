/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

/**
 * Crawl in the Burp Scanner tool.
 */
public interface Crawl extends ScanTask
{
    /**
     * Number of requests that have been made for the
     * scan task.
     *
     * @return The number of requests that have been made for the scan task.
     */
    @Override
    int requestCount();

    /**
     * Number of network errors that have occurred for
     * the scan task.
     *
     * @return The number of network errors that have occurred for the scan
     * task.
     */
    @Override
    int errorCount();

    /**
     * Delete the task.
     */
    @Override
    void delete();

    /**
     * This functionality is not yet implemented.
     *
     * @return the current status message of the task
     */
    @Override
    String statusMessage();
}
