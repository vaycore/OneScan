/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;

/**
 * Task on the Dashboard.
 */
public interface Task
{
    /**
     * Delete the task.
     */
    void delete();

    /**
     * @return the current status message of the task
     */
    String statusMessage();
}
