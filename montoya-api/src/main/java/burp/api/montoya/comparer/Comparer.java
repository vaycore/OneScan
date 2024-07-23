/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.comparer;

import burp.api.montoya.core.ByteArray;

/**
 * Provides access to the functionality of the Comparer tool.
 */
public interface Comparer
{
    /**
     * Send data to the Comparer tool.
     *
     * @param data The data to be sent to Comparer.
     */
    void sendToComparer(ByteArray... data);
}
