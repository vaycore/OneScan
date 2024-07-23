/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

import burp.api.montoya.core.ByteArray;

/**
 * Contains information about the payload
 */
public interface PayloadData
{
    /**
     * @return The value of the payload to be processed.
     */
    ByteArray currentPayload();

    /**
     * @return The value of the original payload prior to processing by any already-applied processing rules
     */
    ByteArray originalPayload();

    /**
     * @return The insertion point data.
     */
    IntruderInsertionPoint insertionPoint();
}
