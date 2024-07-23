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
 * Intruder insertion point for attack payloads.
 */
public interface IntruderInsertionPoint
{
    /**
     * @return The base value of the insertion point.
     */
    ByteArray baseValue();
}
