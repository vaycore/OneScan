/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

/**
 * Instructions that the payload processor can give Intruder for the current payload.
 */
public enum PayloadProcessingAction
{
    /**
     * Skip the current payload
     */
    SKIP_PAYLOAD,
    /**
     * Use the current payload
     */
    USE_PAYLOAD
}
