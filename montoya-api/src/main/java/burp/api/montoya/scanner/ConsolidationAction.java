/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.scanner;

/**
 * This enum represents the action to be taken when duplicate audit issues are
 * found.
 */
public enum ConsolidationAction
{
    KEEP_EXISTING,
    KEEP_BOTH,
    KEEP_NEW
}
