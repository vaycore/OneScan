/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

/**
 * This enum defines HTML encodings.
 */
public enum HtmlEncoding
{
    /**
     * Encode only HTML special characters.
     */
    STANDARD,

    /**
     * Encode HTML special characters as per STANDARD,
     * encode all other characters as decimal entities.
     */
    ALL_CHARACTERS,

    /**
     * Encode all characters as decimal entities.
     */
    ALL_CHARACTERS_DECIMAL,

    /**
     * Encode all characters as hex entities.
     */
    ALL_CHARACTERS_HEX
}
