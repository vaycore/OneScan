/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

/**
 * This interface gives you access to String manipulation features.
 */
public interface StringUtils
{
    /**
     * Convert a string to the hex values of its ASCII characters.
     * Each character will be converted to a two digit hex value.
     *
     * @param data The ASCII data to convert.
     *
     * @return The string of hex values.
     */
    String convertAsciiToHexString(String data);

    /**
     * Convert a string of hex values to a string of ASCII characters.
     * Each pair of hex digits will be converted to a single ASCII character.
     *
     * @param data The string of hex values to convert.
     *
     * @return The string of ASCII characters.
     */
    String convertHexStringToAscii(String data);
}
