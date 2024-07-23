/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

import burp.api.montoya.core.ByteArray;

/**
 * This interface gives you access to number string conversion features.
 */
public interface NumberUtils
{
    /**
     * @param binaryString the binary string to convert
     *
     * @return string containing the octal representation
     */
    String convertBinaryToOctal(String binaryString);

    /**
     * @param byteArray the byte array to convert
     *
     * @return string containing the octal representation
     */
    String convertBinaryToOctal(ByteArray byteArray);

    /**
     * @param binaryString the binary string to convert
     *
     * @return string containing the decimal representation
     */
    String convertBinaryToDecimal(String binaryString);

    /**
     * @param byteArray the byte array to convert
     *
     * @return string containing the decimal representation
     */
    String convertBinaryToDecimal(ByteArray byteArray);

    /**
     * @param binaryString the binary string to convert
     *
     * @return string containing the hex representation
     */
    String convertBinaryToHex(String binaryString);

    /**
     * @param byteArray the byte array to convert
     *
     * @return string containing the hex representation
     */
    String convertBinaryToHex(ByteArray byteArray);

    /**
     * @param octalString the octal string to convert
     *
     * @return string containing the binary representation
     */
    String convertOctalToBinary(String octalString);

    /**
     * @param octalString the octal string to convert
     *
     * @return string containing the decimal representation
     */
    String convertOctalToDecimal(String octalString);

    /**
     * @param octalString the octal string to convert
     *
     * @return string containing the hex representation
     */
    String convertOctalToHex(String octalString);

    /**
     * @param decimalString the decimal string to convert
     *
     * @return string containing the binary representation
     */
    String convertDecimalToBinary(String decimalString);

    /**
     * @param decimalString the decimal string to convert
     *
     * @return string containing the octal representation
     */
    String convertDecimalToOctal(String decimalString);

    /**
     * @param decimalString the decimal string to convert
     *
     * @return string containing the hex representation
     */
    String convertDecimalToHex(String decimalString);

    /**
     * @param hexString the hex string to convert
     *
     * @return string containing the binary representation
     */
    String convertHexToBinary(String hexString);

    /**
     * @param hexString the hex string to convert
     *
     * @return string containing the octal representation
     */
    String convertHexToOctal(String hexString);

    /**
     * @param hexString the hex string to convert
     *
     * @return string containing the decimal representation
     */
    String convertHexToDecimal(String hexString);

    /**
     * @param binaryString the binary string to convert
     * @param radix        the radix to convert to
     *
     * @return string containing the representation in the specified radix
     */
    String convertBinary(String binaryString, int radix);

    /**
     * @param octalString the octal string to convert
     * @param radix       the radix to convert to
     *
     * @return string containing the representation in the specified radix
     */
    String convertOctal(String octalString, int radix);

    /**
     * @param decimalString the decimal string to convert
     * @param radix         the radix to convert to
     *
     * @return string containing the representation in the specified radix
     */
    String convertDecimal(String decimalString, int radix);

    /**
     * @param hexString the hex string to convert
     * @param radix     the radix to convert to
     *
     * @return string containing the representation in the specified radix
     */
    String convertHex(String hexString, int radix);
}
