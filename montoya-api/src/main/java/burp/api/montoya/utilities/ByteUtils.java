/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

import java.util.regex.Pattern;

/**
 * This interface gives you access to various methods for querying and manipulating byte arrays.
 */
public interface ByteUtils
{
    /**
     * This method searches a piece of data for the first occurrence of a specified pattern.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param data       The data to be searched.
     * @param searchTerm The value to be searched for.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(byte[] data, byte[] searchTerm);

    /**
     * This method searches a piece of data for the first occurrence of a specified pattern.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param data          The data to be searched.
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(byte[] data, byte[] searchTerm, boolean caseSensitive);

    /**
     * This method searches a piece of data for the first occurrence of a specified pattern.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param data          The data to be searched.
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     * @param from          The offset within data where the search should begin.
     * @param to            The offset within data where the search should end.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(byte[] data, byte[] searchTerm, boolean caseSensitive, int from, int to);

    /**
     * This method searches a piece of data for the first occurrence of a specified pattern.
     *
     * @param data    The data to be searched.
     * @param pattern The pattern to be matched.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(byte[] data, Pattern pattern);

    /**
     * This method searches a piece of data for the first occurrence of a specified pattern.
     *
     * @param data    The data to be searched.
     * @param pattern The pattern to be matched.
     * @param from    The offset within data where the search should begin.
     * @param to      The offset within data where the search should end.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(byte[] data, Pattern pattern, int from, int to);

    /**
     * This method searches a piece of data and counts all matches for a specified pattern.
     *
     * @param data       The data to be searched.
     * @param searchTerm The value to be searched for.
     *
     * @return The count of all matches of the pattern.
     */
    int countMatches(byte[] data, byte[] searchTerm);

    /**
     * This method searches a piece of data and counts all matches for a specified pattern.
     *
     * @param data          The data to be searched.
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return The count of all matches of the pattern.
     */
    int countMatches(byte[] data, byte[] searchTerm, boolean caseSensitive);

    /**
     * This method searches a piece of data and counts all matches for a specified pattern.
     *
     * @param data          The data to be searched.
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     * @param from          The offset within data where the search should begin.
     * @param to            The offset within data where the search should end.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(byte[] data, byte[] searchTerm, boolean caseSensitive, int from, int to);

    /**
     * This method searches a piece of data and counts all matches for a specified pattern.
     *
     * @param data    The data to be searched.
     * @param pattern The pattern to be matched.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(byte[] data, Pattern pattern);

    /**
     * This method searches a piece of data and counts all matches for a specified pattern.
     *
     * @param data    The data to be searched.
     * @param pattern The pattern to be matched.
     * @param from    The offset within data where the search should begin.
     * @param to      The offset within data where the search should end.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(byte[] data, Pattern pattern, int from, int to);

    /**
     * This method can be used to convert data from an array of bytes into String form. The conversion does not reflect any particular character set, and a byte with the
     * representation 0xYZ will always be converted into a character with the hex representation 0x00YZ. It performs the opposite conversion to the method {@link ByteUtils#convertFromString(String)},
     * and byte-based data that is converted to a String and back again using these two methods is guaranteed to retain its integrity (which may not be the case with
     * conversions that reflect a given character set).
     *
     * @param bytes The data to be converted.
     *
     * @return The converted data.
     */
    String convertToString(byte[] bytes);

    /**
     * This method can be used to convert data from String form into an array of bytes. The conversion does not reflect any particular character set, and a character with
     * the hex representation 0xWXYZ will always be converted into a byte with the representation 0xYZ. It performs the opposite conversion to the method {@link ByteUtils#convertToString(byte[])},
     * and byte-based data that is converted to a String and back again using these two methods is guaranteed to retain its integrity (which may not be the case with
     * conversions that reflect a given character set).
     *
     * @param string The data to be converted
     *
     * @return The converted data.
     */
    byte[] convertFromString(String string);
}
