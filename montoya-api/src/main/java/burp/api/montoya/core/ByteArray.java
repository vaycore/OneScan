/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.core;


import java.util.regex.Pattern;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Burp ByteArray with various methods for querying and manipulating byte arrays.
 */
public interface ByteArray extends Iterable<Byte>
{
    /**
     * Access the byte stored at the provided index.
     *
     * @param index Index of the byte to be retrieved.
     *
     * @return The byte at the index.
     */
    byte getByte(int index);

    /**
     * Sets the byte at the provided index to the provided byte.
     *
     * @param index Index of the byte to be set.
     * @param value The byte to be set.
     */
    void setByte(int index, byte value);

    /**
     * Sets the byte at the provided index to the provided narrowed integer value.
     *
     * @param index Index of the byte to be set.
     * @param value The integer value to be set after a narrowing primitive conversion to a byte.
     */
    void setByte(int index, int value);

    /**
     * Sets bytes starting at the specified index to the provided bytes.
     *
     * @param index The index of the first byte to set.
     * @param data  The byte[] or sequence of bytes to be set.
     */
    void setBytes(int index, byte... data);

    /**
     * Sets bytes starting at the specified index to the provided integers after narrowing primitive conversion to bytes.
     *
     * @param index The index of the first byte to set.
     * @param data  The int[] or the sequence of integers to be set after a narrowing primitive conversion to bytes.
     */
    void setBytes(int index, int... data);

    /**
     * Sets bytes starting at the specified index to the provided bytes.
     *
     * @param index     The index of the first byte to set.
     * @param byteArray The {@code ByteArray} object holding the provided bytes.
     */
    void setBytes(int index, ByteArray byteArray);

    /**
     * Number of bytes stored in the {@code ByteArray}.
     *
     * @return Length of the {@code ByteArray}.
     */
    int length();

    /**
     * Copy of all bytes
     *
     * @return Copy of all bytes.
     */
    byte[] getBytes();

    /**
     * New ByteArray with all bytes between the start index (inclusive) and the end index (exclusive).
     *
     * @param startIndexInclusive The inclusive start index of retrieved range.
     * @param endIndexExclusive   The exclusive end index of retrieved range.
     *
     * @return ByteArray containing all bytes in the specified range.
     */
    ByteArray subArray(int startIndexInclusive, int endIndexExclusive);

    /**
     * New ByteArray with all bytes in the specified range.
     *
     * @param range The {@link Range} of bytes to be returned.
     *
     * @return ByteArray containing all bytes in the specified range.
     */
    ByteArray subArray(Range range);

    /**
     * Create a copy of the {@code ByteArray}
     *
     * @return New {@code ByteArray} with a copy of the wrapped bytes.
     */
    ByteArray copy();

    /**
     * Create a copy of the {@code ByteArray} in temporary file.<br>
     * This method is used to save the {@code ByteArray} object to a temporary file,
     * so that it is no longer held in memory. Extensions can use this method to convert
     * {@code ByteArray} objects into a form suitable for long-term usage.
     *
     * @return A new {@code ByteArray} instance stored in temporary file.
     */
    ByteArray copyToTempFile();

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified term.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param searchTerm The value to be searched for.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(ByteArray searchTerm);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified term.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param searchTerm The value to be searched for.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(String searchTerm);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified term.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(ByteArray searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified term.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(String searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified term.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param searchTerm          The value to be searched for.
     * @param caseSensitive       Flags whether the search is case-sensitive.
     * @param startIndexInclusive The inclusive start index for the search.
     * @param endIndexExclusive   The exclusive end index for the search.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(ByteArray searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified term.
     * It works on byte-based data in a way that is similar to the way the native Java method {@link String#indexOf(String)} works on String-based data.
     *
     * @param searchTerm          The value to be searched for.
     * @param caseSensitive       Flags whether the search is case-sensitive.
     * @param startIndexInclusive The inclusive start index for the search.
     * @param endIndexExclusive   The exclusive end index for the search.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(String searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified pattern.
     *
     * @param pattern The pattern to be matched.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(Pattern pattern);

    /**
     * Searches the data in the ByteArray for the first occurrence of a specified pattern.
     *
     * @param pattern             The pattern to be matched.
     * @param startIndexInclusive The inclusive start index for the search.
     * @param endIndexExclusive   The exclusive end index for the search.
     *
     * @return The offset of the first occurrence of the pattern within the specified bounds, or -1 if no match is found.
     */
    int indexOf(Pattern pattern, int startIndexInclusive, int endIndexExclusive);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified term.
     *
     * @param searchTerm The value to be searched for.
     *
     * @return The count of all matches of the pattern.
     */
    int countMatches(ByteArray searchTerm);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified term.
     *
     * @param searchTerm The value to be searched for.
     *
     * @return The count of all matches of the pattern.
     */
    int countMatches(String searchTerm);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified term.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return The count of all matches of the pattern.
     */
    int countMatches(ByteArray searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified term.
     *
     * @param searchTerm    The value to be searched for.
     * @param caseSensitive Flags whether the search is case-sensitive.
     *
     * @return The count of all matches of the pattern.
     */
    int countMatches(String searchTerm, boolean caseSensitive);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified term.
     *
     * @param searchTerm          The value to be searched for.
     * @param caseSensitive       Flags whether the search is case-sensitive.
     * @param startIndexInclusive The inclusive start index for the search.
     * @param endIndexExclusive   The exclusive end index for the search.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(ByteArray searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified term.
     *
     * @param searchTerm          The value to be searched for.
     * @param caseSensitive       Flags whether the search is case-sensitive.
     * @param startIndexInclusive The inclusive start index for the search.
     * @param endIndexExclusive   The exclusive end index for the search.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(String searchTerm, boolean caseSensitive, int startIndexInclusive, int endIndexExclusive);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified pattern.
     *
     * @param pattern The pattern to be matched.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(Pattern pattern);

    /**
     * Searches the data in the ByteArray and counts all matches for a specified pattern.
     *
     * @param pattern             The pattern to be matched.
     * @param startIndexInclusive The inclusive start index for the search.
     * @param endIndexExclusive   The exclusive end index for the search.
     *
     * @return The count of all matches of the pattern within the specified bounds.
     */
    int countMatches(Pattern pattern, int startIndexInclusive, int endIndexExclusive);

    /**
     * Convert the bytes of the ByteArray into String form using the encoding specified by Burp Suite.
     *
     * @return The converted data in String form.
     */
    @Override
    String toString();

    /**
     * Create a copy of the {@code ByteArray} appended with the provided bytes.
     *
     * @param data The byte[] or sequence of bytes to append.
     */
    ByteArray withAppended(byte... data);

    /**
     * Create a copy of the {@code ByteArray} appended with the provided integers after narrowing primitive conversion to bytes.
     *
     * @param data The int[] or sequence of integers to append after narrowing primitive conversion to bytes.
     */
    ByteArray withAppended(int... data);

    /**
     * Create a copy of the {@code ByteArray} appended with the provided text as bytes.
     *
     * @param text The string to append.
     */
    ByteArray withAppended(String text);

    /**
     * Create a copy of the {@code ByteArray} appended with the provided ByteArray.
     *
     * @param byteArray The ByteArray to append.
     */
    ByteArray withAppended(ByteArray byteArray);

    /**
     * Create a new {@code ByteArray} with the provided length.<br>
     *
     * @param length array length.
     *
     * @return New {@code ByteArray} with the provided length.
     */
    static ByteArray byteArrayOfLength(int length)
    {
        return FACTORY.byteArrayOfLength(length);
    }

    /**
     * Create a new {@code ByteArray} with the provided byte data.<br>
     *
     * @param data byte[] to wrap, or sequence of bytes to wrap.
     *
     * @return New {@code ByteArray} wrapping the provided byte array.
     */
    static ByteArray byteArray(byte... data)
    {
        return FACTORY.byteArray(data);
    }

    /**
     * Create a new {@code ByteArray} with the provided integers after a narrowing primitive conversion to bytes.<br>
     *
     * @param data int[] to wrap or sequence of integers to wrap.
     *
     * @return New {@code ByteArray} wrapping the provided data after a narrowing primitive conversion to bytes.
     */
    static ByteArray byteArray(int... data)
    {
        return FACTORY.byteArray(data);
    }

    /**
     * Create a new {@code ByteArray} from the provided text using the encoding specified by Burp Suite.<br>
     *
     * @param text the text for the byte array.
     *
     * @return New {@code ByteArray} holding a copy of the text as bytes.
     */
    static ByteArray byteArray(String text)
    {
        return FACTORY.byteArray(text);
    }
}

