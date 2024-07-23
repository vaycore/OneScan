/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

import java.util.Arrays;
import java.util.stream.Collectors;

public interface RandomUtils
{
    /**
     * Generate a random string using alphanumeric characters
     *
     * @param length length of the resulting random string
     *
     * @return randomly generated string
     */
    String randomString(int length);

    /**
     * Generate a random string using the supplied characters
     *
     * @param length length of the resulting random string
     * @param chars  the characters to use to generate the string
     *
     * @return randomly generated string
     */
    String randomString(int length, String chars);

    /**
     * Generate a random string using the supplied {@link CharacterSet}
     *
     * @param length        length of the resulting random string
     * @param characterSets the list {@code CharacterSet} to use to generate the string
     *
     * @return randomly generated string
     */
    String randomString(int length, CharacterSet... characterSets);

    /**
     * Generate a random string using the supplied characters
     *
     * @param minLength the inclusive minimum length of the generated string
     * @param maxLength the inclusive maximum length of the generated string
     * @param chars     the characters to use to generate the string
     *
     * @return randomly generated string
     */
    String randomString(int minLength, int maxLength, String chars);

    /**
     * Generate a random string using the supplied {@link CharacterSet}
     *
     * @param minLength     the inclusive minimum length of the generated string
     * @param maxLength     the inclusive maximum length of the generated string
     * @param characterSets the list {@code CharacterSet} to use to generate the string
     *
     * @return randomly generated string
     */
    String randomString(int minLength, int maxLength, CharacterSet... characterSets);

    enum CharacterSet
    {
        ASCII_LOWERCASE("abcdefghijklmnopqrstvwxyz"),
        ASCII_UPPERCASE("ABCDEFGHIJKLMNOPQRSTVWXYZ"),
        ASCII_LETTERS(ASCII_LOWERCASE, ASCII_UPPERCASE),
        DIGITS("0123456789"),
        PUNCTUATION("!\"#$%&'()*+,-./:;=<>?@[\\]^_`{|}~."),
        WHITESPACE(" \t\n\u000b\r\f"),
        PRINTABLE(DIGITS, ASCII_LETTERS, PUNCTUATION, WHITESPACE);

        public final String characters;

        CharacterSet(String characters)
        {
            this.characters = characters;
        }

        CharacterSet(CharacterSet... charsList)
        {
            characters = Arrays.stream(charsList).map(charSet -> charSet.characters).collect(Collectors.joining());
        }
    }
}
