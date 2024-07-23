/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

import burp.api.montoya.core.ByteArray;

import java.util.Base64;

/**
 * This interface contains various methods that give you access to base64 encoding and decoding features.
 */
public interface Base64Utils
{
    /**
     * Encodes all bytes from the specified byte array into a newly-allocated
     * byte array using the {@link Base64} encoding scheme. The returned byte
     * array is of the length of the resulting bytes.
     *
     * @param data    the byte array to encode
     * @param options the options to use for encoding
     *
     * @return A newly-allocated byte array containing the resulting
     * encoded bytes.
     */
    ByteArray encode(ByteArray data, Base64EncodingOptions... options);

    /**
     * Encodes all bytes from the specified String into a newly-allocated
     * byte array using the {@link Base64} encoding scheme. The returned byte
     * array is of the length of the resulting bytes.
     *
     * @param data    the string to encode.
     * @param options the options to use for encoding
     *
     * @return A newly-allocated byte array containing the resulting
     * encoded bytes.
     */
    ByteArray encode(String data, Base64EncodingOptions... options);

    /**
     * Encodes all bytes from the specified byte array into a String using the {@link Base64} encoding scheme.
     *
     * @param data    the byte array to encode
     * @param options the options to use for encoding
     *
     * @return A newly-allocated byte array containing the resulting
     * encoded bytes.
     */
    String encodeToString(ByteArray data, Base64EncodingOptions... options);

    /**
     * Encodes all bytes from the specified String into a String using the {@link Base64} encoding scheme.
     *
     * @param data    the string to encode.
     * @param options the options to use for encoding
     *
     * @return A newly-allocated byte array containing the resulting
     * encoded bytes.
     */
    String encodeToString(String data, Base64EncodingOptions... options);

    /**
     * Decodes all bytes from the specified byte array into a newly-allocated
     * byte array using the {@link Base64} decoding scheme. The returned byte
     * array is of the length of the resulting bytes.
     *
     * @param data    the bytes to decode.
     * @param options the options to use for decoding
     *
     * @return A newly-allocated byte array containing the resulting
     * decoded bytes.
     */
    ByteArray decode(ByteArray data, Base64DecodingOptions... options);

    /**
     * Decodes all bytes from the specified String into a newly-allocated
     * byte array using the {@link Base64} decoding scheme. The returned byte
     * array is of the length of the resulting bytes.
     *
     * @param data    the string to decode.
     * @param options the options to use for decoding
     *
     * @return A newly-allocated byte array containing the resulting
     * decoded bytes.
     */
    ByteArray decode(String data, Base64DecodingOptions... options);
}
