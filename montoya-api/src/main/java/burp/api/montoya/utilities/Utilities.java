/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.utilities;

/**
 * This interface gives you access to other interfaces that have various data conversion and querying features.
 */
public interface Utilities
{
    /**
     * @return an instance of {@link Base64Utils}
     */
    Base64Utils base64Utils();

    /**
     * @return an instance of {@link ByteUtils}
     */
    ByteUtils byteUtils();

    /**
     * @return an instance of {@link CompressionUtils}
     */
    CompressionUtils compressionUtils();

    /**
     * @return an instance of {@link CryptoUtils}
     */
    CryptoUtils cryptoUtils();

    /**
     * @return an instance of {@link HtmlUtils}
     */
    HtmlUtils htmlUtils();

    /**
     * @return an instance of {@link NumberUtils}
     */
    NumberUtils numberUtils();

    /**
     * @return an instance of {@link RandomUtils}
     */
    RandomUtils randomUtils();

    /**
     * @return an instance of {@link StringUtils}
     */
    StringUtils stringUtils();

    /**
     * @return an instance of {@link URLUtils}
     */
    URLUtils urlUtils();
}
