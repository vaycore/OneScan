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
 * This interface gives you access to cryptographic features.
 */
public interface CryptoUtils
{
    /**
     * Generate a message digest for the supplied data using the specified algorithm
     *
     * @param data      the data to generate the digest from
     * @param algorithm the message {@link DigestAlgorithm} to use
     *
     * @return the generated message digest
     */
    ByteArray generateDigest(ByteArray data, DigestAlgorithm algorithm);
}
