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
 * This interface gives you access to data compression features.
 */
public interface CompressionUtils
{
    /**
     * Compress data using the specified compression type.
     *
     * @param data data to be compressed
     * @param type {@link CompressionType} to use. Only GZIP is supported
     *
     * @return compressed data
     */
    ByteArray compress(ByteArray data, CompressionType type);

    /**
     * Decompress data compressed using the specified compression type.
     *
     * @param compressedData data to be decompressed
     * @param type           {@link CompressionType} of the compressed data
     *
     * @return decompressed data
     */
    ByteArray decompress(ByteArray compressedData, CompressionType type);
}
