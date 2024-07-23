/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.decoder;

import burp.api.montoya.core.ByteArray;

/**
 * Provides access to the functionality of the Decoder tool.
 */
public interface Decoder
{
    /**
     * Send data to the Decoder tool.
     *
     * @param data The data to be sent to Decoder.
     */
    void sendToDecoder(ByteArray data);
}
