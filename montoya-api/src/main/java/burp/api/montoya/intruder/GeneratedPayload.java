/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

import burp.api.montoya.core.ByteArray;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Intruder payload.
 */
public interface GeneratedPayload
{
    /**
     * @return Payload value.
     */
    ByteArray value();

    /**
     * Create a new {@link GeneratedPayload} instance from a String payload value.
     *
     * @param payload String payload value.
     *
     * @return A new {@link GeneratedPayload} instance.
     */
    static GeneratedPayload payload(String payload)
    {
        return FACTORY.payload(payload);
    }

    /**
     * Create a new {@link GeneratedPayload} instance from a byte array payload value.
     *
     * @param payload Byte array payload value.
     *
     * @return A new {@link GeneratedPayload} instance.
     */
    static GeneratedPayload payload(ByteArray payload)
    {
        return FACTORY.payload(payload);
    }

    /**
     * Create a new {@link GeneratedPayload} instance to signify there are no more payloads.
     *
     * @return A new {@link GeneratedPayload} instance.
     */
    static GeneratedPayload end()
    {
        return FACTORY.payloadEnd();
    }
}
