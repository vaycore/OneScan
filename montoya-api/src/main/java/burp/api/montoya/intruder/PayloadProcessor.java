/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

/**
 * Extensions can implement this interface and then call {@link Intruder#registerPayloadProcessor} to register a
 * custom Intruder payload processor.
 */
public interface PayloadProcessor
{
    /**
     * Name Burp will use when displaying the payload processor
     * in a dropdown list in the UI.
     *
     * @return Name of the payload processor
     */
    String displayName();

    /**
     * Invoked by Burp each time the processor should be applied to an Intruder payload.
     *
     * @param payloadData Information about the current payload to be processed
     *
     * @return The value of the processed payload.
     */
    PayloadProcessingResult processPayload(PayloadData payloadData);
}
