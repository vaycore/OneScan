/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.intruder;

/**
 * Intruder payload generator. Extensions that have registered
 * a {@link PayloadGeneratorProvider} must return a new instance of this interface when required as part
 * of a new Intruder attack.
 */
public interface PayloadGenerator
{
    /**
     * Invoked by Burp to obtain the value of the next payload.
     * Should return {@link GeneratedPayload#end()} instance to signal to Burp that the generator has finished.
     *
     * @param insertionPoint Insertion point for the payload.
     *
     * @return A generated Intruder payload.
     */
    GeneratedPayload generatePayloadFor(IntruderInsertionPoint insertionPoint);
}