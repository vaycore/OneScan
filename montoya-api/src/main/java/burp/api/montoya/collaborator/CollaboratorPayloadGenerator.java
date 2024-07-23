/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

/**
 * Burp Collaborator payload generator
 * that can be used to generate Burp Collaborator payloads.
 */
public interface CollaboratorPayloadGenerator
{
    /**
     * Generate new Burp Collaborator payloads. Options
     * can be specified to alter the way the payloads are generated. If no
     * options are specified, generated payloads will include the server
     * location.
     *
     * @param options The optional payload options to apply
     *
     * @return The generated payload.
     *
     * @throws IllegalStateException if Burp Collaborator is disabled
     */
    CollaboratorPayload generatePayload(PayloadOption... options);
}
