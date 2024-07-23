/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

import java.util.List;

/**
 * Burp Collaborator client
 * that can be used to generate Burp Collaborator payloads and poll the
 * Collaborator server for any network interactions that result from using
 * those payloads. Extensions can obtain new instances of this class by
 * calling {@link Collaborator#createClient()}.
 * <p>
 * Note that each Burp Collaborator client is tied to the Collaborator
 * server configuration that was in place at the time the client was created.
 * </p>
 */
public interface CollaboratorClient extends CollaboratorPayloadGenerator
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
    @Override
    CollaboratorPayload generatePayload(PayloadOption... options);

    /**
     * Generate new Burp Collaborator payloads with custom data.
     * The custom data can be retrieved from any {@link Interaction} triggered.
     * Options can be specified to alter the way the payloads are generated. If no
     * options are specified, generated payloads will include the server location.
     *
     * @param customData The custom data to add to the payload. Maximum size is 16 characters. Must be alphanumeric.
     * @param options    The optional payload options to apply
     *
     * @return The generated payload.
     *
     * @throws IllegalStateException if Burp Collaborator is disabled
     */
    CollaboratorPayload generatePayload(String customData, PayloadOption... options);

    /**
     * Retrieve all Collaborator server interactions
     * resulting from payloads that were generated for this client.
     *
     * @return The Collaborator interactions that have occurred resulting from
     * payloads that were generated for this client.
     *
     * @throws IllegalStateException if Burp Collaborator is disabled
     */
    List<Interaction> getAllInteractions();

    /**
     * Retrieve filtered Collaborator server
     * interactions resulting from payloads that were generated for this
     * client. Only interactions matching the supplied filter will be returned.
     *
     * @param filter The filter that will be applied to each interaction.
     *
     * @return The filtered Collaborator interactions resulting from payloads
     * that were generated for this client.
     *
     * @throws IllegalStateException if Burp Collaborator is disabled
     */
    List<Interaction> getInteractions(InteractionFilter filter);

    /**
     * Retrieve the details of the Collaborator server
     * associated with this client.
     *
     * @return The Collaborator server details.
     *
     * @throws IllegalStateException if Burp Collaborator is disabled
     */
    CollaboratorServer server();

    /**
     * Secret key that is associated with this client context.
     * The key can be used to re-create this client again with the interaction data if required.
     *
     * @return The {@link SecretKey} that is associated with this Collaborator client.
     */
    SecretKey getSecretKey();
}
