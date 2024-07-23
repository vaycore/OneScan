/*
 * Copyright (c) 2022-2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package burp.api.montoya.collaborator;

import static burp.api.montoya.internal.ObjectFactoryLocator.FACTORY;

/**
 * Provides a filtering mechanism for use when retrieving
 * interactions from the Burp Collaborator server.
 * Helper methods are provided to create filters based on the interaction id
 * and the payload.
 */
public interface InteractionFilter
{
    /**
     * This method is invoked for each interaction retrieved from the
     * Collaborator server and determines whether the interaction should be
     * included in the list of interactions returned.
     *
     * @param server      The collaborator server that received the interaction.
     * @param interaction The interaction details.
     *
     * @return {@code true} if the interaction should be included,
     * {@code false} if not.
     */
    boolean matches(CollaboratorServer server, Interaction interaction);

    /**
     * Construct a InteractionFilter that matches any
     * interaction with the specified interaction id.
     *
     * @param id The interaction id.
     *
     * @return {@code true} if the interaction has the specified id,
     * {@code false} if not.
     */
    static InteractionFilter interactionIdFilter(String id)
    {
        return FACTORY.interactionIdFilter(id);
    }

    /**
     * Construct an InteractionFilter that matches any
     * interaction with the specified payload.
     *
     * @param payload The payload.
     *
     * @return {@code true} if the interaction has the specified payload,
     * {@code false} if not.
     */
    static InteractionFilter interactionPayloadFilter(String payload)
    {
        return FACTORY.interactionPayloadFilter(payload);
    }
}
